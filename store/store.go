// Package store persists the document METADATA layer (the `document` schema). The
// platform backend is PostgreSQL reached ONLY through the schema's SECURITY
// DEFINER procedures under the EXECUTE-only `document_public` role
// (authbyte-db/document); an in-memory backend exists for tests. No backend
// exposes raw table access — every operation is a procedure call. Document BYTES
// live in S3 (envelope-encrypted), never here.
package store

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Sentinel errors the procedure error codes map onto, so routes can pick the
// right HTTP status (document:<reason> — :not_found → 404, :legal_hold → 409).
var (
	// ErrNotFound is returned when a document is absent OR not owned by the
	// caller (the two are deliberately indistinguishable — no-IDOR).
	ErrNotFound = errors.New("document: not found")
	// ErrLegalHold is returned when a delete is refused due to a legal hold.
	ErrLegalHold = errors.New("document: under legal hold")
	// ErrChainAdvanced is returned when a keep-latest container replace is
	// rejected because the chain head moved since the signer began (optimistic
	// CAS) — the caller should reload the latest and retry.
	ErrChainAdvanced = errors.New("document: chain advanced since signing began")
	// ErrChainLive is returned when a history-record removal is refused because
	// the chain still has a live row (delete it through the normal path) or is
	// under legal hold.
	ErrChainLive = errors.New("document: chain is live or under legal hold")
	// ErrNotBundleable is returned when a document offered to a bundle (or the
	// bundle itself on a rebundle) is not in a bundleable state — only unsigned
	// "received" sources may be absorbed, and only an unsigned "received"
	// container may be rebundled.
	ErrNotBundleable = errors.New("document: not bundleable")
)

// ManifestFile is one data object inside a stored ASiC-E container — its
// in-container name, media type, and size. Captured once (from go-asice Inspect)
// when the container row is written, so the portal can list "what is inside"
// without unzipping the encrypted blob on every read. Metadata only — never the
// authoritative bytes.
type ManifestFile struct {
	Name      string `json:"name"`
	MediaType string `json:"mediaType,omitempty"`
	Size      int64  `json:"size,omitempty"`
}

// Document is one metadata row. Bytes are NOT here: they live in S3 under
// StorageRef, encrypted with the KMS-wrapped data key in EncryptionKeyRef.
type Document struct {
	ID                string    `json:"id"`
	Owner             string    `json:"owner"`
	TenantID          string    `json:"tenant_id,omitempty"`
	Kind              string    `json:"kind"` // source | container
	ParentID          string    `json:"parent_id,omitempty"`
	Filename          string    `json:"filename,omitempty"`
	StorageRef        string    `json:"storage_ref,omitempty"` // S3 object key (empty once purged)
	ContentHash       string    `json:"content_hash"`          // canonical SHA-256 (B1), base64
	Mime              string    `json:"mime"`
	Size              int64     `json:"size"`
	Status            string    `json:"status"`                       // received|signing|signed|expired|deleted
	EncryptionKeyRef  string    `json:"encryption_key_ref,omitempty"` // KMS-wrapped data key (empty once destroyed)
	PreservationClass string    `json:"preservation_class"`           // none|b_lt|preservation
	RetentionUntil    time.Time `json:"retention_until"`
	LegalHold         bool      `json:"legal_hold"`
	// SignedAt is the instant the PLATFORM applied a signature to this row in
	// place (the keep-latest replace); nil for uploads, including files that
	// arrived already signed. Together with a set ParentID it answers "was this
	// chain signed here" for the dashboard classification.
	SignedAt *time.Time `json:"signed_at,omitempty"`
	// ResultFrozen is the CHAIN's download freeze (a root-row flag the reads
	// project onto every row): while a signing workflow over the chain is in
	// progress, byte reads of its non-source rows refuse — the signed result
	// opens at the workflow's terminal transition. Sources serve throughout.
	ResultFrozen bool `json:"result_frozen,omitempty"`
	// InnerFiles is the ASiC-E inner-file manifest for a container row (the data
	// objects it holds); nil for a plain source. Cheap "what's inside" metadata.
	InnerFiles []ManifestFile `json:"inner_files,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// Chain is a document chain projected to its single LIVE HEAD — the signed
// artifact where one exists (at most one lives per chain), else the uploaded
// source. The "always latest" listing row: a consumer never sees a chain's
// source next to its signed result as two rows. HasSignatures reports that the
// head carries signatures (any non-source kind — including a file that arrived
// already signed); PlatformSigned reports the head was produced by a signing
// here (it derives from a parent) rather than being the upload itself;
// ChainCreatedAt is when the chain started (the root's created_at, falling
// back to the head's when the root row is gone).
type Chain struct {
	ChainRootID       string    `json:"chain_root_id"`
	ID                string    `json:"id"`
	Kind              string    `json:"kind"`
	Status            string    `json:"status"`
	Filename          string    `json:"filename,omitempty"`
	Mime              string    `json:"mime"`
	Size              int64     `json:"size"`
	RetentionUntil    time.Time `json:"retention_until"`
	LegalHold         bool      `json:"legal_hold"`
	PreservationClass string    `json:"preservation_class"` // none|b_lt|preservation — 'preservation' once archive-timestamped (B-LTA)
	HasSignatures     bool      `json:"has_signatures"`
	PlatformSigned    bool      `json:"platform_signed"`
	// ResultFrozen mirrors the chain's download freeze so a listing consumer
	// renders the row as in-signing rather than draft/completed while a
	// workflow is in progress.
	ResultFrozen bool `json:"result_frozen,omitempty"`
	// InnerFiles is the head container's manifest — what is inside it. Carried
	// by the single-chain read only, so a screen that shows a container's
	// contents needs one read; a listing leaves it empty.
	InnerFiles     []ManifestFile `json:"inner_files,omitempty"`
	ChainCreatedAt time.Time      `json:"chain_created_at"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// HistoryChain is a TERMINAL chain in the caller's history — every row expired
// or deleted, the storage destroyed, only this metadata record remaining (for a
// bounded keep window). Presented as the chain's terminal head; DestroyedAt is
// when that head reached its terminal state.
type HistoryChain struct {
	ChainRootID    string    `json:"chain_root_id"`
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Status         string    `json:"status"`
	Filename       string    `json:"filename,omitempty"`
	Mime           string    `json:"mime"`
	Size           int64     `json:"size"`
	HasSignatures  bool      `json:"has_signatures"`
	PlatformSigned bool      `json:"platform_signed"`
	ChainCreatedAt time.Time `json:"chain_created_at"`
	DestroyedAt    time.Time `json:"destroyed_at"`
}

// InsertInput is the metadata for one new row. Kind defaults to "source", Status
// to "received", PreservationClass to "none" when empty.
type InsertInput struct {
	Owner             string
	TenantID          string
	Kind              string
	ParentID          string
	Filename          string
	StorageRef        string
	ContentHash       string
	Mime              string
	Size              int64
	Status            string
	EncryptionKeyRef  string
	PreservationClass string
	RetentionUntil    time.Time
	// InnerFiles is the ASiC-E inner-file manifest to persist for a container
	// (captured from go-asice Inspect at write time); nil for a plain source.
	InnerFiles []ManifestFile
}

// PurgedRef is one document's bytes-location refs returned by MarkDeleted /
// SweepRetention so the Go layer can destroy the S3 object + KMS data key.
type PurgedRef struct {
	ID               string `json:"id"`
	StorageRef       string `json:"storageRef"`
	EncryptionKeyRef string `json:"encryptionKeyRef"`
}

// Caller is the authenticated principal on a request: the token subject and, for
// a named person, their eIDAS serial. A read/co-sign is authorized when EITHER
// the subject owns the document chain OR the serial matches an invited
// participant's ACL entry. The serial is empty for service callers and for the
// owner-by-subject path (the subject alone authorizes).
type Caller struct {
	Sub    string
	Serial string
}

// NormalizeSerial is the canonical form of an eIDAS identity code for ACL
// matching — it mirrors the database `document.normalize_serial`: trim + upper.
// Fuller cross-border normalization is a planned extension behind this seam.
func NormalizeSerial(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// GrantInput records standing ACL access to a document's chain. The chain root
// is resolved from DocID; PrincipalKind is "sub" or "serial"; Rights default to
// {read, cosign} when empty. A serial principal is stored normalized.
type GrantInput struct {
	DocID         string
	PrincipalKind string
	PrincipalID   string
	Rights        []string
	TenantID      string
	GrantedBy     string
}

// ReplaceInput hard-replaces a container's bytes in place (keep-latest). The
// swap commits only if the row's current content hash still equals ExpectedHash
// (optimistic CAS); ContentHash/Size/StorageRef/EncryptionKeyRef describe the
// new blob the caller already stored.
type ReplaceInput struct {
	ID               string
	ExpectedHash     string
	StorageRef       string
	ContentHash      string
	Size             int64
	EncryptionKeyRef string
	// PreservationClass, when set, is recorded in the same write as the swap: an
	// archive-timestamped refresh upgrades the row to "preservation" as one fact
	// with its bytes, never as a second step that can fail on its own. Empty
	// leaves the row's class unchanged.
	PreservationClass string
}

// Bundleable reports whether a document may be absorbed into a bundle: an unsigned
// source, or an already-signed file — a signed PDF or a signed ASiC-E container (an
// annex such as a counterparty's signed letter). A signed input rides in as a data
// object: the new container's signature covers its bytes, and its own signatures
// stay intact inside it. An UNSIGNED container is never an input — that is a draft
// bundle, which is rebundled instead.
func Bundleable(kind, status string) bool {
	return (kind == "source" && status == "received") ||
		((kind == "pdf" || kind == "container") && status == "signed")
}

// BundleInput creates a multi-document bundle: ONE unsigned container row (a
// fresh chain root, status "received") built from the owner's loose source
// documents, which are absorbed — hard-deleted with their ACL entries — in the
// same transaction. The caller has already stored the new blob; SourceIDs is
// the sender-set order and must hold at least one owned source.
type BundleInput struct {
	Owner             string
	TenantID          string
	SourceIDs         []string
	Filename          string
	StorageRef        string
	ContentHash       string
	Mime              string
	Size              int64
	EncryptionKeyRef  string
	PreservationClass string
	RetentionUntil    time.Time
	InnerFiles        []ManifestFile
}

// RebundleInput replaces an UNSIGNED bundle's bytes in place (a draft edit:
// add / remove / reorder inner files) under the same optimistic CAS as
// ReplaceInput, refreshing the inner-file manifest. AbsorbSourceIDs are newly
// staged loose sources to absorb exactly as in BundleInput (may be empty).
type RebundleInput struct {
	Owner            string
	ID               string
	ExpectedHash     string
	StorageRef       string
	ContentHash      string
	Size             int64
	EncryptionKeyRef string
	InnerFiles       []ManifestFile
	AbsorbSourceIDs  []string
}

// Store is the document-metadata persistence contract. It maps 1:1 onto the
// `document` schema procedures.
type Store interface {
	// Insert persists a metadata row and returns its assigned ULID id.
	Insert(ctx context.Context, in InsertInput) (id string, err error)
	// ReplaceContainerBlob hard-replaces a container's bytes in place (keep-latest)
	// under an optimistic CAS on its current content hash, returning the updated
	// row + the PRIOR blob refs to destroy. ErrChainAdvanced when the hash moved.
	// A PreservationClass in the input is recorded in the same write.
	ReplaceContainerBlob(ctx context.Context, in ReplaceInput) (*Document, *PurgedRef, error)
	// Bundle inserts ONE unsigned container row (a fresh chain root) built from
	// the owner's loose sources and absorbs those source rows + their ACL
	// entries in the same transaction. Returns the new row id + the absorbed
	// blob refs to destroy after commit. ErrNotFound when a source is absent or
	// foreign-owned; ErrLegalHold when a source is under hold.
	Bundle(ctx context.Context, in BundleInput) (id string, absorbed []PurgedRef, err error)
	// Rebundle replaces an unsigned bundle's bytes in place (a draft edit)
	// under an optimistic CAS on its current content hash, refreshing the
	// inner-file manifest and absorbing newly staged sources. Returns the
	// updated row, the prior blob ref, and the absorbed refs. ErrChainAdvanced
	// when the hash moved; ErrNotFound / ErrLegalHold as in Bundle.
	Rebundle(ctx context.Context, in RebundleInput) (*Document, *PurgedRef, []PurgedRef, error)
	// Grant records standing ACL access to a document's chain (idempotent — a
	// re-grant replaces the principal's rights). Returns ErrNotFound when DocID
	// does not exist.
	Grant(ctx context.Context, in GrantInput) error
	// Get returns one document the caller may read, authorized by the chain's
	// ACL (DB-enforced no-IDOR). It returns ErrNotFound when the row is absent or
	// the caller is not on the ACL (deliberately indistinguishable).
	Get(ctx context.Context, id string, caller Caller) (*Document, error)
	// GetContainerByParent returns the single container of a chain root (its
	// parent), authorized by the same chain ACL as Get. Used to re-resolve the
	// existing container when a concurrent first co-sign lost the create race.
	// ErrNotFound when no container exists yet or the caller is not on the ACL.
	GetContainerByParent(ctx context.Context, parentID string, caller Caller) (*Document, error)
	// GetLatestSignedPdfByChain returns the current live signed PDF of a chain —
	// a signed child of the root, or the root itself when the uploaded document
	// arrived already signed — authorized by the same chain ACL as Get. The PDF
	// analog of GetContainerByParent: a co-signer re-resolves the current signed
	// PDF to sign on top of it (an embedded PDF signature can't be merged).
	// ErrNotFound when none exists yet or the caller is not on the ACL.
	GetLatestSignedPdfByChain(ctx context.Context, parentID string, caller Caller) (*Document, error)
	// List returns the documents the caller may read (excluding deleted),
	// keyset-paginated by descending id; after is an exclusive upper-bound id
	// ("" = first page).
	List(ctx context.Context, caller Caller, limit int, after string) ([]*Document, error)
	// ListChains returns the caller's readable documents projected one row per
	// chain — each chain as its live head (the signed artifact over the
	// source) — keyset-paginated by descending chain root id; after is an
	// exclusive upper-bound chain root id ("" = first page). A chain whose
	// head has expired is omitted unless includeExpired.
	ListChains(ctx context.Context, caller Caller, limit int, after string, includeExpired bool) ([]*Chain, error)
	// GetChain returns ONE chain as its live head, addressed by any id in it
	// (the chain root or the signed head derived from it). It answers
	// independently of any listing: a listing may legitimately omit a chain
	// (filtered, paged, or represented elsewhere), and a chain's own facts must
	// not depend on that. An expired chain is still returned; a chain with no
	// live row left, and one the caller may not read, are both ErrNotFound.
	GetChain(ctx context.Context, caller Caller, id string) (*Chain, error)
	// SetStatus atomically changes an owned document's status.
	SetStatus(ctx context.Context, id, caller, status string) error
	// SetResultFreeze sets/clears the chain-level download freeze (resolved to
	// the chain root from any of its rows). The caller's authority is the
	// service boundary's job (the grant scope) — the store just records it.
	SetResultFreeze(ctx context.Context, id string, frozen bool) error
	// ChainRetention reports when the bytes of a chain stop being downloadable —
	// the latest retention instant across the chain's rows that still hold
	// storage, resolved to the chain root from any of its rows. Not owner-scoped
	// and byte-free: it answers only "how long is there still something to read",
	// for the service that administers the chain's sharing. A chain with nothing
	// stored reports a zero instant and no live rows.
	ChainRetention(ctx context.Context, id string) (until time.Time, liveRows int, err error)
	// ExtendRetention rolls an owned document's retention_until forward (never
	// shortens) to until.
	ExtendRetention(ctx context.Context, id, caller string, until time.Time) error
	// RemoveAccess removes the caller's standing access to a document's chain
	// (reference-counted): the caller's ACL entry is dropped, and only when the
	// LAST entry is gone are the chain's bytes purged — the returned refs are the
	// blobs to destroy (empty when others still hold access). A legal hold on any
	// row in the chain refuses (ErrLegalHold). ErrNotFound when the caller has no
	// access.
	RemoveAccess(ctx context.Context, docID string, caller Caller) ([]PurgedRef, error)
	// SweepRetention flips expired non-hold documents to "expired", NULLs their
	// refs, and returns the prior refs to purge. now is the cutoff instant.
	SweepRetention(ctx context.Context, now time.Time, limit int) ([]PurgedRef, error)
	// ListHistory returns the caller's TERMINAL chains (no live row left), one
	// row per chain as its terminal head, owner-scoped by the uploader subject;
	// keyset-paginated by descending chain root id.
	ListHistory(ctx context.Context, owner string, limit int, after string) ([]*HistoryChain, error)
	// SweepHistory hard-deletes terminal metadata rows older than before (the
	// history keep window), plus orphaned chain ACL entries. Returns the number
	// of rows removed.
	SweepHistory(ctx context.Context, before time.Time, limit int) (int, error)
	// DeleteHistoryChain removes one of the caller's history records early
	// (hard-delete of the owned terminal chain rows + orphaned ACL entries).
	// ErrChainLive when the chain still has a live row or is under legal hold;
	// ErrNotFound when the caller owns no such record.
	DeleteHistoryChain(ctx context.Context, owner, chainRootID string) error
	// Ping verifies backend connectivity for readiness checks.
	Ping(ctx context.Context) error
	// Close releases backend resources.
	Close()
}
