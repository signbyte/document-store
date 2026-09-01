// Package documents is the Document Service's domain core: it composes the
// metadata store, the encrypted S3 blob store, and the KMS to own the document
// bytes + the canonical hash (B1/B2/S4). It performs NO audit emission and reads
// NO request context — the routes layer owns authZ + the three audit regimes and
// passes a plain context here. The 24h TTL clock lives here (distinct from the
// SignAPI session TTL).
package documents

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/signbyte/document-store/kms"
	"github.com/signbyte/document-store/packaging"
	"github.com/signbyte/document-store/s3"
	"github.com/signbyte/document-store/store"
)

// ErrGone is returned when a document's bytes are no longer available (purged on
// TTL/manual-delete) even though the metadata row may still exist.
var ErrGone = errors.New("documents: bytes no longer available")

// Service owns document bytes + the canonical hash.
type Service struct {
	store store.Store
	blob  s3.Store
	kms   kms.KMS
	ttl   time.Duration
}

// New builds the service. ttl is the 24h retention window applied at ingest.
func New(st store.Store, blob s3.Store, k kms.KMS, ttl time.Duration) *Service {
	return &Service{store: st, blob: blob, kms: k, ttl: ttl}
}

// CanonicalHash is the B1 digest: base64(SHA-256(bytes)). It is computed ONCE at
// ingest and stored on the row; the Orchestrator fetches it, never recomputes.
func CanonicalHash(data []byte) string {
	sum := sha256.Sum256(data)

	return base64.StdEncoding.EncodeToString(sum[:])
}

// IngestInput is one new blob to store (a `source` upload or an assembled
// `container`). Mime defaults to application/octet-stream; Kind to "source".
type IngestInput struct {
	Owner string
	// Serial is the caller's eIDAS identity code, used only to read the row back after
	// insert. A co-signer creating the first container is on the chain ACL by serial (not
	// by sub), so the read-back must present it — otherwise the co-signer's own first sign
	// fails the ACL check. Empty for a plain upload (the creator's sub ACL covers it).
	Serial            string
	TenantID          string
	Kind              string // "" → source
	ParentID          string
	Filename          string
	Mime              string
	PreservationClass string
	Status            string // "" → received (source) ; callers set "signed" for containers
	Data              []byte
}

// Ingest computes the canonical hash, envelope-encrypts the bytes (fresh per-object
// data key, KMS-wrapped), stores the ciphertext in S3, and persists the metadata
// row with retention_until = now + ttl. On a metadata failure the orphan blob is
// cleaned up.
//
// Detection of an uploaded ALREADY-SIGNED file (kind override) is the caller's
// concern: the user-facing upload route runs the document gate on the raw
// upload and sets Kind/Status accordingly; internal callers set their Kind
// explicitly. Container detection stays here (every stored container needs its
// inner-file manifest captured, whatever the caller).
func (s *Service) Ingest(ctx context.Context, in IngestInput) (*store.Document, error) {
	mime := in.Mime
	if mime == "" {
		mime = "application/octet-stream"
	}

	// Detect an ASiC-E container and capture its inner-file manifest in one pass.
	// A raw upload that is already a container is recorded as a signed container, so
	// signing it co-signs a parallel signature INTO it rather than wrapping it as a
	// nested data object; the manifest lets the portal list its contents without
	// unzipping. Assembled/co-signed containers set Kind explicitly — their inner
	// files are still captured here. A plain source yields nothing.
	var innerFiles []store.ManifestFile
	if files, isContainer := packaging.Inspect(in.Data); isContainer {
		if in.Kind == "" {
			in.Kind = "container"
			if in.Status == "" {
				in.Status = "signed"
			}
		}
		innerFiles = make([]store.ManifestFile, len(files))
		for i, f := range files {
			innerFiles[i] = store.ManifestFile{Name: f.Name, MediaType: f.MediaType, Size: f.Size}
		}
	}

	hash := CanonicalHash(in.Data)

	plainKey, wrapped, err := s.kms.GenerateDataKey()
	if err != nil {
		return nil, err
	}
	sealed, err := kms.Seal(plainKey, in.Data)
	if err != nil {
		return nil, err
	}

	objKey := ulid.Make().String()
	if err := s.blob.Put(ctx, objKey, sealed); err != nil {
		return nil, err
	}

	id, err := s.store.Insert(ctx, store.InsertInput{
		Owner:             in.Owner,
		TenantID:          in.TenantID,
		Kind:              in.Kind,
		ParentID:          in.ParentID,
		Filename:          in.Filename,
		StorageRef:        objKey,
		ContentHash:       hash,
		Mime:              mime,
		Size:              int64(len(in.Data)),
		Status:            in.Status,
		EncryptionKeyRef:  base64.StdEncoding.EncodeToString(wrapped),
		PreservationClass: in.PreservationClass,
		RetentionUntil:    time.Now().Add(s.ttl),
		InnerFiles:        innerFiles,
	})
	if err != nil {
		// Roll back the orphan blob so a failed insert leaves nothing behind.
		_ = s.blob.Delete(ctx, objKey)

		return nil, err
	}

	// Read the row back under the caller's full identity (sub + serial). A new source
	// carries its creator's seeded sub ACL; a first container inherits the chain root's
	// ACL, where a co-signer signing first is granted by serial, not by sub — so without
	// the serial the co-signer could not read back the container they just created.
	return s.store.Get(ctx, id, store.Caller{Sub: in.Owner, Serial: in.Serial})
}

// BundleEntry names one member of a rebundled set, in final order: either an
// inner file already inside the bundle (Name) or a newly staged loose source to
// absorb (SourceID). Exactly one is set.
type BundleEntry struct {
	Name     string
	SourceID string
}

// uniqueObjectName makes a container-root data-object name unique within the
// set, suffixing " (2)", " (3)", … before the extension on a collision (two
// uploads may legitimately share a filename, but a container's entries cannot).
func uniqueObjectName(seen map[string]bool, name string, index int) string {
	if name == "" {
		name = fmt.Sprintf("document-%d", index+1)
	}
	candidate := name
	for n := 2; seen[candidate]; n++ {
		if i := strings.LastIndexByte(name, '.'); i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", name[:i], n, name[i:])
		} else {
			candidate = fmt.Sprintf("%s (%d)", name, n)
		}
	}
	seen[candidate] = true

	return candidate
}

// bundleFilename derives the bundle's default filename from its first inner
// file: the basename with the extension swapped for .asice.
func bundleFilename(first string) string {
	if first == "" {
		return "container.asice"
	}
	if i := strings.LastIndexByte(first, '.'); i > 0 {
		return first[:i] + ".asice"
	}

	return first + ".asice"
}

// manifestFiles captures a container's inner-file manifest for the metadata row.
func manifestFiles(container []byte) []store.ManifestFile {
	inner, _ := packaging.Inspect(container)
	files := make([]store.ManifestFile, len(inner))
	for i, f := range inner {
		files[i] = store.ManifestFile{Name: f.Name, MediaType: f.MediaType, Size: f.Size}
	}

	return files
}

// sealAndStore envelope-encrypts bytes with a fresh data key and stores the
// ciphertext, returning the object key and the wrapped key (base64).
func (s *Service) sealAndStore(ctx context.Context, data []byte) (objKey, keyRef string, err error) {
	plainKey, wrapped, err := s.kms.GenerateDataKey()
	if err != nil {
		return "", "", err
	}
	sealed, err := kms.Seal(plainKey, data)
	if err != nil {
		return "", "", err
	}
	objKey = ulid.Make().String()
	if err := s.blob.Put(ctx, objKey, sealed); err != nil {
		return "", "", err
	}

	return objKey, base64.StdEncoding.EncodeToString(wrapped), nil
}

// Bundle packages the owner's loose source documents into ONE unsigned ASiC-E
// bundle — the at-rest form of a signing set (one file or many) and its chain root. The bundle
// holds the files in the given (sender-set) order; the loose source rows are
// absorbed (deleted, blobs destroyed) in the same transaction, so the set has
// exactly one row from here on. The first signature later merges into the
// bundle like any parallel co-signature. Filename defaults to the first file's
// basename + ".asice".
func (s *Service) Bundle(ctx context.Context, owner, tenantID string, sourceIDs []string, filename string) (*store.Document, error) {
	if len(sourceIDs) < 1 {
		return nil, store.ErrNotBundleable
	}
	caller := store.Caller{Sub: owner}

	seen := map[string]bool{}
	files := make([]packaging.File, 0, len(sourceIDs))
	for i, id := range sourceIDs {
		doc, data, err := s.Content(ctx, id, caller)
		if err != nil {
			return nil, err
		}
		if doc.Owner != owner || !store.Bundleable(doc.Kind, doc.Status) {
			return nil, store.ErrNotBundleable
		}
		files = append(files, packaging.File{Name: uniqueObjectName(seen, doc.Filename, i), Data: data})
	}
	if filename == "" {
		filename = bundleFilename(files[0].Name)
	}

	bundle, err := packaging.BuildUnsigned(files)
	if err != nil {
		return nil, err
	}

	objKey, keyRef, err := s.sealAndStore(ctx, bundle)
	if err != nil {
		return nil, err
	}

	id, absorbed, err := s.store.Bundle(ctx, store.BundleInput{
		Owner:            owner,
		TenantID:         tenantID,
		SourceIDs:        sourceIDs,
		Filename:         filename,
		StorageRef:       objKey,
		ContentHash:      CanonicalHash(bundle),
		Mime:             packaging.MimeType,
		Size:             int64(len(bundle)),
		EncryptionKeyRef: keyRef,
		RetentionUntil:   time.Now().Add(s.ttl),
		InnerFiles:       manifestFiles(bundle),
	})
	if err != nil {
		// Roll back the orphan blob so a failed bundle leaves nothing behind.
		_ = s.blob.Delete(ctx, objKey)

		return nil, err
	}

	// Ordering: the bundle row is committed; now destroy the absorbed loose
	// blobs. A failed delete leaves a harmless orphan, never data loss.
	for _, ref := range absorbed {
		if ref.StorageRef != "" {
			_ = s.blob.Delete(ctx, ref.StorageRef)
		}
	}

	return s.store.Get(ctx, id, caller)
}

// Rebundle rebuilds an UNSIGNED bundle from the given entries — a draft edit:
// add (SourceID), remove (omit), reorder (entry order). It replaces the
// bundle's bytes in place under the keep-latest CAS, refreshes the inner-file
// manifest, and absorbs newly staged sources. A signed container never comes
// here (store.ErrNotBundleable).
func (s *Service) Rebundle(ctx context.Context, owner, id string, entries []BundleEntry) (*store.Document, error) {
	if len(entries) < 1 {
		return nil, store.ErrNotBundleable
	}
	caller := store.Caller{Sub: owner}

	cur, curBytes, err := s.Content(ctx, id, caller)
	if err != nil {
		return nil, err
	}
	if cur.Owner != owner || cur.Kind != "container" || cur.Status != "received" {
		return nil, store.ErrNotBundleable
	}
	existing, err := packaging.DataObjects(curBytes)
	if err != nil {
		return nil, err
	}
	byName := make(map[string][]byte, len(existing))
	for _, o := range existing {
		byName[o.Name] = o.Data
	}

	seen := map[string]bool{}
	files := make([]packaging.File, 0, len(entries))
	var absorb []string
	for i, e := range entries {
		switch {
		case e.Name != "" && e.SourceID == "":
			data, ok := byName[e.Name]
			if !ok {
				return nil, store.ErrNotFound
			}
			files = append(files, packaging.File{Name: uniqueObjectName(seen, e.Name, i), Data: data})
		case e.SourceID != "" && e.Name == "":
			doc, data, err := s.Content(ctx, e.SourceID, caller)
			if err != nil {
				return nil, err
			}
			if doc.Owner != owner || !store.Bundleable(doc.Kind, doc.Status) {
				return nil, store.ErrNotBundleable
			}
			absorb = append(absorb, e.SourceID)
			files = append(files, packaging.File{Name: uniqueObjectName(seen, doc.Filename, i), Data: data})
		default:
			return nil, store.ErrNotBundleable
		}
	}

	bundle, err := packaging.BuildUnsigned(files)
	if err != nil {
		return nil, err
	}

	objKey, keyRef, err := s.sealAndStore(ctx, bundle)
	if err != nil {
		return nil, err
	}

	doc, old, absorbed, err := s.store.Rebundle(ctx, store.RebundleInput{
		Owner:            owner,
		ID:               id,
		ExpectedHash:     cur.ContentHash,
		StorageRef:       objKey,
		ContentHash:      CanonicalHash(bundle),
		Size:             int64(len(bundle)),
		EncryptionKeyRef: keyRef,
		InnerFiles:       manifestFiles(bundle),
		AbsorbSourceIDs:  absorb,
	})
	if err != nil {
		// Roll back the orphan new blob (a CAS rejection leaves nothing behind).
		_ = s.blob.Delete(ctx, objKey)

		return nil, err
	}

	if old != nil && old.StorageRef != "" {
		_ = s.blob.Delete(ctx, old.StorageRef)
	}
	for _, ref := range absorbed {
		if ref.StorageRef != "" {
			_ = s.blob.Delete(ctx, ref.StorageRef)
		}
	}

	return doc, nil
}

// ReplaceContainer hard-replaces a container's bytes in place (keep-latest): it
// encrypts + stores the new bytes, atomically swaps the row to point at them
// ONLY IF its content hash is unchanged (optimistic CAS — else
// store.ErrChainAdvanced), then destroys the prior blob. The chain keeps exactly
// one container. The new blob is rolled back if the swap fails. Returns the
// updated row.
func (s *Service) ReplaceContainer(ctx context.Context, containerID, expectedHash string, newBytes []byte) (*store.Document, error) {
	hash := CanonicalHash(newBytes)

	plainKey, wrapped, err := s.kms.GenerateDataKey()
	if err != nil {
		return nil, err
	}
	sealed, err := kms.Seal(plainKey, newBytes)
	if err != nil {
		return nil, err
	}

	objKey := ulid.Make().String()
	if err := s.blob.Put(ctx, objKey, sealed); err != nil {
		return nil, err
	}

	doc, old, err := s.store.ReplaceContainerBlob(ctx, store.ReplaceInput{
		ID:               containerID,
		ExpectedHash:     expectedHash,
		StorageRef:       objKey,
		ContentHash:      hash,
		Size:             int64(len(newBytes)),
		EncryptionKeyRef: base64.StdEncoding.EncodeToString(wrapped),
	})
	if err != nil {
		// Roll back the orphan new blob (a CAS rejection leaves nothing behind).
		_ = s.blob.Delete(ctx, objKey)

		return nil, err
	}

	// Ordering: the pointer is committed; now destroy the superseded blob. A
	// failed delete leaves a harmless orphan (a sweep mops it up), never data loss.
	if old != nil && old.StorageRef != "" {
		_ = s.blob.Delete(ctx, old.StorageRef)
	}

	return doc, nil
}

// GetContainerByParent returns a chain's single container (ACL-authorized), used
// to re-resolve the existing container when a concurrent first co-sign lost the
// create race. ErrNotFound when none exists yet or the caller is off the ACL.
func (s *Service) GetContainerByParent(ctx context.Context, parentID string, caller store.Caller) (*store.Document, error) {
	return s.store.GetContainerByParent(ctx, parentID, caller)
}

// GetLatestSignedPdfByChain returns a chain's current signed PDF (ACL-authorized),
// used to re-resolve the current PDF for a PAdES co-sign (sign on top of it).
// ErrNotFound when none exists yet or the caller is off the ACL.
func (s *Service) GetLatestSignedPdfByChain(ctx context.Context, parentID string, caller store.Caller) (*store.Document, error) {
	return s.store.GetLatestSignedPdfByChain(ctx, parentID, caller)
}

// Get returns one ACL-authorized metadata row (no bytes).
func (s *Service) Get(ctx context.Context, id string, caller store.Caller) (*store.Document, error) {
	return s.store.Get(ctx, id, caller)
}

// Grant records standing ACL access (read / co-sign) on a document's chain for
// an invited participant. Idempotent.
func (s *Service) Grant(ctx context.Context, in store.GrantInput) error {
	return s.store.Grant(ctx, in)
}

// List returns the documents the caller may read (keyset by descending id).
func (s *Service) List(ctx context.Context, caller store.Caller, limit int, after string) ([]*store.Document, error) {
	return s.store.List(ctx, caller, limit, after)
}

// ListChains lists the caller's documents projected one live-head row per
// chain (the "always latest" view), keyset-paginated by chain root id.
func (s *Service) ListChains(ctx context.Context, caller store.Caller, limit int, after string, includeExpired bool) ([]*store.Chain, error) {
	return s.store.ListChains(ctx, caller, limit, after, includeExpired)
}

// GetChain reads ONE chain as its live head, addressed by any id in it. The
// screen that owns a document reads this rather than searching a listing for it:
// a listing may legitimately omit the chain, and a chain's own facts must not
// depend on that.
func (s *Service) GetChain(ctx context.Context, caller store.Caller, id string) (*store.Chain, error) {
	return s.store.GetChain(ctx, caller, id)
}

// ListHistory lists the owner's terminal chains — the history records that
// remain after storage is destroyed, for the bounded keep window.
func (s *Service) ListHistory(ctx context.Context, owner string, limit int, after string) ([]*store.HistoryChain, error) {
	return s.store.ListHistory(ctx, owner, limit, after)
}

// SweepHistory erases terminal metadata records older than the keep window.
func (s *Service) SweepHistory(ctx context.Context, before time.Time, limit int) (int, error) {
	return s.store.SweepHistory(ctx, before, limit)
}

// DeleteHistoryChain removes one of the owner's history records early.
func (s *Service) DeleteHistoryChain(ctx context.Context, owner, chainRootID string) error {
	return s.store.DeleteHistoryChain(ctx, owner, chainRootID)
}

// Content returns the metadata row and the DECRYPTED bytes. ErrGone is returned
// when the bytes were purged. (Audit of the decrypted-byte access is the routes'
// job — this method emits nothing.)
func (s *Service) Content(ctx context.Context, id string, caller store.Caller) (*store.Document, []byte, error) {
	doc, err := s.store.Get(ctx, id, caller)
	if err != nil {
		return nil, nil, err
	}
	if doc.StorageRef == "" || doc.EncryptionKeyRef == "" {
		return doc, nil, ErrGone
	}

	sealed, found, err := s.blob.Get(ctx, doc.StorageRef)
	if err != nil {
		return doc, nil, err
	}
	if !found {
		return doc, nil, ErrGone
	}

	wrapped, err := base64.StdEncoding.DecodeString(doc.EncryptionKeyRef)
	if err != nil {
		return doc, nil, fmt.Errorf("documents: decode key ref: %w", err)
	}
	plainKey, err := s.kms.Unwrap(wrapped)
	if err != nil {
		return doc, nil, err
	}
	data, err := kms.Open(plainKey, sealed)
	if err != nil {
		return doc, nil, err
	}

	return doc, data, nil
}

// ExtendRetention rolls an owned document's TTL forward to now + ttl
// (rolling-extension-on-co-sign).
func (s *Service) ExtendRetention(ctx context.Context, id, owner string) error {
	return s.store.ExtendRetention(ctx, id, owner, time.Now().Add(s.ttl))
}

// SetPreservationClass sets/upgrades the B4 class on an owned document.
func (s *Service) SetPreservationClass(ctx context.Context, id, owner, class string) error {
	return s.store.SetPreservationClass(ctx, id, owner, class)
}

// SetResultFreeze sets/clears the chain-level download freeze (resolved to the
// chain root from any of its rows). While frozen, content reads of the chain's
// non-source rows refuse — the signed result is locked during a signing
// workflow and opens at its terminal transition.
func (s *Service) SetResultFreeze(ctx context.Context, id string, frozen bool) error {
	return s.store.SetResultFreeze(ctx, id, frozen)
}

// ChainRetention reports when a chain's bytes stop being downloadable — the latest
// retention instant across the rows that still hold storage. It exists for the
// service that administers the chain's sharing and keeps a record only as long as
// the download does: retention rolls forward on every signing act, so a value that
// service copied earlier is always a lower bound and it cannot compute this itself.
func (s *Service) ChainRetention(ctx context.Context, id string) (time.Time, int, error) {
	return s.store.ChainRetention(ctx, id)
}

// Delete removes the caller's standing access to a document's chain ("remove
// from my documents"). Reference-counted: only when the caller was the last
// participant are the chain's S3 objects + data keys destroyed (refused under a
// legal hold). It returns the PRE-delete row (for the domain event).
func (s *Service) Delete(ctx context.Context, id string, caller store.Caller) (*store.Document, error) {
	doc, err := s.store.Get(ctx, id, caller)
	if err != nil {
		return nil, err
	}

	purged, err := s.store.RemoveAccess(ctx, id, caller)
	if err != nil {
		return nil, err
	}
	for _, ref := range purged {
		if ref.StorageRef != "" {
			// Best effort: the metadata is authoritative; an orphaned object is an
			// ops concern, not a delete failure.
			_ = s.blob.Delete(ctx, ref.StorageRef)
		}
	}

	return doc, nil
}

// Sweep flips expired non-hold documents to "expired" and destroys their S3
// objects + data keys (the retention core.Tasker). Returns how many were purged.
func (s *Service) Sweep(ctx context.Context, now time.Time, limit int) (int, error) {
	refs, err := s.store.SweepRetention(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	for i := range refs {
		if refs[i].StorageRef != "" {
			_ = s.blob.Delete(ctx, refs[i].StorageRef)
		}
	}

	return len(refs), nil
}
