// Package response holds the document-store HTTP response DTOs.
package response

import (
	"time"

	"github.com/signbyte/document-store/store"
)

// Ingested is the POST /api/v1/documents result.
type Ingested struct {
	ID                string `json:"id"`
	ContentHash       string `json:"contentHash"` // canonical SHA-256 (B1), base64
	Mime              string `json:"mime"`
	Size              int64  `json:"size"`
	PreservationClass string `json:"preservationClass"`
	// HasSignatures reports a structural detection only (a signature dictionary
	// exists), not a cryptographic verification — the caller decides what to do
	// with an already-signed upload (surface it, route to validation, ignore it).
	HasSignatures bool `json:"hasSignatures"`
}

// Document is the metadata projection returned by GET /api/v1/documents/{id} and
// in listings. It never carries the storage_ref / encryption_key_ref (internal).
type Document struct {
	ID                string    `json:"id"`
	Owner             string    `json:"owner"`
	TenantID          string    `json:"tenantId,omitempty"`
	Kind              string    `json:"kind"`
	ParentID          string    `json:"parentId,omitempty"`
	Filename          string    `json:"filename,omitempty"`
	ContentHash       string    `json:"contentHash"`
	Mime              string    `json:"mime"`
	Size              int64     `json:"size"`
	Status            string    `json:"status"`
	PreservationClass string    `json:"preservationClass"`
	RetentionUntil    time.Time `json:"retentionUntil"`
	LegalHold         bool      `json:"legalHold"`
	// InnerFiles lists a container's data objects (name/type/size) for "what's
	// inside" — empty for a plain source. No bytes; extracted only on demand.
	InnerFiles []InnerFile `json:"innerFiles,omitempty"`
	CreatedAt  time.Time   `json:"createdAt"`
	UpdatedAt  time.Time   `json:"updatedAt"`
}

// InnerFile is one data object inside an ASiC-E container — its in-container name,
// media type, and size. The cheap "what's inside" listing; the bytes stay in
// storage, fetched only on demand (preview/download).
type InnerFile struct {
	Name      string `json:"name"`
	MediaType string `json:"mediaType,omitempty"`
	Size      int64  `json:"size,omitempty"`
}

// FromStore maps a store.Document to the response projection.
func FromStore(d *store.Document) Document {
	var inner []InnerFile
	if len(d.InnerFiles) > 0 {
		inner = make([]InnerFile, len(d.InnerFiles))
		for i, f := range d.InnerFiles {
			inner[i] = InnerFile{Name: f.Name, MediaType: f.MediaType, Size: f.Size}
		}
	}

	return Document{
		ID:                d.ID,
		Owner:             d.Owner,
		TenantID:          d.TenantID,
		Kind:              d.Kind,
		ParentID:          d.ParentID,
		Filename:          d.Filename,
		ContentHash:       d.ContentHash,
		Mime:              d.Mime,
		Size:              d.Size,
		Status:            d.Status,
		PreservationClass: d.PreservationClass,
		RetentionUntil:    d.RetentionUntil,
		LegalHold:         d.LegalHold,
		InnerFiles:        inner,
		CreatedAt:         d.CreatedAt,
		UpdatedAt:         d.UpdatedAt,
	}
}

// DocumentList is the GET /api/v1/documents listing result.
type DocumentList struct {
	Documents []Document `json:"documents"`
	Count     int        `json:"count"`
}

// Chain is one row of the chains listing view (GET /api/v1/documents?view=chains):
// a document chain projected to its single live head — the signed artifact where
// one exists, else the uploaded source. HasSignatures reports the head carries
// signatures (including a file that arrived already signed); PlatformSigned
// reports the head was produced by a signing here rather than being the upload
// itself; ChainCreatedAt is when the chain started.
type Chain struct {
	ChainRootID       string    `json:"chainRootId"`
	ID                string    `json:"id"`
	Kind              string    `json:"kind"`
	Status            string    `json:"status"`
	Filename          string    `json:"filename,omitempty"`
	Mime              string    `json:"mime"`
	Size              int64     `json:"size"`
	RetentionUntil    time.Time `json:"retentionUntil"`
	LegalHold         bool      `json:"legalHold"`
	PreservationClass string    `json:"preservationClass"` // none|b_lt|preservation — 'preservation' once archive-timestamped (B-LTA)
	HasSignatures     bool      `json:"hasSignatures"`
	PlatformSigned    bool      `json:"platformSigned"`
	// ResultFrozen: a signing workflow over the chain is in progress — the
	// signed result is download-locked until its terminal transition, and a
	// listing consumer renders the row as in-signing.
	ResultFrozen bool `json:"resultFrozen,omitempty"`
	// InnerFiles lists the head container's data objects — carried by the
	// single-chain read so a screen showing "what's inside" needs one call; the
	// listing view leaves it empty.
	InnerFiles     []InnerFile `json:"innerFiles,omitempty"`
	ChainCreatedAt time.Time   `json:"chainCreatedAt"`
	CreatedAt      time.Time   `json:"createdAt"`
	UpdatedAt      time.Time   `json:"updatedAt"`
}

// ChainFromStore maps a store.Chain to the response projection.
func ChainFromStore(c *store.Chain) Chain {
	var inner []InnerFile
	if len(c.InnerFiles) > 0 {
		inner = make([]InnerFile, len(c.InnerFiles))
		for i, f := range c.InnerFiles {
			inner[i] = InnerFile{Name: f.Name, MediaType: f.MediaType, Size: f.Size}
		}
	}

	return Chain{
		InnerFiles:        inner,
		ChainRootID:       c.ChainRootID,
		ID:                c.ID,
		Kind:              c.Kind,
		Status:            c.Status,
		Filename:          c.Filename,
		Mime:              c.Mime,
		Size:              c.Size,
		RetentionUntil:    c.RetentionUntil,
		LegalHold:         c.LegalHold,
		PreservationClass: c.PreservationClass,
		HasSignatures:     c.HasSignatures,
		PlatformSigned:    c.PlatformSigned,
		ResultFrozen:      c.ResultFrozen,
		ChainCreatedAt:    c.ChainCreatedAt,
		CreatedAt:         c.CreatedAt,
		UpdatedAt:         c.UpdatedAt,
	}
}

// ChainList is the GET /api/v1/documents?view=chains listing result.
type ChainList struct {
	Chains []Chain `json:"chains"`
	Count  int     `json:"count"`
}

// HistoryChain is one terminal chain in the caller's history: storage destroyed,
// only this record remaining for the bounded keep window. DestroyedAt is when
// the head reached its terminal state.
type HistoryChain struct {
	ChainRootID    string    `json:"chainRootId"`
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Status         string    `json:"status"`
	Filename       string    `json:"filename,omitempty"`
	Mime           string    `json:"mime"`
	Size           int64     `json:"size"`
	HasSignatures  bool      `json:"hasSignatures"`
	PlatformSigned bool      `json:"platformSigned"`
	ChainCreatedAt time.Time `json:"chainCreatedAt"`
	DestroyedAt    time.Time `json:"destroyedAt"`
}

// HistoryFromStore maps a store.HistoryChain to the response projection.
func HistoryFromStore(h *store.HistoryChain) HistoryChain {
	return HistoryChain{
		ChainRootID:    h.ChainRootID,
		ID:             h.ID,
		Kind:           h.Kind,
		Status:         h.Status,
		Filename:       h.Filename,
		Mime:           h.Mime,
		Size:           h.Size,
		HasSignatures:  h.HasSignatures,
		PlatformSigned: h.PlatformSigned,
		ChainCreatedAt: h.ChainCreatedAt,
		DestroyedAt:    h.DestroyedAt,
	}
}

// HistoryList is the GET /api/v1/history listing result.
type HistoryList struct {
	Chains []HistoryChain `json:"chains"`
	Count  int            `json:"count"`
}

// Archived is the POST /api/v1/documents/{id}/archived result: the signed head
// refreshed in place with its archive-timestamped form — the SAME document id,
// now pointing at the archived bytes.
type Archived struct {
	ID          string `json:"id"`
	ContentHash string `json:"contentHash"`
	Mime        string `json:"mime"`
	Size        int64  `json:"size"`
}

// Digest is the GET /api/v1/documents/{id}/digest result — the canonical digest
// the Signing Orchestrator fetches (no bytes).
type Digest struct {
	ID          string `json:"id"`
	ContentHash string `json:"contentHash"` // base64
	Algorithm   string `json:"algorithm"`   // "SHA-256"
}

// DataObject is one inner file of an ASiC-E container: the in-container filename
// and its canonical SHA-256, base64. The Signing Orchestrator registers these for
// a parallel co-signature (which signs the container's inner files, not the blob).
type DataObject struct {
	Name        string `json:"name"`
	ContentHash string `json:"contentHash"` // base64 SHA-256
	Algorithm   string `json:"algorithm"`   // "SHA-256"
}

// DataObjects is the GET /api/v1/documents/{id}/data-objects result: the inner
// data objects of an ASiC-E container, by name + digest, for a parallel co-sign.
type DataObjects struct {
	ContainerID string       `json:"containerId"`
	DataObjects []DataObject `json:"dataObjects"`
}

// Container is the result of /complete, /assemble, /add-signature: the stored
// assembled container (id + canonical hash). DSS validation is NOT performed here —
// it is the Signing Orchestrator's call; container integrity is
// self-checked at assembly via asice.CheckReferences (the B1 digest invariant).
type Container struct {
	ContainerID string `json:"containerId"`
	ContentHash string `json:"contentHash"`
	Mime        string `json:"mime"`
	Size        int64  `json:"size"`
}

// SignedDocument is the result of /documents/{id}/signed: a finished, opaque
// signed document (e.g. a PDF signed in place) stored verbatim against its chain.
// Unlike Container it is not assembled or reference-checked here — integrity is the
// embedded signature, verified later by the validate call.
type SignedDocument struct {
	SignedDocumentID string `json:"signedDocumentId"`
	ContentHash      string `json:"contentHash"`
	Mime             string `json:"mime"`
	Size             int64  `json:"size"`
}

// ChainRetention says how long a chain's bytes remain downloadable: the latest
// retention instant across the rows that still hold storage, and how many such rows
// there are. LiveRows 0 means nothing is stored any more, and RetentionUntil is then
// the zero instant — there is no download left to outlive. It carries no content, no
// owner and no personal data: only the clock.
type ChainRetention struct {
	RetentionUntil time.Time `json:"retentionUntil"`
	LiveRows       int       `json:"liveRows"`
}

// ChainHead is the current live head of a chain, resolved by chain root — the
// signed artifact a co-signer must sign next (never a stale client-supplied id).
// Id is empty when no signed head exists yet (the chain is still just its source,
// so the caller signs the root). Kind is "pdf" (PAdES) or "container" (ASiC-E).
type ChainHead struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	ContentHash string `json:"contentHash"`
}
