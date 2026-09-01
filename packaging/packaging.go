// Package packaging embeds the gmb-lib/go-asice library and exposes thin
// in-process wrappers for ASiC-E assembly. No extra service, no byte hop: the
// Document Service is the sole byte owner.
//
// This path is XAdES / ASiC-E ONLY. For PAdES the signer returns a complete signed
// PDF (no fileless container) which the Document Service stores directly — it never
// reaches this package.
package packaging

import "github.com/gmb-lib/go-asice"

// File is a named blob (re-exported so callers don't import asice directly).
type File = asice.File

// MimeType is the ASiC-E container content type.
const MimeType = asice.MimeType

// InnerFile is one data object inside an ASiC-E container — its in-container name,
// media type, and size — captured as cheap "what's inside" metadata without holding
// the bytes (those stay in encrypted storage, fetched only on demand).
type InnerFile struct {
	Name      string `json:"name"`
	MediaType string `json:"mediaType,omitempty"`
	Size      int64  `json:"size,omitempty"`
}

// Inspect detects whether data is an ASiC-E container and, if so, returns its inner
// data objects (name/type/size) in one pass — both the answer the ingest detection
// needs and the manifest the portal lists. Detection is authoritative: it keys on
// the parsed ASiC-E structure (a manifest or signatures, which a plain ZIP has
// neither of) via go-asice's own Inspect, so a non-container — or arbitrary bytes —
// yields isContainer=false. The bytes are never trusted by filename/MIME.
func Inspect(data []byte) (files []InnerFile, isContainer bool) {
	manifest, signatures, objects, err := asice.Inspect(data)
	if err != nil || (len(manifest.Entries) == 0 && len(signatures) == 0) {
		return nil, false
	}

	files = make([]InnerFile, 0, len(objects))
	for _, o := range objects {
		files = append(files, InnerFile{Name: o.Name, MediaType: o.MediaType, Size: o.Size})
	}

	return files, true
}

// BuildUnsigned assembles a signature-less ASiC-E holding the documents in the
// given order (mimetype + data objects + manifest, no signatures) — the
// multi-document bundle's at-rest form. The first signature is later merged in
// exactly like a parallel co-signature (CoSign), so the bundle signs over the
// same path as any existing container.
func BuildUnsigned(docs []File) ([]byte, error) {
	return asice.BuildUnsigned(docs)
}

// CheckReferences enforces the B1 digest invariant before assembly: the
// signatures must reference exactly the supplied documents (count + filename +
// SHA-256). An error here means an integrity mismatch — fail closed.
func CheckReferences(docs, signatures []File) error {
	return asice.CheckReferences(docs, signatures)
}

// Assemble builds a new ASiC-E from document(s) + detached XAdES signature(s)
// after checking references (file-mode path, /documents/assemble).
func Assemble(docs, signatures []File) ([]byte, error) {
	if err := asice.CheckReferences(docs, signatures); err != nil {
		return nil, err
	}

	return asice.BuildContainer(docs, signatures, nil)
}

// Complete fills LVRTC's FILELESS ASiC-E with the source bytes
// (asice.AddDocuments) — the primary MVP hash-only path
// (/documents/{id}/complete).
func Complete(filelessContainer []byte, docs []File) ([]byte, error) {
	return asice.AddDocuments(filelessContainer, docs)
}

// AddSignature adds a parallel (co-sign) signature to an existing container
// (/documents/{id}/add-signature, the Envelope multi-signer seam D1).
func AddSignature(container, signature []byte) ([]byte, error) {
	return asice.AddSignature(container, signature)
}

// CoSign merges the signature(s) from the signer's FILELESS hash-only result into
// an existing container as parallel co-signature(s) — the path taken when the
// document being signed is itself an ASiC-E container. It adds the new signature
// alongside the existing ones over the same data objects (a merge), rather than
// wrapping the whole container as a new data object (which would nest a container
// inside a container).
func CoSign(container, fileless []byte) ([]byte, error) {
	return asice.CoSign(container, fileless)
}

// DataObjects returns a container's inner data objects (the signed files) with
// their bytes, so the caller can compute the per-file digests a parallel
// co-signature must reference — a co-signature signs the container's inner files,
// not the container blob as a whole.
func DataObjects(container []byte) ([]File, error) {
	return asice.DataObjects(container)
}
