package routes

import (
	"context"
	"errors"
	"io"
	"math"
	"mime/multipart"
	"strings"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	docgate "github.com/gmb-lib/go-docgate"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	pkweb "github.com/gmb-lib/go-platform-kit/web"

	"github.com/signbyte/document-store/clamav"
	"github.com/signbyte/document-store/documents"
	"github.com/signbyte/document-store/packaging"
	"github.com/signbyte/document-store/routes/request"
	"github.com/signbyte/document-store/routes/response"
	"github.com/signbyte/document-store/store"
)

// ingest streams an upload, computes the canonical SHA-256 (B1), envelope-encrypts
// it, stores it in S3, and persists a `source` row with retention_until = now+TTL.
//
// @operationId IngestDocument
// @title Ingest a document
// @description Upload a document (multipart `file`). Computes the canonical SHA-256, envelope-encrypts the bytes into S3, and stores a source row with a 24h TTL. Returns the id + canonical digest.
// @accept multipart/form-data
// @param file formData file true "The document bytes"
// @param mime formData string false "MIME type override (else the part's Content-Type)"
// @param preservation_class formData string false "none | b_lt | preservation (default none)"
// @success 201 IngestedResponse response.Ingested "Stored"
// @failure 400 string string "Invalid upload"
// @failure 413 string string "File too large"
// @resource Documents
// @route /api/v1/documents [post].
func (r *router) ingest(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	caller := callerID(ctx)

	fh, data, ok := r.readRequiredFile(ctx, "file")
	if !ok {
		return
	}

	presv := formField(ctx, "preservation_class")
	if !request.ValidPreservationClass(presv) {
		ctx.Error(pkerrors.NewProblem("err:document:invalidPreservationClass",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("preservation_class must be none, b_lt or preservation")))

		return
	}

	mime := formField(ctx, "mime")
	if mime == "" {
		mime = fh.Header.Get("Content-Type")
	}

	// The document gate: filename hygiene, size caps, and structural checks on
	// content that claims or appears to be PDF or ASiC-E — any other format is
	// stored opaque. Run on this user-facing upload only; the internal
	// store-back routes receive platform-produced bytes. The gate is also the
	// signed-upload detector: a PDF that already carries a signature is
	// recorded as a signed pdf row, so a later co-sign embeds into it instead
	// of treating it as an unsigned source (an uploaded ASiC-E is recorded as
	// a container by the service's manifest capture the same way).
	gate, err := docgate.Check(docgate.ModeSigning, fh.Filename, data,
		docgate.WithMaxBytes(r.Config().MaxFileBytes))
	if err != nil {
		r.Audit().IngestOutcome(ctx, caller, false)
		r.writeGateErr(ctx, err)

		return
	}

	// Optional malware scan — a deployment seam: active only when
	// CLAMAV_ENDPOINT is configured, skipped entirely otherwise.
	if ep := r.Config().ClamAVEndpoint; ep != "" {
		// Scan on a standalone context, never the request context: the request
		// context is recycled into a pool the moment this handler returns, so
		// handing it to the dialer would leave a cancellation-watcher goroutine
		// reading that recycled object afterwards (a data race). The scan carries
		// its own dial and stream timeouts, so it stays bounded on its own.
		verdict, err := clamav.Scan(context.Background(), ep, data)
		if err == nil && !verdict.Clean {
			r.Audit().IngestOutcome(ctx, caller, false)
			ctx.Error(pkerrors.NewProblem("err:document:infectedUpload",
				pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
				pkerrors.WithTitle("Upload rejected by malware scan"),
				pkerrors.WithDetail("the malware scan rejected this file ("+verdict.Signature+")")))

			return
		}
		if err != nil {
			// Fail-open by design: the scan is an optional add-on and must not
			// take document intake down with it; the failure stays observable.
			ctx.Log().Warn("malware scan unavailable, upload admitted unscanned", zap.Error(err))
		}
	}

	in := documents.IngestInput{
		Owner:             caller,
		Filename:          fh.Filename,
		Mime:              mime,
		PreservationClass: presv,
		Data:              data,
	}
	if gate.Kind == docgate.KindPDF && gate.HasSignatures {
		in.Kind = "pdf"
		in.Status = "signed"
	}

	doc, err := r.Documents().Ingest(ctx, in)
	if err != nil {
		r.Audit().IngestOutcome(ctx, caller, false)
		r.writeStoreErr(ctx, err)

		return
	}

	r.Audit().IngestOutcome(ctx, caller, true)
	r.Audit().Uploaded(ctx, caller, doc)

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(&response.Ingested{
		ID:                doc.ID,
		ContentHash:       doc.ContentHash,
		Mime:              doc.Mime,
		Size:              doc.Size,
		PreservationClass: doc.PreservationClass,
		HasSignatures:     gate.HasSignatures,
	})
}

// writeGateErr maps a document-gate rejection onto the error contract with the
// underlying cause in the detail (a swallowed detector error would be
// indistinguishable from a clean verdict).
func (r *router) writeGateErr(ctx *azugo.Context, err error) {
	switch {
	case errors.Is(err, docgate.ErrTooLarge):
		r.Audit().CapExceeded(ctx, callerID(ctx))
		ctx.Error(pkerrors.NewProblem("err:document:fileTooLarge",
			pkerrors.WithStatus(fasthttp.StatusRequestEntityTooLarge),
			pkerrors.WithTitle("File too large"),
			pkerrors.WithDetail(err.Error())))
	default:
		ctx.Error(pkerrors.NewProblem("err:document:malformedUpload",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithTitle("Upload rejected"),
			pkerrors.WithDetail(err.Error())))
	}
}

// list returns the caller's documents (keyset paginated by descending id).
// With ?view=chains the listing collapses to one live-head row per document
// chain (the signed artifact where one exists, else the source) — the
// "always latest" view; expired chains are omitted unless ?includeExpired=true.
//
// @operationId ListDocuments
// @param view query string false "Listing view: omit for raw rows, chains for one live-head row per chain"
// @param includeExpired query bool false "chains view only: include chains whose head has expired"
// @route /api/v1/documents [get].
func (r *router) list(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}

	limit := 0
	if l, err := ctx.Query.IntOptional("limit"); err == nil && l != nil {
		limit = *l
	}
	after := ""
	if v := ctx.Query.StringOptional("after"); v != nil {
		after = *v
	}

	if v := ctx.Query.StringOptional("view"); v != nil && *v == "chains" {
		includeExpired := false
		if b, err := ctx.Query.BoolOptional("includeExpired"); err == nil && b != nil {
			includeExpired = *b
		}

		chains, err := r.Documents().ListChains(ctx, reqCaller(ctx), limit, after, includeExpired)
		if err != nil {
			r.writeStoreErr(ctx, err)

			return
		}

		out := response.ChainList{Count: len(chains), Chains: make([]response.Chain, 0, len(chains))}
		for _, c := range chains {
			out.Chains = append(out.Chains, response.ChainFromStore(c))
		}
		ctx.JSON(&out)

		return
	}

	docs, err := r.Documents().List(ctx, reqCaller(ctx), limit, after)
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	out := response.DocumentList{Count: len(docs)}
	for _, d := range docs {
		out.Documents = append(out.Documents, response.FromStore(d))
	}
	ctx.JSON(&out)
}

// getDocument returns one owner-filtered metadata row.
//
// @operationId GetDocument
// @route /api/v1/documents/{id} [get].
func (r *router) getDocument(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}

	doc, err := r.Documents().Get(ctx, ctx.Params.String("id"), reqCaller(ctx))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	out := response.FromStore(doc)
	ctx.JSON(&out)
}

// getDigest returns the canonical digest the Signing Orchestrator fetches (no
// bytes — S4 byte ownership stays here).
//
// @operationId GetDocumentDigest
// @route /api/v1/documents/{id}/digest [get].
func (r *router) getDigest(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}

	doc, err := r.Documents().Get(ctx, ctx.Params.String("id"), reqCaller(ctx))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	ctx.JSON(&response.Digest{ID: doc.ID, ContentHash: doc.ContentHash, Algorithm: "SHA-256"})
}

// getContent returns the DECRYPTED bytes (re-fetch for finalize / download). It
// records a GDPR-audit (GDPR access) event per retrieval.
//
// @operationId GetDocumentContent
// @route /api/v1/documents/{id}/content [get].
func (r *router) getContent(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}
	caller := callerID(ctx)

	doc, data, err := r.Documents().Content(ctx, ctx.Params.String("id"), reqCaller(ctx))
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound), errors.Is(err, documents.ErrGone):
			r.writeStoreErr(ctx, err)
		default:
			r.Audit().IntegrityFailure(ctx, caller, "content decrypt/read failed")
			r.writeStoreErr(ctx, err)
		}

		return
	}

	// The chain's download freeze: while a signing workflow over the chain is
	// in progress the signed RESULT is not served — it opens at the workflow's
	// terminal transition; the source/input stays readable for review. The
	// platform's own byte conduits declare their purpose and keep working. No
	// access audit on a refusal — no bytes were handed over.
	if doc.ResultFrozen && doc.Kind != "source" && !isConduit(ctx) {
		ctx.Error(pkerrors.NewProblem("err:document:resultFrozen",
			pkerrors.WithStatus(fasthttp.StatusConflict),
			pkerrors.WithDetail("the signed result is locked while its signing workflow is in progress; it becomes available when the workflow reaches a final state")))

		return
	}

	// GDPR-audit: a decrypted-bytes retrieval is a personal-data access. The actor is
	// the authenticated caller and the data subject is the document owner — so a
	// co-signer reading the owner's document records the cross-person access here, no
	// new audit surface needed.
	r.Audit().DocumentAccessed(ctx, caller, doc.Owner, doc.ID)

	setDownloadHeaders(ctx, doc.Filename, doc.Mime)
	ctx.Raw(data)
}

// deleteDocument soft-deletes an owned document and destroys its bytes + data key
// (honours legal hold).
//
// @operationId DeleteDocument
// @route /api/v1/documents/{id} [delete].
func (r *router) deleteDocument(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	caller := callerID(ctx)

	doc, err := r.Documents().Delete(ctx, ctx.Params.String("id"), reqCaller(ctx))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	r.Audit().DeleteOutcome(ctx, caller, true)
	r.Audit().Deleted(ctx, caller, doc)

	ctx.StatusCode(fasthttp.StatusNoContent)
}

// grantACLRequest invites an eIDAS serial to a document's chain with the given
// rights (default read + co-sign when omitted).
type grantACLRequest struct {
	Serial string   `json:"serial"`
	Rights []string `json:"rights"`
}

// resultFreezeRequest sets/clears the chain's download freeze.
type resultFreezeRequest struct {
	Frozen *bool `json:"frozen" validate:"required"`
}

// resultFreeze sets/clears the chain-level download freeze. The workflow
// service — the same grant-scope authority that administers the chain ACL —
// freezes the signed result at send and lifts it at the workflow's terminal
// transition; while frozen, content reads of the chain's non-source rows
// refuse. Idempotent.
//
// @operationId SetResultFreeze
// @title Set the chain download freeze
// @description Set or clear the chain-level download freeze (the signed result is locked while a signing workflow is in progress). Bounded to the workflow service.
// @param id path string true "Document ID (resolved to its chain root)"
// @success 204 {empty} "Recorded"
// @failure 403 {empty} "Forbidden"
// @failure 404 string string "Document not found"
// @resource Documents
// @route /api/v1/documents/{id}/result-freeze [post].
func (r *router) resultFreeze(ctx *azugo.Context) {
	if !r.requireScope(ctx, "grant") {
		return
	}

	var req resultFreezeRequest
	if err := ctx.Body.JSON(&req); err != nil { // auto-validates
		ctx.Error(err)

		return
	}

	if err := r.Documents().SetResultFreeze(ctx, ctx.Params.String("id"), *req.Frozen); err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusNoContent)
}

// chainRetention reports how long the chain's bytes remain downloadable. The
// workflow service keeps its own record of a signing only as long as that download
// exists, and it cannot work the instant out for itself: retention rolls forward on
// every signing act, so any value it pinned earlier is a lower bound and acting on
// one would drop its record while the document was still readable.
//
// Byte-free and owner-free — the same grant-scope authority that administers the
// chain's ACL and freeze is the gate, and the answer is a clock and a count, never
// content or an identity.
//
// @operationId GetChainRetention
// @title Read the chain's retention horizon
// @description How long the chain's bytes stay downloadable: the latest retention instant across the rows that still hold storage, and how many there are. Zero live rows means nothing is stored any more. Bounded to the workflow service.
// @param id path string true "Document ID (resolved to its chain root)"
// @success 200 {object} response.ChainRetention "The chain's retention horizon"
// @failure 403 {empty} "Forbidden"
// @failure 404 string string "Document not found"
// @resource Documents
// @route /api/v1/documents/{id}/retention [get].
func (r *router) chainRetention(ctx *azugo.Context) {
	if !r.requireScope(ctx, "grant") {
		return
	}

	until, live, err := r.Documents().ChainRetention(ctx, ctx.Params.String("id"))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	ctx.JSON(&response.ChainRetention{RetentionUntil: until, LiveRows: live})
}

// isConduit reports a declared byte-consumer purpose that keeps working while
// the chain's signed result is frozen mid-workflow:
//   - signing — the orchestrator fetching the artifact to merge a co-signature,
//     validate, or archive;
//   - render — the preview service rasterizing pages for in-app viewing;
//   - review — the user retrieving an original input to review or re-stage
//     before signing (a signed result is never handed out this way — only an
//     inner original).
//
// It routes purpose, not trust — the scope grant is the boundary (every caller
// here is a registry-authorized service) — and an undeclared consumer fails
// CLOSED under the freeze.
func isConduit(ctx *azugo.Context) bool {
	if v := ctx.Query.StringOptional("conduit"); v != nil {
		return *v == "signing" || *v == "render" || *v == "review"
	}

	return false
}

// grantACL grants an invited participant standing access to a document's chain.
// The workflow service calls this at send, once per slot, so the invited
// co-signers can read and co-sign the shared document. Bounded by the
// documents:grant scope (held only by the workflow service) — no user can
// self-grant. Idempotent: a re-send re-grants without error.
//
// @operationId GrantDocumentACL
// @title Grant chain access
// @description Grant an invited eIDAS serial standing access (read + co-sign) to the document's chain. Bounded to the workflow service.
// @param id path string true "Document ID (resolved to its chain root)"
// @success 204 {empty} "Granted"
// @failure 400 string string "Missing serial"
// @failure 403 {empty} "Forbidden"
// @failure 404 string string "Document not found"
// @failure 422 string string "Invalid right"
// @resource Documents
// @route /api/v1/documents/{id}/acl [post].
func (r *router) grantACL(ctx *azugo.Context) {
	if !r.requireScope(ctx, "grant") {
		return
	}

	var req grantACLRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}
	serial := strings.TrimSpace(req.Serial)
	if serial == "" {
		ctx.Error(pkerrors.NewProblem("err:document:missingSerial",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("serial is required")))

		return
	}
	for _, right := range req.Rights {
		if right != "read" && right != "cosign" {
			ctx.Error(pkerrors.NewProblem("err:document:invalidRight",
				pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
				pkerrors.WithDetail("rights must be a subset of {read, cosign}")))

			return
		}
	}

	if err := r.Documents().Grant(ctx, store.GrantInput{
		DocID:         ctx.Params.String("id"),
		PrincipalKind: "serial",
		PrincipalID:   serial,
		Rights:        req.Rights,
		GrantedBy:     callerID(ctx),
	}); err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusNoContent)
}

// complete fills LVRTC's FILELESS ASiC-E (multipart `container`) with the stored
// source bytes (asice.AddDocuments), self-checks the digest references locally
// (asice.CheckReferences — the B1 invariant, no DSS call), then stores + hashes the
// container. The primary MVP hash-only path. The user-facing DSS validate is the
// Signing Orchestrator's; it fetches these bytes to validate.
//
// @operationId CompleteContainer
// @accept multipart/form-data
// @param container formData file true "The fileless.asice returned by LVRTC"
// @route /api/v1/documents/{id}/complete [post].
func (r *router) complete(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	caller := callerID(ctx)
	id := ctx.Params.String("id")

	_, fileless, ok := r.readRequiredFile(ctx, "container")
	if !ok {
		return
	}

	// Read the source/container the caller is signing (ACL-authorized: the owner, or
	// an invited co-signer whose eIDAS serial is on the chain). The co-signed
	// container's owner column is provenance only — access is governed by the chain
	// ACL — so the first signature stores it under the caller and a co-sign then
	// replaces that one container in place.
	srcDoc, srcBytes, err := r.Documents().Content(ctx, id, reqCaller(ctx))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	// When the document being signed is itself an ASiC-E container, add the new
	// signature as a parallel co-signature inside it rather than wrapping the whole
	// container as a new data object (which would nest a container in a container).
	if srcDoc.Kind == "container" {
		r.coSignInto(ctx, caller, srcDoc, srcBytes, fileless)

		return
	}

	// The target is a source: create the chain's single container from it. Two
	// parties who begin from the same source can reach here at once, but only one
	// creation wins (one container per chain). The loser re-resolves the winner's
	// container and co-signs into it, so the result is one shared multi-signature
	// container rather than two divergent single-signature ones.
	completed, err := packaging.Complete(fileless, []packaging.File{{Name: srcDoc.Filename, Data: srcBytes}})
	if err != nil {
		r.Audit().IntegrityFailure(ctx, caller, "asice complete (fill) failed: "+err.Error())
		ctx.Error(pkerrors.NewProblem("err:document:packagingFailed",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("could not complete the container: "+err.Error())))

		return
	}

	// The first signature stores the chain's single container, owned by the document
	// owner (not the signing caller) — the owner keeps the document while a co-signer
	// only adds a signature.
	doc, err := r.Documents().Ingest(ctx, documents.IngestInput{
		Owner:             caller,
		Serial:            reqCaller(ctx).Serial, // so a co-signer signing first can read back their new container (chain ACL grants them by serial, not sub)
		Kind:              "container",
		ParentID:          id,
		Filename:          containerName(srcDoc.Filename),
		Mime:              packaging.MimeType,
		PreservationClass: srcDoc.PreservationClass,
		Status:            "signed",
		Data:              completed,
	})
	if err == nil {
		r.Audit().IngestOutcome(ctx, caller, true)
		r.Audit().Uploaded(ctx, caller, doc)
		ctx.StatusCode(fasthttp.StatusCreated)
		ctx.JSON(&response.Container{ContainerID: doc.ID, ContentHash: doc.ContentHash, Mime: doc.Mime, Size: doc.Size})

		return
	}
	if !errors.Is(err, store.ErrChainAdvanced) {
		r.Audit().IngestOutcome(ctx, caller, false)
		r.writeStoreErr(ctx, err)

		return
	}

	// Lost the create race: another party's first co-sign already created the chain's
	// container. Re-resolve it and co-sign into it (reading its current bytes + hash in
	// one pass, so the keep-latest CAS is against the value we merged over).
	winner, werr := r.Documents().GetContainerByParent(ctx, id, reqCaller(ctx))
	if werr != nil {
		r.writeStoreErr(ctx, werr)

		return
	}
	winnerDoc, winnerBytes, werr := r.Documents().Content(ctx, winner.ID, reqCaller(ctx))
	if werr != nil {
		r.writeStoreErr(ctx, werr)

		return
	}
	r.coSignInto(ctx, caller, winnerDoc, winnerBytes, fileless)
}

// coSignInto merges the signer's fileless result as a parallel co-signature into an
// existing container, then keep-latest-replaces the one container per chain in place
// (write new bytes → optimistic CAS on its current hash → drop the old blob). A
// concurrent co-sign that advanced the chain first yields chain_advanced (409), for
// the caller to reload the latest and retry. Writes the HTTP response.
func (r *router) coSignInto(ctx *azugo.Context, caller string, contDoc *store.Document, contBytes, fileless []byte) {
	completed, cerr := packaging.CoSign(contBytes, fileless)
	if cerr != nil {
		r.Audit().IntegrityFailure(ctx, caller, "asice co-sign failed: "+cerr.Error())
		ctx.Error(pkerrors.NewProblem("err:document:packagingFailed",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("could not co-sign the container: "+cerr.Error())))

		return
	}

	doc, rerr := r.Documents().ReplaceContainer(ctx, contDoc.ID, contDoc.ContentHash, completed)
	if rerr != nil {
		r.writeStoreErr(ctx, rerr)

		return
	}

	r.Audit().IngestOutcome(ctx, caller, true)
	r.Audit().Uploaded(ctx, caller, doc)
	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(&response.Container{ContainerID: doc.ID, ContentHash: doc.ContentHash, Mime: doc.Mime, Size: doc.Size})
}

// chainHead resolves a chain's CURRENT live head by its root id — the signed
// artifact a co-signer must sign next. A signed PDF (PAdES) or a container (ASiC-E);
// a chain is one or the other. An uploaded already-signed document is its own chain
// root AND its own head, so it resolves to itself. Returns an empty id when no
// signed head exists yet (the chain is still just its unsigned source), so the
// caller signs the root. This is the server-authoritative resolution: a signer
// never dictates which artifact a slot signs via a stale client-supplied id.
//
// @operationId GetChainHead
// @title Current live head of a chain
// @param id path string true "The chain root document id"
// @success 200 ChainHeadResponse response.ChainHead "The current head (empty id = none yet)"
// @failure 404 string string "Root not found / not on the chain ACL"
// @resource Documents
// @route /api/v1/documents/{id}/head [get].
func (r *router) chainHead(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}
	root := ctx.Params.String("id")

	// A signed PDF is the head for a PAdES chain; a container for an ASiC-E chain.
	pdf, err := r.Documents().GetLatestSignedPdfByChain(ctx, root, reqCaller(ctx))
	if err == nil {
		ctx.JSON(&response.ChainHead{ID: pdf.ID, Kind: pdf.Kind, ContentHash: pdf.ContentHash})

		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		r.writeStoreErr(ctx, err)

		return
	}

	cont, err := r.Documents().GetContainerByParent(ctx, root, reqCaller(ctx))
	if err == nil {
		ctx.JSON(&response.ChainHead{ID: cont.ID, Kind: cont.Kind, ContentHash: cont.ContentHash})

		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		r.writeStoreErr(ctx, err)

		return
	}

	// No signed head yet — the chain is still just its source; the caller signs the root.
	ctx.JSON(&response.ChainHead{})
}

// chain returns ONE document chain as its live head — the projection a document
// screen states: signed-ness, preservation class, retention, the download freeze,
// and the head container's inner files. Addressed by ANY id in the chain (its
// root, or the signed head derived from it), so a bookmark on either resolves to
// the same chain.
//
// Deliberately independent of the listing: a listing filters, pages, and may
// represent a chain by the workflow that covers it, and a chain's own facts must
// never depend on whether some other view chose to show it. Distinct from /head,
// which answers the signing question — which artifact a co-signer must sign next.
//
// @operationId GetDocumentChain
// @title One document chain, as its live head
// @param id path string true "Any document id in the chain (its root or its head)"
// @success 200 ChainResponse response.Chain "The chain's live head"
// @failure 404 string string "No such chain / not on the chain ACL"
// @resource Documents
// @route /api/v1/documents/{id}/chain [get].
func (r *router) chain(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}

	c, err := r.Documents().GetChain(ctx, reqCaller(ctx), ctx.Params.String("id"))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	out := response.ChainFromStore(c)
	ctx.JSON(&out)
}

// dataObjects returns a container's inner data objects by name + canonical SHA-256,
// so the Signing Orchestrator can register them for a parallel co-signature (which
// signs the container's inner files, not the container blob as a whole). It reads
// the decrypted bytes (a signing-prep read, like /complete — no GDPR access event).
// 422 when the document is not an ASiC-E container.
//
// @operationId GetContainerDataObjects
// @title Container data objects
// @description Return an ASiC-E container's inner data objects (name + canonical SHA-256), for registering a parallel co-signature. 422 if the document is not a container.
// @success 200 DataObjectsResponse response.DataObjects "Inner data objects"
// @failure 422 string string "Not an ASiC-E container"
// @resource Documents
// @route /api/v1/documents/{id}/data-objects [get].
func (r *router) dataObjects(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}

	doc, data, err := r.Documents().Content(ctx, ctx.Params.String("id"), reqCaller(ctx))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}
	if doc.Kind != "container" {
		ctx.Error(pkerrors.NewProblem("err:document:notAContainer",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("document is not an ASiC-E container")))

		return
	}

	objs, err := packaging.DataObjects(data)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:document:packagingFailed",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("could not read the container data objects: "+err.Error())))

		return
	}

	out := response.DataObjects{ContainerID: doc.ID}
	for _, o := range objs {
		out.DataObjects = append(out.DataObjects, response.DataObject{
			Name:        o.Name,
			ContentHash: documents.CanonicalHash(o.Data),
			Algorithm:   "SHA-256",
		})
	}
	ctx.JSON(&out)
}

// bundleRequest is the multi-document bundle input: the loose source documents
// to package, in the sender-set order (= the container's inner-file order).
type bundleRequest struct {
	SourceIDs []string `json:"sourceIds"`
	Filename  string   `json:"filename"`
}

// bundle packages 2+ of the caller's loose source documents into ONE unsigned
// ASiC-E container — the multi-document set's at-rest form and its chain root.
// The loose sources are absorbed (rows deleted, blobs destroyed) in the same
// transaction; signing the bundle later merges the first signature in like any
// parallel co-signature. 422 when a document is not an unsigned owned source.
//
// @operationId BundleDocuments
// @title Bundle documents
// @description Package two or more of the caller's unsigned source documents into one unsigned ASiC-E container (the multi-document bundle), absorbing the loose sources.
// @success 201 DocumentResponse response.Document "The bundle container row"
// @failure 422 string string "A document is not bundleable"
// @resource Documents
// @route /api/v1/documents/bundle [post].
func (r *router) bundle(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	caller := callerID(ctx)

	var req bundleRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}
	if len(req.SourceIDs) < 1 {
		ctx.Error(pkerrors.NewProblem("err:document:bundleTooSmall",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("a bundle needs at least one source document")))

		return
	}

	doc, err := r.Documents().Bundle(ctx, caller, "", req.SourceIDs, req.Filename)
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	r.Audit().Uploaded(ctx, caller, doc)

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(response.FromStore(doc))
}

// rebundleRequest rebuilds an unsigned bundle from entries in final order: an
// existing inner file (name) or a newly staged loose source (sourceId) each.
type rebundleRequest struct {
	Entries []struct {
		Name     string `json:"name"`
		SourceID string `json:"sourceId"`
	} `json:"entries"`
}

// rebundle rebuilds an UNSIGNED bundle (a draft edit: add / remove / reorder
// inner files) in place under the keep-latest CAS, refreshing the manifest and
// absorbing newly staged sources. A signed container is never rebundled (422).
//
// @operationId RebundleDocument
// @title Rebundle an unsigned bundle
// @description Rebuild an unsigned multi-document bundle from the given entries (existing inner files by name, new sources by id) in final order.
// @success 200 DocumentResponse response.Document "The updated bundle row"
// @failure 422 string string "Not an unsigned bundle / entry not bundleable"
// @resource Documents
// @route /api/v1/documents/{id}/rebundle [post].
func (r *router) rebundle(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}

	var req rebundleRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}
	if len(req.Entries) < 1 {
		ctx.Error(pkerrors.NewProblem("err:document:bundleTooSmall",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("a bundle needs at least one entry")))

		return
	}
	entries := make([]documents.BundleEntry, len(req.Entries))
	for i, e := range req.Entries {
		entries[i] = documents.BundleEntry{Name: e.Name, SourceID: e.SourceID}
	}

	doc, err := r.Documents().Rebundle(ctx, callerID(ctx), ctx.Params.String("id"), entries)
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	ctx.JSON(response.FromStore(doc))
}

// extractObject streams ONE named inner data object out of a container —
// extract-an-original on demand (the loose originals are absorbed at bundle
// time, so the container is their only home). Works on unsigned bundles and
// signed containers alike. A decrypted retrieval of the user's content, so it
// records the same GDPR access event as a content download.
//
// It returns only an inner ORIGINAL — never a signature or the assembled
// container — but the chain's download freeze still applies: while a signing
// workflow is in progress an undeclared reader is refused, and only a declared
// purpose (render / review / signing) keeps working. Same rule as a content read.
//
// @operationId ExtractContainerDataObject
// @title Extract one inner file
// @description Stream one named inner data object out of an ASiC-E container (extract-an-original on demand). Refused while the chain's signing workflow is in progress unless the caller declares a review/render/signing purpose.
// @success 200 file byte "The inner file bytes"
// @failure 409 {empty} "The signing workflow is in progress; the download is locked"
// @failure 422 string string "Not an ASiC-E container"
// @resource Documents
// @route /api/v1/documents/{id}/data-objects/{name} [get].
func (r *router) extractObject(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}
	caller := callerID(ctx)

	doc, data, err := r.Documents().Content(ctx, ctx.Params.String("id"), reqCaller(ctx))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}
	if doc.Kind != "container" {
		ctx.Error(pkerrors.NewProblem("err:document:notAContainer",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("document is not an ASiC-E container")))

		return
	}

	// While the chain's signing workflow is in progress the download is locked,
	// exactly as for a whole-container read — an undeclared consumer is refused;
	// preview, the signing orchestrator, and a user reviewing an original declare
	// their purpose and keep working. No access audit on a refusal — no bytes were
	// handed over.
	if doc.ResultFrozen && !isConduit(ctx) {
		ctx.Error(pkerrors.NewProblem("err:document:resultFrozen",
			pkerrors.WithStatus(fasthttp.StatusConflict),
			pkerrors.WithDetail("the signed result is locked while its signing workflow is in progress; it becomes available when the workflow reaches a final state")))

		return
	}

	objs, err := packaging.DataObjects(data)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:document:packagingFailed",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("could not read the container data objects: "+err.Error())))

		return
	}

	name := pkweb.PathParam(ctx, "name")
	for _, o := range objs {
		if o.Name != name {
			continue
		}

		r.Audit().DocumentAccessed(ctx, caller, doc.Owner, doc.ID)

		mime := "application/octet-stream"
		for _, f := range doc.InnerFiles {
			if f.Name == name && f.MediaType != "" {
				mime = f.MediaType

				break
			}
		}
		setDownloadHeaders(ctx, name, mime)
		ctx.Raw(o.Data)

		return
	}

	ctx.Error(pkerrors.NewProblem("err:document:notFound",
		pkerrors.WithTitle("Inner file not found"),
		pkerrors.WithDetail("the container holds no inner file with that name")))
}

// assemble builds a new container from uploaded document(s) + detached XAdES
// signature(s) (file-mode), stores + hashes it, then validates it.
//
// @operationId AssembleContainer
// @accept multipart/form-data
// @param documents formData file true "Original document(s)"
// @param signatures formData file true "Detached XAdES signature(s)"
// @route /api/v1/documents/assemble [post].
func (r *router) assemble(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	caller := callerID(ctx)

	docs, ok := r.readFiles(ctx, "documents")
	if !ok {
		return
	}
	sigs, ok := r.readFiles(ctx, "signatures")
	if !ok {
		return
	}
	if len(docs) == 0 || len(sigs) == 0 {
		ctx.Error(pkerrors.NewProblem("err:document:missingFiles",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("documents and signatures are both required")))

		return
	}

	container, err := packaging.Assemble(docs, sigs)
	if err != nil {
		r.Audit().IntegrityFailure(ctx, caller, "asice assemble failed: "+err.Error())
		ctx.Error(pkerrors.NewProblem("err:document:packagingFailed",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("could not assemble the container: "+err.Error())))

		return
	}

	r.storeContainer(ctx, caller, "", "none", "container.asice", container)
}

// addSignature adds a parallel (co-sign) signature to a stored container, stores
// the new container, validates it, and rolls the source's retention forward.
//
// @operationId AddSignature
// @accept multipart/form-data
// @param signature formData file true "New detached XAdES signature (or fileless.asice)"
// @route /api/v1/documents/{id}/add-signature [post].
func (r *router) addSignature(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	caller := callerID(ctx)
	id := ctx.Params.String("id")

	_, sig, ok := r.readRequiredFile(ctx, "signature")
	if !ok {
		return
	}

	contDoc, contBytes, err := r.Documents().Content(ctx, id, reqCaller(ctx))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	updated, err := packaging.AddSignature(contBytes, sig)
	if err != nil {
		r.Audit().IntegrityFailure(ctx, caller, "asice add-signature failed: "+err.Error())
		ctx.Error(pkerrors.NewProblem("err:document:packagingFailed",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("could not add the signature: "+err.Error())))

		return
	}

	// keep-latest: replace the container's bytes in place (CAS on its current
	// hash) rather than piling a new row.
	doc, err := r.Documents().ReplaceContainer(ctx, id, contDoc.ContentHash, updated)
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}
	r.Audit().IngestOutcome(ctx, caller, true)
	r.Audit().Uploaded(ctx, caller, doc)
	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(&response.Container{ContainerID: doc.ID, ContentHash: doc.ContentHash, Mime: doc.Mime, Size: doc.Size})

	// Rolling-extension-on-co-sign (best effort): roll the chain root forward.
	if contDoc.ParentID != "" {
		if err := r.Documents().ExtendRetention(ctx, contDoc.ParentID, caller); err != nil {
			ctx.Log().Warn("extend retention on co-sign failed", zap.Error(err))
		}
	}
}

// storeSigned stores a finished, opaque signed document against its chain — e.g. a
// PDF signed in place, where the signature is embedded and there is no container to
// assemble. Format-agnostic: the artifact is stored verbatim as its own form (a PDF
// is stored as kind "pdf"), NOT parsed or reference-checked — integrity is the
// embedded signature, verified later by the validate call. The counterpart of
// /complete (which fills a fileless ASiC-E container). When the target is itself a
// signed PDF — the chain's current head, or an uploaded already-signed PDF that is
// its own chain root — the result supersedes it in place (keep-latest); a fresh row
// is created only for the first signature on a plain source. One live signed
// document per chain is enforced at the data layer: a concurrent second creation
// surfaces as chain-advanced (the caller re-resolves the current one and re-signs —
// an embedded signature cannot be merged after the fact).
//
// @operationId StoreSignedDocument
// @title Store a finished signed document
// @description Store a finished signed document (multipart `signed`) against the chain rooted at {id} — e.g. a PDF signed in place. Stored verbatim as its own form; not assembled or reference-checked. Returns the id + canonical digest.
// @accept multipart/form-data
// @param id path string true "Parent document id (the chain root / source, or the prior signed document)"
// @param signed formData file true "The finished signed document bytes"
// @param mime formData string false "MIME type override (else the part's Content-Type)"
// @success 201 SignedDocumentResponse response.SignedDocument "Stored"
// @failure 400 string string "Invalid upload"
// @failure 404 string string "Parent not found"
// @failure 409 string string "Chain advanced (a signed document already exists for this chain)"
// @resource Documents
// @route /api/v1/documents/{id}/signed [post].
func (r *router) storeSigned(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	caller := callerID(ctx)
	id := ctx.Params.String("id")

	fh, data, ok := r.readRequiredFile(ctx, "signed")
	if !ok {
		return
	}

	if !r.signedFormIsPdf(ctx, caller, data) {
		return
	}

	mime := formField(ctx, "mime")
	if mime == "" {
		mime = fh.Header.Get("Content-Type")
	}

	// Read the parent for lineage + preservation class (ACL-authorized: the signer
	// must be on the chain). Anchor the signed-document chain at the chain root, so a
	// co-sign of a prior signed document still hangs off the same root.
	parent, err := r.Documents().Get(ctx, id, reqCaller(ctx))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}
	chainRoot := parent.ParentID
	if chainRoot == "" {
		chainRoot = parent.ID
	}

	// The document being signed is itself a signed PDF — the chain's current head,
	// or an uploaded already-signed PDF that is its own chain root. The new bytes
	// were signed on top of it, so they SUPERSEDE the chain's current signed PDF in
	// place (keep-latest) rather than adding a second live signed row next to it.
	// The mirror of /complete's container branch (which co-signs into an existing
	// container), minus the merge — a PDF signature arrives already embedded.
	if parent.Kind == "pdf" {
		r.supersedeSignedPdf(ctx, caller, chainRoot, data)

		return
	}

	doc, err := r.Documents().Ingest(ctx, documents.IngestInput{
		Owner:             caller,
		Serial:            reqCaller(ctx).Serial, // read the new row back under the chain ACL (a co-signer is granted by serial, not sub)
		Kind:              "pdf",
		ParentID:          chainRoot,
		Filename:          fh.Filename,
		Mime:              mime,
		PreservationClass: parent.PreservationClass,
		Status:            "signed",
		Data:              data,
	})
	if err != nil {
		// A signed PDF already exists for this chain even though the target was not
		// one (that case supersedes in place above): the caller posted against the
		// chain root while a signed head exists, or lost a concurrent first-sign
		// create race. Resolve the current head and supersede it in place
		// (keep-latest); the CAS on its current hash is the backstop — a further
		// concurrent advance → 409, the caller re-resolves + re-signs (an embedded
		// PDF signature cannot be merged).
		if errors.Is(err, store.ErrChainAdvanced) {
			r.supersedeSignedPdf(ctx, caller, chainRoot, data)

			return
		}
		r.Audit().IngestOutcome(ctx, caller, false)
		r.writeStoreErr(ctx, err)

		return
	}

	r.Audit().IngestOutcome(ctx, caller, true)
	r.Audit().Uploaded(ctx, caller, doc)

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(&response.SignedDocument{
		SignedDocumentID: doc.ID,
		ContentHash:      doc.ContentHash,
		Mime:             doc.Mime,
		Size:             doc.Size,
	})

	// Rolling-extension-on-sign (best effort): roll the chain root forward.
	if err := r.Documents().ExtendRetention(ctx, chainRoot, caller); err != nil {
		ctx.Log().Warn("extend retention on store-signed failed", zap.Error(err))
	}
}

// signedFormIsPdf checks that the bytes a signing service returned really are PDF
// content before this route records them as one. The kind stored below is hard-coded
// "pdf" and everything downstream branches on it — co-signing, preview, validation,
// download — so an artifact of some other form would otherwise be recorded as a
// signed PDF and handed to the person as their signed document, with the first
// notice being a recipient who cannot open it. The two neighbouring paths already
// look at their bytes (a person's upload is gated; a returned container is opened to
// be filled), which left this the one path taking a returned artifact on trust.
//
// Deliberately only the FORM, never the signature. Whether the signature is good is
// the qualified provider's answer: it validates server-side and returns a file only
// when that passes. The form is an observation of the leading bytes, so unlike a
// validity judgement it cannot be wrong in the direction that would matter here —
// discarding a real signature the person has already paid for. That asymmetry is
// what makes refusing the right behaviour on this check and the wrong one on a
// deeper claim; the detector's own signature probe is best-effort in this mode by
// its documented contract, so it is reported and never a reason to refuse.
//
// Writes the error response and returns false on a mismatch.
func (r *router) signedFormIsPdf(ctx *azugo.Context, caller string, data []byte) bool {
	// An extension-less name on purpose: the multipart part's own filename comes
	// from the signing service, and filename hygiene — a rule about names a person
	// chose — must not be able to reject a real signature. With no extension the
	// gate reports the form it detects in the bytes, which is the only question
	// here. The size cap is lifted for the same reason: the source passed the
	// upload cap already, and a signature makes the result larger than what passed.
	gate, err := docgate.Check(docgate.ModeSigning, "signed", data,
		docgate.WithMaxBytes(math.MaxInt64))
	if err == nil && gate.Kind == docgate.KindPDF {
		return true
	}

	observed := string(gate.Kind)
	if err != nil {
		observed = "unreadable content (" + err.Error() + ")"
	}

	// High-severity security event (NIS2): a qualified provider answering with the
	// wrong artifact is an integrity fault on the one artifact the platform never
	// re-derives, and it is invisible in every other record.
	r.Audit().IngestOutcome(ctx, caller, false)
	r.Audit().IntegrityFailure(ctx, caller,
		"signed-PDF store received "+observed+" instead of PDF content")
	ctx.Log().Error("signed result is not the form it was stored as",
		zap.String("expected_form", "pdf"), zap.String("observed_form", observed),
		zap.Bool("signature_detected", gate.HasSignatures), zap.Int("bytes", len(data)))

	ctx.Error(pkerrors.NewProblem("err:document:signedFormMismatch",
		pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
		pkerrors.WithTitle("Signed document is not a PDF"),
		pkerrors.WithDetail("the signed document was stored as a PDF but the bytes are "+
			observed+"; nothing was stored and the document is unchanged")))

	return false
}

// supersedeSignedPdf keep-latest-replaces a chain's current signed PDF in place with a
// co-signature signed on top of it — the PAdES analogue of coSignInto for ASiC-E, minus
// the merge (a PDF co-signature is embedded by the provider, not merged here). The CAS
// is on the head's current content hash; the chain lock guarantees the head is the one
// the caller signed on top of, so a mismatch means a concurrent advance → 409 to retry.
// Writes the HTTP response.
func (r *router) supersedeSignedPdf(ctx *azugo.Context, caller, chainRoot string, data []byte) {
	head, err := r.Documents().GetLatestSignedPdfByChain(ctx, chainRoot, reqCaller(ctx))
	if err != nil {
		r.Audit().IngestOutcome(ctx, caller, false)
		r.writeStoreErr(ctx, err)

		return
	}

	doc, err := r.Documents().ReplaceContainer(ctx, head.ID, head.ContentHash, data)
	if err != nil {
		r.Audit().IngestOutcome(ctx, caller, false)
		r.writeStoreErr(ctx, err)

		return
	}

	r.Audit().IngestOutcome(ctx, caller, true)
	r.Audit().Uploaded(ctx, caller, doc)

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(&response.SignedDocument{
		SignedDocumentID: doc.ID,
		ContentHash:      doc.ContentHash,
		Mime:             doc.Mime,
		Size:             doc.Size,
	})

	// Rolling-extension-on-sign (best effort): roll the chain root forward.
	if err := r.Documents().ExtendRetention(ctx, chainRoot, caller); err != nil {
		ctx.Log().Warn("extend retention on co-sign supersede failed", zap.Error(err))
	}
}

// storeArchived replaces a signed head's bytes in place with its
// archive-timestamped form (B-LT → B-LTA): the same document, refreshed — never
// a new row, so the chain keeps exactly one live signed artifact. Works for
// both signed forms (an ASiC-E container and a signed PDF); a plain source has
// nothing to archive. The swap is an optimistic CAS on the head's current
// content hash, so a concurrent co-sign wins cleanly (409 to retry on the new
// head). The prior blob is destroyed on success.
//
// @operationId StoreArchivedDocument
// @title Store the archive-timestamped form of a signed document
// @param id path string true "The signed head document id (container or signed PDF)"
// @accept multipart/form-data
// @success 200 Archived response.Archived "Replaced in place"
// @failure 404 string string "Not found / not on the chain ACL"
// @failure 409 string string "Chain advanced (the head changed since the archive began)"
// @failure 422 string string "Not a signed document (a source cannot be archived)"
// @resource Documents
// @route /api/v1/documents/{id}/archived [post].
func (r *router) storeArchived(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	id := ctx.Params.String("id")

	_, data, ok := r.readRequiredFile(ctx, "archived")
	if !ok {
		return
	}

	head, err := r.Documents().Get(ctx, id, reqCaller(ctx))
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}
	if head.Kind == "source" {
		ctx.Error(pkerrors.NewProblem("err:document:notSigned",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("only a signed document can carry an archive timestamp")))

		return
	}

	// The swap and the fact are one write. An archive timestamp upgrades the
	// document to long-term preservation (B-LTA); that class is recorded in the
	// same transaction as the new bytes, so a refused fact leaves the document
	// untouched and a swapped document is always recorded as archive-timestamped.
	// Without the fact the only trace is the swapped bytes — indistinguishable
	// from an ordinary co-sign replace — and the activity trail could not show
	// the timestamp after a reload. Whoever the access list lets read the head may
	// add the archive timestamp: a co-signer holds the same document as the
	// uploader.
	doc, err := r.Documents().ReplaceContainerArchived(ctx, head.ID, head.ContentHash, data)
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	ctx.JSON(&response.Archived{
		ID:          doc.ID,
		ContentHash: doc.ContentHash,
		Mime:        doc.Mime,
		Size:        doc.Size,
	})
}

// listHistory returns the caller's terminal chains — the records that remain
// (for a bounded keep window) after a chain's storage is destroyed. Owner-scoped
// by the uploader subject: a deleted chain has no ACL entries left, so history
// is the owner's own record. Keyset-paginated by descending chain root id.
//
// @operationId ListHistory
// @route /api/v1/history [get].
func (r *router) listHistory(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}

	limit := 0
	if l, err := ctx.Query.IntOptional("limit"); err == nil && l != nil {
		limit = *l
	}
	after := ""
	if v := ctx.Query.StringOptional("after"); v != nil {
		after = *v
	}

	chains, err := r.Documents().ListHistory(ctx, callerID(ctx), limit, after)
	if err != nil {
		r.writeStoreErr(ctx, err)

		return
	}

	out := response.HistoryList{Count: len(chains), Chains: make([]response.HistoryChain, 0, len(chains))}
	for _, h := range chains {
		out.Chains = append(out.Chains, response.HistoryFromStore(h))
	}
	ctx.JSON(&out)
}

// deleteHistory removes one of the caller's history records early — a hard
// delete of the terminal chain's remaining metadata. A live or legal-hold chain
// refuses (409): live chains are deleted through the normal document path.
//
// @operationId DeleteHistoryRecord
// @route /api/v1/history/{chainRoot} [delete].
func (r *router) deleteHistory(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}

	if err := r.Documents().DeleteHistoryChain(ctx, callerID(ctx), ctx.Params.String("chainRoot")); err != nil {
		if errors.Is(err, store.ErrChainLive) {
			ctx.Error(pkerrors.NewProblem("err:document:chainLive",
				pkerrors.WithStatus(fasthttp.StatusConflict),
				pkerrors.WithDetail("the chain is live or under legal hold")))

			return
		}
		r.writeStoreErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusNoContent)
}

// storeContainer is the shared tail of complete/assemble/add-signature: ingest the
// container row, emit audit, and write the response. Returns the stored container
// (nil on a store failure). The DSS validate is NOT done here — it is the Signing
// Orchestrator's call;
// container integrity is self-checked at assembly via asice.CheckReferences
// (packaging layer — the B1 digest invariant, pure Go, no DSS).
func (r *router) storeContainer(ctx *azugo.Context, caller, parentID, presv, filename string, container []byte) *store.Document {
	doc, err := r.Documents().Ingest(ctx, documents.IngestInput{
		Owner:             caller,
		Serial:            reqCaller(ctx).Serial, // so a co-signer signing first can read back their new container (chain ACL grants them by serial, not sub)
		Kind:              "container",
		ParentID:          parentID,
		Filename:          filename,
		Mime:              packaging.MimeType,
		PreservationClass: presv,
		Status:            "signed",
		Data:              container,
	})
	if err != nil {
		r.Audit().IngestOutcome(ctx, caller, false)
		r.writeStoreErr(ctx, err)

		return nil
	}

	r.Audit().IngestOutcome(ctx, caller, true)
	r.Audit().Uploaded(ctx, caller, doc)

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(&response.Container{
		ContainerID: doc.ID,
		ContentHash: doc.ContentHash,
		Mime:        doc.Mime,
		Size:        doc.Size,
	})

	return doc
}

// ---- multipart helpers ------------------------------------------------------

// readRequiredFile reads a single required uploaded file, enforcing MAX_FILE_BYTES.
func (r *router) readRequiredFile(ctx *azugo.Context, field string) (*multipart.FileHeader, []byte, bool) {
	fh := ctx.Form.FileOptional(field)
	if fh == nil {
		ctx.Error(pkerrors.NewProblem("err:document:missingFile",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(field+" is required (multipart/form-data)")))

		return nil, nil, false
	}
	if fh.Size > r.Config().MaxFileBytes {
		r.Audit().CapExceeded(ctx, callerID(ctx))
		ctx.Error(pkerrors.NewProblem("err:document:fileTooLarge",
			pkerrors.WithStatus(fasthttp.StatusRequestEntityTooLarge),
			pkerrors.WithTitle("File too large"),
			pkerrors.WithDetail(field+" exceeds MAX_FILE_BYTES")))

		return nil, nil, false
	}
	data, err := readMultipartFile(fh)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:document:invalidUpload",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("could not read "+field)))

		return nil, nil, false
	}

	return fh, data, true
}

// readFiles reads all uploaded files for a field as packaging.File values,
// enforcing the per-file size cap.
func (r *router) readFiles(ctx *azugo.Context, field string) ([]packaging.File, bool) {
	headers := ctx.Form.Files(field)
	files := make([]packaging.File, 0, len(headers))
	for _, fh := range headers {
		if fh.Size > r.Config().MaxFileBytes {
			r.Audit().CapExceeded(ctx, callerID(ctx))
			ctx.Error(pkerrors.NewProblem("err:document:fileTooLarge",
				pkerrors.WithStatus(fasthttp.StatusRequestEntityTooLarge),
				pkerrors.WithTitle("File too large"),
				pkerrors.WithDetail(field+" exceeds MAX_FILE_BYTES")))

			return nil, false
		}
		data, err := readMultipartFile(fh)
		if err != nil {
			ctx.Error(pkerrors.NewProblem("err:document:invalidUpload",
				pkerrors.WithStatus(fasthttp.StatusBadRequest),
				pkerrors.WithDetail("could not read "+field)))

			return nil, false
		}
		files = append(files, packaging.File{Name: fh.Filename, Data: data})
	}

	return files, true
}

// formField reads an optional multipart/form string field, trimmed ("" when absent).
func formField(ctx *azugo.Context, name string) string {
	if v := ctx.Form.StringOptional(name); v != nil {
		return strings.TrimSpace(*v)
	}

	return ""
}

// readMultipartFile reads an uploaded file fully into memory.
func readMultipartFile(fh *multipart.FileHeader) ([]byte, error) {
	f, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return io.ReadAll(f)
}

// containerName derives the container filename from a source filename.
func containerName(sourceFilename string) string {
	if sourceFilename == "" {
		return "container.asice"
	}
	if i := strings.LastIndexByte(sourceFilename, '.'); i > 0 {
		return sourceFilename[:i] + ".asice"
	}

	return sourceFilename + ".asice"
}

// sanitizeFilename strips characters unsafe for a Content-Disposition header.
func sanitizeFilename(name string) string {
	return strings.NewReplacer("\"", "", "\r", "", "\n", "", "\\", "").Replace(name)
}

// browserActiveMimeTypes are content types a browser can render/execute as
// active content (script vector: an uploaded HTML/XHTML/SVG/XML file signed
// or attached as a regular document). setDownloadHeaders coerces these to an
// inert type on the way out, defence-in-depth alongside Content-Disposition
// and nosniff — the stored bytes are never altered; only the outbound
// header/type on a raw-bytes download changes.
var browserActiveMimeTypes = map[string]bool{
	"text/html":             true,
	"application/xhtml+xml": true,
	"image/svg+xml":         true,
	"text/xml":              true,
	"application/xml":       true,
}

// setDownloadHeaders sets the headers every raw-bytes download route needs:
// Content-Disposition (forces save-as, never inline render), X-Content-Type-Options
// nosniff (the browser must honour the declared type, never sniff its way into
// rendering it), and an inert Content-Type for anything a browser could execute
// as active content — a document upload can be any file type a user wants
// signed, so a downloaded document must never come back capable of running as
// a script in this origin's security context.
func setDownloadHeaders(ctx *azugo.Context, filename, mime string) {
	if filename != "" {
		ctx.Header.Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(filename)+"\"")
	}
	ctx.Header.Set("X-Content-Type-Options", "nosniff")
	ctx.ContentType(inertMime(mime))
}

// inertMime returns mime unchanged unless it is one browsers render/execute as
// active content, in which case it returns application/octet-stream.
func inertMime(mime string) string {
	base := mime
	if i := strings.IndexByte(mime, ';'); i >= 0 {
		base = mime[:i]
	}
	if browserActiveMimeTypes[strings.ToLower(strings.TrimSpace(base))] {
		return "application/octet-stream"
	}

	return mime
}
