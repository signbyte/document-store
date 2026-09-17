// Package routes registers the document-store HTTP API.
package routes

import (
	"errors"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/claims"
	"github.com/gmb-lib/go-authbyte/identitycode"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	documentstore "github.com/signbyte/document-store"
	"github.com/signbyte/document-store/documents"
	"github.com/signbyte/document-store/store"
)

type router struct {
	*documentstore.App
}

// Init registers all routes.
func Init(a *documentstore.App) error {
	r := &router{App: a}

	// Public liveness/readiness.
	a.Get("/healthz", r.healthz)
	a.Get("/readyz", r.readyz)

	// Authenticated API (go-authbyte DPoP service tokens; aud svc:document).
	v1 := a.Group("/api/v1")
	v1.Use(a.AuthMiddleware())

	// Ingest + lifecycle.
	v1.Post("/documents", r.ingest)
	v1.Get("/documents", r.list)
	v1.Get("/documents/{id}", r.getDocument)
	v1.Get("/documents/{id}/content", r.getContent)
	v1.Get("/documents/{id}/digest", r.getDigest)
	v1.Get("/documents/{id}/data-objects", r.dataObjects)
	v1.Get("/documents/{id}/head", r.chainHead)
	v1.Get("/documents/{id}/chain", r.chain)
	v1.Delete("/documents/{id}", r.deleteDocument)

	// Standing chain access: the workflow service grants invited co-signers
	// read + co-sign on a document's chain at envelope send (documents:grant).
	v1.Post("/documents/{id}/acl", r.grantACL)
	v1.Post("/documents/{id}/result-freeze", r.resultFreeze)
	// How long the chain's bytes remain downloadable — read by the workflow
	// service, which keeps its own record only as long as that download exists
	// and cannot work the answer out for itself (retention moves on every
	// signing act). Byte-free and owner-free: the sharing authority is the gate.
	v1.Get("/documents/{id}/retention", r.chainRetention)

	// ASiC-E assembly (embedded gmb-lib/go-asice).
	v1.Post("/documents/{id}/complete", r.complete)
	v1.Post("/documents/assemble", r.assemble)
	v1.Post("/documents/{id}/add-signature", r.addSignature)

	// The multi-document bundle: 2+ loose sources become ONE unsigned container
	// (the chain root; sources absorbed), editable while unsigned, with
	// extract-an-original on demand.
	v1.Post("/documents/bundle", r.bundle)
	v1.Post("/documents/{id}/rebundle", r.rebundle)
	v1.Get("/documents/{id}/data-objects/{name}", r.extractObject)

	// Store a finished, opaque signed document (e.g. a PDF signed in place) against
	// its chain — no assembly, integrity is the embedded signature.
	v1.Post("/documents/{id}/signed", r.storeSigned)
	v1.Post("/documents/{id}/archived", r.storeArchived)
	v1.Get("/history", r.listHistory)
	v1.Delete("/history/{chainRoot}", r.deleteHistory)

	return nil
}

// requireScope enforces a documents:<level> scope; on denial it emits the
// platform authz.denied security event and returns false.
//
//	read — metadata / content / digest / list
//	write — ingest / complete / assemble / add-signature / signed / delete
//	durable — storing a document no clock will remove. Its own level because
//	  every uploader holds `write`, and a compromised token that also held this
//	  one by default could create storage nothing ever cleans up.
func (r *router) requireScope(ctx *azugo.Context, level string) bool {
	if ctx.User().HasScopeLevel("documents", level) {
		return true
	}

	r.Audit().Denied(ctx, callerID(ctx), "documents:"+level)
	ctx.Error(pkerrors.NewProblem("err:document:forbidden",
		pkerrors.WithDetail("missing documents:"+level+" scope")))

	return false
}

// callerID is the authenticated identity the token carries (a service id, or
// the person `sub` a delegated token acts for). It is the document `owner` on ingest.
func callerID(ctx *azugo.Context) string { return ctx.User().ID() }

// productPrincipal is the owner a product-owned document carries: the product
// this credential belongs to, and the organisation the token names. Both come from
// the token — the client id it authenticated as, and its tenant claim — and never
// from the request, so no caller can name an owner it is not.
//
// It returns "" when this client owns no documents or the token names no
// organisation. Either way there is no owner to record, and the upload is refused
// rather than stored under a guess.
func (r *router) productPrincipal(ctx *azugo.Context) (principal, tenant string) {
	tenant = ctx.User().ClaimValue(claims.ClaimTenant)
	product := r.Config().ProductFor(ctx.User().ID())
	if product == "" || tenant == "" {
		return "", tenant
	}

	return "product:" + product + ":" + tenant, tenant
}

// reqCaller is the authenticated principal for an ACL-authorized read: the
// subject plus the eIDAS serial claim (present on a named person's token, and
// carried through on-behalf delegation — so a co-signer matches an invited slot),
// plus the product principal when the credential belongs to one. A caller may be
// both: a person's delegated token that happens to reach a product-owned document
// matches on neither, which is the point.
func (r *router) reqCaller(ctx *azugo.Context) store.Caller {
	// The serial is reduced to the one spelling this platform compares before it is
	// matched against a chain grant. The claim is already canonical when it comes
	// from this platform's own identity service; reducing it again costs nothing and
	// covers the case that matters — a co-signer who is on the chain and is told the
	// document does not exist, which is what a miss looks like from outside.
	serial := ctx.User().ClaimValue("serial_number")
	if serial != "" {
		serial = identitycode.Key(serial)
	}

	principal, tenant := r.productPrincipal(ctx)

	return store.Caller{
		Sub:     ctx.User().ID(),
		Serial:  serial,
		Product: principal,
		Tenant:  tenant,
	}
}

// writeStoreErr maps store/domain errors to the right HTTP status.
func (r *router) writeStoreErr(ctx *azugo.Context, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		ctx.Error(pkerrors.NewProblem("err:document:notFound",
			pkerrors.WithTitle("Document not found"),
			pkerrors.WithDetail("document not found")))
	case errors.Is(err, store.ErrLegalHold):
		ctx.Error(pkerrors.NewProblem("err:document:legalHold",
			pkerrors.WithStatus(fasthttp.StatusConflict),
			pkerrors.WithTitle("Document under legal hold"),
			pkerrors.WithDetail("document is under legal hold")))
	case errors.Is(err, store.ErrChainAdvanced):
		ctx.Error(pkerrors.NewProblem("err:document:chainAdvanced",
			pkerrors.WithStatus(fasthttp.StatusConflict),
			pkerrors.WithTitle("Document changed since signing began"),
			pkerrors.WithDetail("the document changed since signing began; reload the latest and retry")))
	case errors.Is(err, store.ErrNotBundleable):
		ctx.Error(pkerrors.NewProblem("err:document:notBundleable",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithTitle("Document not bundleable"),
			pkerrors.WithDetail("only an unsigned source or an already-signed file (PDF or ASiC-E) can be bundled, and only an unsigned bundle can be rebundled")))
	case errors.Is(err, documents.ErrGone):
		ctx.Error(pkerrors.NewProblem("err:document:gone",
			pkerrors.WithTitle("Document no longer available"),
			pkerrors.WithDetail("document bytes are no longer available (purged on TTL/delete)")))
	default:
		// Unmapped failure: log the cause (kept off the wire — it may name
		// internals) and return the fixed internal problem; the renderer records
		// the correlated error line.
		ctx.Log().Error("unmapped store error", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:document:internal"))
	}
}
