package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/signbyte/document-store/routes/response"
)

// The single-chain read answers with the chain's live head from ANY id in the
// chain, and states the same signed-ness facts as the listing. It exists so a
// document screen never has to find its document inside a listing — a listing
// filters and pages, and a chain's own facts must not depend on that.
func TestGetChainResolvesHeadFromEitherID(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	// A chain with a source root and a signed artifact head.
	srcID := ingestDoc(t, app, "owner-1", "contract.pdf", samplePDF()).ID
	body, ct := buildMultipart(t, map[string]string{"mime": "application/pdf"},
		[]fileEntry{{"signed", "contract.pdf", fakeSignedPDF}})
	resp, err := tc.Post("/api/v1/documents/"+srcID+"/signed", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	var signed response.SignedDocument
	decode(t, resp, &signed)
	fasthttp.ReleaseResponse(resp)

	// By the ROOT id: the head is the signed artifact, and the chain reads as
	// signed here — the facts a completed signing's screen states.
	resp, err = tc.Get("/api/v1/documents/"+srcID+"/chain",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var byRoot response.Chain
	decode(t, resp, &byRoot)
	qt.Assert(t, qt.Equals(byRoot.ID, signed.SignedDocumentID))
	qt.Assert(t, qt.Equals(byRoot.ChainRootID, srcID))
	qt.Assert(t, qt.IsTrue(byRoot.PlatformSigned))
	qt.Assert(t, qt.IsTrue(byRoot.HasSignatures))

	// By the HEAD id: the same chain, not a different answer.
	resp, err = tc.Get("/api/v1/documents/"+signed.SignedDocumentID+"/chain",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var byHead response.Chain
	decode(t, resp, &byHead)
	qt.Assert(t, qt.Equals(byHead.ID, byRoot.ID))
	qt.Assert(t, qt.Equals(byHead.ChainRootID, byRoot.ChainRootID))
	qt.Assert(t, qt.Equals(byHead.PlatformSigned, byRoot.PlatformSigned))
}

// A caller who is not on the chain ACL is answered exactly like a caller asking
// for an id that does not exist, and an unknown id is a 404 rather than an empty
// success a screen would render as an unsigned draft.
func TestGetChainHidesOtherPeoplesChains(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	id := ingestDoc(t, app, "owner-1", "contract.pdf", samplePDF()).ID

	resp, err := tc.Get("/api/v1/documents/"+id+"/chain",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "someone-else"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.Get("/api/v1/documents/no-such-id/chain",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)

	// Reading a chain is authenticated like every other document read.
	resp, err = tc.Get("/api/v1/documents/"+id+"/chain",
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}
