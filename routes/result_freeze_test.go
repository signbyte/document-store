package routes

import (
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/signbyte/document-store/routes/response"
)

// The co-sign download freeze over the routes: while frozen, the chain's signed
// artifact refuses content reads (typed 409) unless the caller is a declared
// platform conduit; the SOURCE stays readable throughout; lifting the freeze
// serves again. The freeze flag rides the chains listing so a dashboard can
// render the row as in-signing.
func TestResultFreezeLocksSignedArtifactUntilLifted(t *testing.T) {
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

	// Freeze (workflow authority = the grant scope); resolving from the SOURCE id
	// must land the flag on the chain root all the same.
	resp, err = tc.Post("/api/v1/documents/"+srcID+"/result-freeze", []byte(`{"frozen":true}`),
		tc.WithHeader("Content-Type", "application/json"),
		tc.WithHeader("X-Test-Scopes", scopeGrant),
		tc.WithHeader("X-Test-Sub", "svc:envelope"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNoContent))
	fasthttp.ReleaseResponse(resp)

	// A read scope must NOT be able to freeze/unfreeze.
	resp, err = tc.Post("/api/v1/documents/"+srcID+"/result-freeze", []byte(`{"frozen":false}`),
		tc.WithHeader("Content-Type", "application/json"),
		tc.WithHeader("X-Test-Scopes", scopeRead),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	fasthttp.ReleaseResponse(resp)

	// The signed artifact refuses a plain content read with the typed 409.
	resp, err = tc.Get("/api/v1/documents/"+signed.SignedDocumentID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	qt.Assert(t, qt.IsTrue(strings.Contains(string(bodyOf(t, resp)), "resultFrozen")))

	// The platform conduits keep working (signing merge/validate/archive, render).
	for _, conduit := range []string{"signing", "render"} {
		resp, err = tc.Get("/api/v1/documents/"+signed.SignedDocumentID+"/content?conduit="+conduit,
			tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
		fasthttp.ReleaseResponse(resp)
	}

	// An unknown declaration fails CLOSED.
	resp, err = tc.Get("/api/v1/documents/"+signed.SignedDocumentID+"/content?conduit=whatever",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusConflict))
	fasthttp.ReleaseResponse(resp)

	// The SOURCE stays readable for review throughout the freeze.
	resp, err = tc.Get("/api/v1/documents/"+srcID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)

	// The chains listing carries the flag so a dashboard renders "in signing".
	resp, err = tc.Get("/api/v1/documents?view=chains",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var chains response.ChainList
	decode(t, resp, &chains)
	qt.Assert(t, qt.Equals(len(chains.Chains), 1))
	qt.Assert(t, qt.IsTrue(chains.Chains[0].ResultFrozen))

	// Lift the freeze (the workflow's terminal transition) — the artifact serves.
	resp, err = tc.Post("/api/v1/documents/"+srcID+"/result-freeze", []byte(`{"frozen":false}`),
		tc.WithHeader("Content-Type", "application/json"),
		tc.WithHeader("X-Test-Scopes", scopeGrant),
		tc.WithHeader("X-Test-Sub", "svc:envelope"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNoContent))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.Get("/api/v1/documents/"+signed.SignedDocumentID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

// The freeze also gates the extract-an-inner-original door: while frozen, an
// undeclared extract is refused (typed 409); a declared purpose keeps working
// (render for preview, review for a user reviewing/re-staging an original,
// signing for the orchestrator); an unknown declaration fails closed; lifting
// the freeze serves again. An inner original is only ever an input — the signed
// container is never handed out this way — but the freeze rule matches a content
// read.
func TestResultFreezeGatesInnerExtract(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	docs := sampleDocs()
	containerID := assembleContainer(t, app, "owner-1", docs, "FIRST")
	inner := docs[0].Name

	extract := func(query string) int {
		resp, err := tc.Get("/api/v1/documents/"+containerID+"/data-objects/"+inner+query,
			tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
		qt.Assert(t, qt.IsNil(err))
		code := resp.StatusCode()
		fasthttp.ReleaseResponse(resp)

		return code
	}

	setFreeze := func(frozen string) {
		resp, err := tc.Post("/api/v1/documents/"+containerID+"/result-freeze", []byte(`{"frozen":`+frozen+`}`),
			tc.WithHeader("Content-Type", "application/json"),
			tc.WithHeader("X-Test-Scopes", scopeGrant),
			tc.WithHeader("X-Test-Sub", "svc:envelope"))
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNoContent))
		fasthttp.ReleaseResponse(resp)
	}

	// Not frozen: a plain extract works.
	qt.Assert(t, qt.Equals(extract(""), fasthttp.StatusOK))

	// Frozen: an undeclared extract is refused with the typed 409.
	setFreeze("true")
	qt.Assert(t, qt.Equals(extract(""), fasthttp.StatusConflict))

	// The declared purposes keep working.
	for _, conduit := range []string{"render", "review", "signing"} {
		qt.Assert(t, qt.Equals(extract("?conduit="+conduit), fasthttp.StatusOK))
	}

	// An unknown declaration fails CLOSED.
	qt.Assert(t, qt.Equals(extract("?conduit=whatever"), fasthttp.StatusConflict))

	// Lifting the freeze serves again.
	setFreeze("false")
	qt.Assert(t, qt.Equals(extract(""), fasthttp.StatusOK))
}
