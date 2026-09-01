package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

const scopeGrant = "documents:grant"

// A co-signer cannot read the owner's document until the workflow service grants
// their eIDAS serial; after the grant they read the shared document, and the
// match is normalization-aware (case/whitespace). A different serial still 404s.
func TestGrantACLThenSerialCanRead(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	id := ingestDoc(t, app, "owner-1", "deal.txt", []byte("co-sign me")).ID

	// Before the grant: the co-signer (different sub, with a serial) is hidden.
	pre, err := tc.Get("/api/v1/documents/"+id,
		tc.WithHeader("X-Test-Scopes", scopeRead),
		tc.WithHeader("X-Test-Sub", "cosigner-x"),
		tc.WithHeader("X-Test-Serial", invitedSerial))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(pre.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(pre)

	// The workflow service grants the serial (note the different case/spacing).
	gr, err := tc.Post("/api/v1/documents/"+id+"/acl", grantBodyLowerSpaced(invitedSerial),
		tc.WithHeader("Content-Type", "application/json"),
		tc.WithHeader("X-Test-Scopes", scopeGrant),
		tc.WithHeader("X-Test-Sub", "svc:envelope"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(gr.StatusCode(), fasthttp.StatusNoContent))
	fasthttp.ReleaseResponse(gr)

	// After the grant: the co-signer reads the shared document.
	got, err := tc.Get("/api/v1/documents/"+id,
		tc.WithHeader("X-Test-Scopes", scopeRead),
		tc.WithHeader("X-Test-Sub", "cosigner-x"),
		tc.WithHeader("X-Test-Serial", invitedSerial))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(got)

	// A different serial is still hidden (fail-closed).
	other, err := tc.Get("/api/v1/documents/"+id,
		tc.WithHeader("X-Test-Scopes", scopeRead),
		tc.WithHeader("X-Test-Sub", "cosigner-y"),
		tc.WithHeader("X-Test-Serial", strangerSerial))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(other.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(other)
}

// The grant route is bounded to the documents:grant scope (held only by the
// workflow service) — a plain write-scoped user cannot self-grant.
func TestGrantACLRequiresGrantScope(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	id := ingestDoc(t, app, "owner-1", "deal.txt", []byte("x")).ID

	resp, err := tc.Post("/api/v1/documents/"+id+"/acl", []byte(`{"serial":"PNOLV-1"}`),
		tc.WithHeader("Content-Type", "application/json"),
		tc.WithHeader("X-Test-Scopes", scopeWrite), // not documents:grant
		tc.WithHeader("X-Test-Sub", "mallory"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	fasthttp.ReleaseResponse(resp)
}

// Grant input validation: missing serial → 400, unknown document → 404, an
// out-of-set right → 422.
func TestGrantACLValidation(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	id := ingestDoc(t, app, "owner-1", "deal.txt", []byte("x")).ID

	grantHeaders := func(body string, path string) *fasthttp.Response {
		resp, err := tc.Post(path, []byte(body),
			tc.WithHeader("Content-Type", "application/json"),
			tc.WithHeader("X-Test-Scopes", scopeGrant),
			tc.WithHeader("X-Test-Sub", "svc:envelope"))
		qt.Assert(t, qt.IsNil(err))

		return resp
	}

	missing := grantHeaders(`{}`, "/api/v1/documents/"+id+"/acl")
	qt.Check(t, qt.Equals(missing.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(missing)

	unknown := grantHeaders(`{"serial":"PNOLV-1"}`, "/api/v1/documents/no-such-id/acl")
	qt.Check(t, qt.Equals(unknown.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(unknown)

	badRight := grantHeaders(`{"serial":"PNOLV-1","rights":["delete"]}`, "/api/v1/documents/"+id+"/acl")
	qt.Check(t, qt.Equals(badRight.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(badRight)
}
