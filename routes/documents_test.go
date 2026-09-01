package routes

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/signbyte/document-store/routes/response"
)

// ingestDoc uploads a document as owner and returns its id + the response.
func ingestDoc(t *testing.T, app *azugo.TestApp, owner, filename string, data []byte) response.Ingested {
	t.Helper()
	tc := app.TestClient()
	body, ct := buildMultipart(t, map[string]string{"mime": "text/plain"}, []fileEntry{{"file", filename, data}})
	resp, err := tc.Post("/api/v1/documents", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", owner))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var out response.Ingested
	decode(t, resp, &out)

	return out
}

func TestIngestThenDigestContentDelete(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	data := []byte("hello eIDAS")
	ing := ingestDoc(t, app, "owner-1", "hello.txt", data)

	// B1: the returned content_hash is base64(SHA-256(bytes)).
	sum := sha256.Sum256(data)
	qt.Check(t, qt.Equals(ing.ContentHash, base64.StdEncoding.EncodeToString(sum[:])))
	qt.Check(t, qt.IsTrue(ing.ID != ""))

	// Digest endpoint returns the same canonical hash (what the Orchestrator fetches).
	resp, err := tc.Get("/api/v1/documents/"+ing.ID+"/digest",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var dg response.Digest
	decode(t, resp, &dg)
	qt.Check(t, qt.Equals(dg.ContentHash, ing.ContentHash))
	qt.Check(t, qt.Equals(dg.Algorithm, "SHA-256"))

	// Content endpoint round-trips the decrypted bytes.
	resp, err = tc.Get("/api/v1/documents/"+ing.ID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	qt.Check(t, qt.Equals(string(bodyOf(t, resp)), string(data)))

	// Delete → 204. The sole holder removing access empties the ACL, so the
	// document then leaves their view entirely (404, not 410-Gone).
	resp, err = tc.Delete("/api/v1/documents/"+ing.ID,
		tc.WithHeader("X-Test-Scopes", scopeWrite), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNoContent))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.Get("/api/v1/documents/"+ing.ID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)
}

// TestDownloadHeadersHardenedAgainstScriptVectors pins the script-vector
// defence: a stored file re-served to a browser must never carry a
// browser-active Content-Type, and must always carry nosniff + attachment,
// regardless of what mime the uploader claimed.
func TestDownloadHeadersHardenedAgainstScriptVectors(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	data := []byte("<script>alert(document.domain)</script>")
	body, ct := buildMultipart(t, map[string]string{"mime": "text/html"}, []fileEntry{{"file", "evil.html", data}})
	resp, err := tc.Post("/api/v1/documents", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	var ing response.Ingested
	decode(t, resp, &ing)
	qt.Check(t, qt.Equals(ing.Mime, "text/html")) // stored verbatim; only the DOWNLOAD response is hardened

	resp, err = tc.Get("/api/v1/documents/"+ing.ID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("X-Content-Type-Options")), "nosniff"))
	qt.Check(t, qt.Equals(string(resp.Header.ContentType()), "application/octet-stream"))
	qt.Check(t, qt.StringContains(string(resp.Header.Peek("Content-Disposition")), "attachment"))
	qt.Check(t, qt.Equals(string(bodyOf(t, resp)), string(data))) // bytes unaltered, only headers hardened
}

func TestNoIDORAcrossOwners(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	ing := ingestDoc(t, app, "owner-1", "secret.txt", []byte("classified"))

	// A second owner gets 404 (not_found), never the row.
	resp, err := tc.Get("/api/v1/documents/"+ing.ID,
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-2"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)
}

func TestIngestMissingFile(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	body, ct := buildMultipart(t, map[string]string{"mime": "text/plain"}, nil)
	resp, err := tc.Post("/api/v1/documents", body,
		tc.WithHeader("Content-Type", ct), tc.WithHeader("X-Test-Scopes", scopeWrite))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)
}

func TestUnauthorizedAndForbidden(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	// No scopes header → 401 (stub auth rejects).
	resp, err := tc.Get("/api/v1/documents", tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)

	// Authenticated but wrong scope (read-only) on a write endpoint → 403.
	body, ct := buildMultipart(t, nil, []fileEntry{{"file", "x.txt", []byte("x")}})
	resp, err = tc.Post("/api/v1/documents", body,
		tc.WithHeader("Content-Type", ct), tc.WithHeader("X-Test-Scopes", scopeRead))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	fasthttp.ReleaseResponse(resp)
}
