package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/signbyte/document-store/routes/response"
)

// A finished signed document is opaque to the store — any bytes stand in for a
// real signed PDF (the route never parses it; integrity is the embedded signature).
var fakeSignedPDF = []byte("%PDF-1.7\nfake signed pdf bytes\n%%EOF")

// storeSigned persists a finished signed document (e.g. a PDF signed in place) as
// kind "pdf" against its chain, retrievable byte-for-byte.
func TestStoreSignedStoresPdf(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	srcID := ingestDoc(t, app, "owner-1", "contract.pdf", samplePDF()).ID

	body, ct := buildMultipart(t, map[string]string{"mime": "application/pdf"},
		[]fileEntry{{"signed", "contract.pdf", fakeSignedPDF}})
	resp, err := tc.Post("/api/v1/documents/"+srcID+"/signed", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var out response.SignedDocument
	decode(t, resp, &out)
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(out.SignedDocumentID != ""))
	qt.Check(t, qt.Equals(out.Mime, "application/pdf"))
	qt.Check(t, qt.Equals(out.Size, int64(len(fakeSignedPDF))))

	// Stored as kind "pdf" (the signed artifact form).
	resp, err = tc.Get("/api/v1/documents/"+out.SignedDocumentID,
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var meta response.Document
	decode(t, resp, &meta)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(meta.Kind, "pdf"))

	// Retrievable byte-for-byte.
	resp, err = tc.Get("/api/v1/documents/"+out.SignedDocumentID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	got := bodyOf(t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(string(got), string(fakeSignedPDF)))
}

// A second signed PDF for the same chain is a PAdES CO-SIGNATURE: it keep-latest
// SUPERSEDES the current signed PDF in place (one live signed PDF per chain), rather
// than creating a second head or 409-ing. The caller signs on top of the current head
// (server-resolved via /head), so the co-signed bytes descend from it and win in place
// — the head keeps its id, its bytes become the co-signed ones (keep-latest, in place).
func TestStoreSignedSecondSignSupersedesHead(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	srcID := ingestDoc(t, app, "owner-1", "contract.pdf", samplePDF()).ID

	firstBody, ct := buildMultipart(t, map[string]string{"mime": "application/pdf"},
		[]fileEntry{{"signed", "contract.pdf", fakeSignedPDF}})
	first, err := tc.Post("/api/v1/documents/"+srcID+"/signed", firstBody,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(first.StatusCode(), fasthttp.StatusCreated))
	var firstOut response.SignedDocument
	decode(t, first, &firstOut)
	fasthttp.ReleaseResponse(first)

	// The co-signature: distinct bytes carrying both signatures. Posted against the
	// chain — the store re-resolves the head to supersede it in place.
	coSigned := []byte("%PDF-1.7\nfake co-signed pdf (two signatures)\n%%EOF")
	secondBody, ct := buildMultipart(t, map[string]string{"mime": "application/pdf"},
		[]fileEntry{{"signed", "contract.pdf", coSigned}})
	second, err := tc.Post("/api/v1/documents/"+srcID+"/signed", secondBody,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(second.StatusCode(), fasthttp.StatusCreated))
	var secondOut response.SignedDocument
	decode(t, second, &secondOut)
	fasthttp.ReleaseResponse(second)

	// Keep-latest, in place: the head keeps its id, bytes are now the co-signed ones.
	qt.Check(t, qt.Equals(secondOut.SignedDocumentID, firstOut.SignedDocumentID))

	// The chain resolves to exactly one live head, carrying the superseding bytes.
	headResp, err := tc.Get("/api/v1/documents/"+srcID+"/head",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(headResp.StatusCode(), fasthttp.StatusOK))
	var head response.ChainHead
	decode(t, headResp, &head)
	fasthttp.ReleaseResponse(headResp)
	qt.Check(t, qt.Equals(head.Kind, "pdf"))
	qt.Check(t, qt.Equals(head.ID, firstOut.SignedDocumentID))

	content, err := tc.Get("/api/v1/documents/"+head.ID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(content.StatusCode(), fasthttp.StatusOK))
	got := bodyOf(t, content)
	fasthttp.ReleaseResponse(content)
	qt.Check(t, qt.Equals(string(got), string(coSigned)))
}

// The chain-head route resolves a chain's current live signed head by root id: an
// empty id before any signature (the caller then signs the source), the signed PDF
// head after a PAdES sign. This is the server-authoritative head a co-signer signs.
func TestChainHeadResolvesCurrentSignedPdf(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	srcID := ingestDoc(t, app, "owner-1", "contract.pdf", samplePDF()).ID

	// No signed head yet → empty id (200): the chain is still just its source.
	resp, err := tc.Get("/api/v1/documents/"+srcID+"/head",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var none response.ChainHead
	decode(t, resp, &none)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(none.ID, ""))

	// Sign it → the head is the signed PDF.
	body, ct := buildMultipart(t, map[string]string{"mime": "application/pdf"},
		[]fileEntry{{"signed", "contract.pdf", fakeSignedPDF}})
	signed, err := tc.Post("/api/v1/documents/"+srcID+"/signed", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(signed.StatusCode(), fasthttp.StatusCreated))
	var out response.SignedDocument
	decode(t, signed, &out)
	fasthttp.ReleaseResponse(signed)

	resp, err = tc.Get("/api/v1/documents/"+srcID+"/head",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var head response.ChainHead
	decode(t, resp, &head)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(head.Kind, "pdf"))
	qt.Check(t, qt.Equals(head.ID, out.SignedDocumentID))
}

// An UPLOADED already-signed PDF is its own chain root AND its own head: signing
// it supersedes that root in place (keep-latest) — the chain keeps exactly one
// live signed row, never a signed child piling up next to a live signed root.
func TestStoreSignedOnPresignedUploadSupersedesRootInPlace(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	// Upload a PDF that already carries a signature — ingested as a signed root.
	up := postUpload(t, app, "owner-1", "signed.pdf", signedSamplePDF())
	qt.Assert(t, qt.Equals(up.StatusCode(), fasthttp.StatusCreated))
	var uploaded response.Ingested
	decode(t, up, &uploaded)
	fasthttp.ReleaseResponse(up)

	// The pre-signed root resolves as the chain's current head (itself).
	headResp, err := tc.Get("/api/v1/documents/"+uploaded.ID+"/head",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(headResp.StatusCode(), fasthttp.StatusOK))
	var head response.ChainHead
	decode(t, headResp, &head)
	fasthttp.ReleaseResponse(headResp)
	qt.Check(t, qt.Equals(head.ID, uploaded.ID))
	qt.Check(t, qt.Equals(head.Kind, "pdf"))

	// Sign it: the result carries the prior signature embedded and supersedes the
	// root in place — same id, new bytes; no second live signed row for the chain.
	coSigned := []byte("%PDF-1.7\nfake re-signed pdf (upload's signature + a new one)\n%%EOF")
	body, ct := buildMultipart(t, map[string]string{"mime": "application/pdf"},
		[]fileEntry{{"signed", "signed.pdf", coSigned}})
	resp, err := tc.Post("/api/v1/documents/"+uploaded.ID+"/signed", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	var out response.SignedDocument
	decode(t, resp, &out)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(out.SignedDocumentID, uploaded.ID))

	// Still one head — the same row — now carrying the superseding bytes.
	meta := getMeta(t, app, "owner-1", uploaded.ID)
	qt.Check(t, qt.Equals(meta.Kind, "pdf"))
	qt.Check(t, qt.Equals(meta.Status, "signed"))

	content, err := tc.Get("/api/v1/documents/"+uploaded.ID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(content.StatusCode(), fasthttp.StatusOK))
	got := bodyOf(t, content)
	fasthttp.ReleaseResponse(content)
	qt.Check(t, qt.Equals(string(got), string(coSigned)))

	headResp, err = tc.Get("/api/v1/documents/"+uploaded.ID+"/head",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(headResp.StatusCode(), fasthttp.StatusOK))
	decode(t, headResp, &head)
	fasthttp.ReleaseResponse(headResp)
	qt.Check(t, qt.Equals(head.ID, uploaded.ID))
}

// A missing `signed` file part is a 400.
func TestStoreSignedRejectsMissingFile(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	srcID := ingestDoc(t, app, "owner-1", "contract.pdf", samplePDF()).ID

	body, ct := buildMultipart(t, map[string]string{"mime": "application/pdf"}, nil)
	resp, err := tc.Post("/api/v1/documents/"+srcID+"/signed", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)
}
