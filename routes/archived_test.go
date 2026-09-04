package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/signbyte/document-store/routes/response"
)

// The archived form is opaque to the store — any bytes stand in for the
// timestamped result (integrity lives in the embedded archive timestamp).
var fakeArchived = []byte("%PDF-1.7\nfake archived (B-LTA) bytes\n%%EOF")

// storeArchived refreshes a signed head IN PLACE: same document id, new bytes,
// no extra row — the chain still lists as one row, now the archived form.
func TestStoreArchivedReplacesSignedPdfInPlace(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	srcID := ingestDoc(t, app, "owner-1", "contract.pdf", samplePDF()).ID

	// Sign it (stores the kind "pdf" head).
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

	// Archive-timestamp it: the head is replaced in place.
	body, ct = buildMultipart(t, nil, []fileEntry{{"archived", "contract.pdf", fakeArchived}})
	resp, err = tc.Post("/api/v1/documents/"+signed.SignedDocumentID+"/archived", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out response.Archived
	decode(t, resp, &out)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(out.ID, signed.SignedDocumentID)) // same id — replaced, not re-created
	qt.Check(t, qt.Equals(out.Size, int64(len(fakeArchived))))

	// The bytes are the archived form now.
	resp, err = tc.Get("/api/v1/documents/"+out.ID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	got := bodyOf(t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(string(got), string(fakeArchived)))

	// The archive is now a DURABLE fact: the head is upgraded to long-term
	// preservation (B-LTA), so the projection carries it after a reload — the
	// activity trail can show "archived" without relying on session state.
	resp, err = tc.Get("/api/v1/documents/"+out.ID,
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	var meta response.Document
	decode(t, resp, &meta)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(meta.PreservationClass, "preservation"))
}

// A plain source has nothing to archive — 422, never a silent replace.
func TestStoreArchivedRejectsSource(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	srcID := ingestDoc(t, app, "owner-1", "notes.txt", []byte("plain source")).ID

	body, ct := buildMultipart(t, nil, []fileEntry{{"archived", "notes.txt", fakeArchived}})
	resp, err := tc.Post("/api/v1/documents/"+srcID+"/archived", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
}

// A caller off the chain ACL cannot archive (indistinguishable from absent).
func TestStoreArchivedACLScoped(t *testing.T) {
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
	var signed response.SignedDocument
	decode(t, resp, &signed)
	fasthttp.ReleaseResponse(resp)

	body, ct = buildMultipart(t, nil, []fileEntry{{"archived", "contract.pdf", fakeArchived}})
	resp, err = tc.Post("/api/v1/documents/"+signed.SignedDocumentID+"/archived", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "mallory"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)
}

// The archive act belongs to every party on the chain's access list, not only the
// uploader: a co-signer who archives the shared container gets the same answer as
// the owner, and the upgrade is recorded on the row for both to read. The swap and
// the recorded fact are one write — a co-signer's click must never replace the
// bytes and then report a failure.
func TestStoreArchivedByCoSignerRecordsPreservation(t *testing.T) {
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
	var signed response.SignedDocument
	decode(t, resp, &signed)
	fasthttp.ReleaseResponse(resp)

	// The workflow service grants the co-signer's serial on the chain at send.
	gr, err := tc.Post("/api/v1/documents/"+srcID+"/acl", []byte(`{"serial":"`+invitedSerial+`"}`),
		tc.WithHeader("Content-Type", "application/json"),
		tc.WithHeader("X-Test-Scopes", scopeGrant),
		tc.WithHeader("X-Test-Sub", "svc:envelope"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(gr.StatusCode(), fasthttp.StatusNoContent))
	fasthttp.ReleaseResponse(gr)

	// The co-signer (a different sub, on the list by serial) archives the head.
	body, ct = buildMultipart(t, nil, []fileEntry{{"archived", "contract.pdf", fakeArchived}})
	resp, err = tc.Post("/api/v1/documents/"+signed.SignedDocumentID+"/archived", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "cosigner-x"),
		tc.WithHeader("X-Test-Serial", invitedSerial))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out response.Archived
	decode(t, resp, &out)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(out.ID, signed.SignedDocumentID))
	qt.Check(t, qt.Equals(out.Size, int64(len(fakeArchived))))

	// The fact is on the row: the owner reads it …
	resp, err = tc.Get("/api/v1/documents/"+out.ID,
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	var asOwner response.Document
	decode(t, resp, &asOwner)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(asOwner.PreservationClass, "preservation"))

	// … and so does the co-signer who applied it.
	resp, err = tc.Get("/api/v1/documents/"+out.ID,
		tc.WithHeader("X-Test-Scopes", scopeRead),
		tc.WithHeader("X-Test-Sub", "cosigner-x"),
		tc.WithHeader("X-Test-Serial", invitedSerial))
	qt.Assert(t, qt.IsNil(err))
	var asCoSigner response.Document
	decode(t, resp, &asCoSigner)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(asCoSigner.PreservationClass, "preservation"))
}
