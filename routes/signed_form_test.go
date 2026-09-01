package routes

import (
	"bytes"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/gmb-lib/go-asice"

	"github.com/signbyte/document-store/routes/response"
)

// The signed-PDF store records the artifact as kind "pdf" and everything downstream
// branches on that field, so the bytes must actually BE PDF content. A signing
// service answering with some other artifact is refused: nothing is stored, the
// chain is left as it was, and a high-severity security event records the fault.
//
// Only the form is checked, never the signature — validity stays the provider's
// answer. The three cases below are the three ways the form can be wrong: another
// legitimate signed form (a container), a plain archive, and bytes that are no
// document at all. Per the ruling there is no split between them: any non-PDF answer
// to a PDF store is an error.
func TestStoreSignedRefusesNonPdfForm(t *testing.T) {
	container, err := asice.BuildContainer(sampleDocs(),
		[]asice.File{{Name: "sig.xml", Data: makeXAdES(t, "WRONGFORM", sampleDocs())}}, nil)
	qt.Assert(t, qt.IsNil(err))

	cases := []struct {
		name     string
		data     []byte
		observed string
	}{
		{"an ASiC-E container where a PDF was asked", container, "asice"},
		{"a plain zip", append([]byte("PK\x03\x04"), bytes.Repeat([]byte("z"), 64)...), "zip"},
		{"bytes that are no document at all", []byte("<html>502 Bad Gateway</html>"), "other"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			app := testApp(t)
			app.Start(t)
			defer app.Stop()
			tc := app.TestClient()

			srcID := ingestDoc(t, app, "owner-1", "contract.pdf", samplePDF()).ID

			body, ct := buildMultipart(t, map[string]string{"mime": "application/pdf"},
				[]fileEntry{{"signed", "contract.pdf", tt.data}})
			resp, err := tc.Post("/api/v1/documents/"+srcID+"/signed", body,
				tc.WithHeader("Content-Type", ct),
				tc.WithHeader("X-Test-Scopes", scopeWrite),
				tc.WithHeader("X-Test-Sub", "owner-1"))
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))

			// The error names the code and the form that actually arrived — the
			// detail is what tells an operator which side misbehaved.
			gotBody := bodyOf(t, resp)
			fasthttp.ReleaseResponse(resp)
			qt.Check(t, qt.IsTrue(bytes.Contains(gotBody, []byte("err:document:signedFormMismatch"))))
			qt.Check(t, qt.IsTrue(bytes.Contains(gotBody, []byte(tt.observed))))

			// The chain is untouched: no signed head exists, so the person's
			// document is exactly as it was before the refused store.
			headResp, err := tc.Get("/api/v1/documents/"+srcID+"/head",
				tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(headResp.StatusCode(), fasthttp.StatusOK))
			var head response.ChainHead
			decode(t, headResp, &head)
			fasthttp.ReleaseResponse(headResp)
			qt.Check(t, qt.Equals(head.ID, ""))
		})
	}
}

// The counterpart, so the check cannot pass by refusing everything: a PDF carrying a
// signature is stored, and so is one whose signature our best-effort probe cannot
// find. The probe is inconclusive by its own contract in this mode, so a signature it
// misses must never cost the person a real signature.
func TestStoreSignedAcceptsPdfWhateverTheProbeSees(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"a signed PDF", signedSamplePDF()},
		{"PDF content our signature probe finds nothing in", fakeSignedPDF},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			app := testApp(t)
			app.Start(t)
			defer app.Stop()
			tc := app.TestClient()

			srcID := ingestDoc(t, app, "owner-1", "contract.pdf", samplePDF()).ID

			body, ct := buildMultipart(t, map[string]string{"mime": "application/pdf"},
				[]fileEntry{{"signed", "contract.pdf", tt.data}})
			resp, err := tc.Post("/api/v1/documents/"+srcID+"/signed", body,
				tc.WithHeader("Content-Type", ct),
				tc.WithHeader("X-Test-Scopes", scopeWrite),
				tc.WithHeader("X-Test-Sub", "owner-1"))
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
			fasthttp.ReleaseResponse(resp)
		})
	}
}
