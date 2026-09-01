package routes

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/signbyte/document-store/routes/response"
)

// samplePDF builds a minimal, valid, unsigned single-page PDF with correct
// cross-reference offsets, so it parses without relying on a repair path.
func samplePDF() []byte {
	var buf bytes.Buffer
	offsets := make([]int, 4)

	buf.WriteString("%PDF-1.4\n")
	obj := func(n int, body string) {
		offsets[n] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", n, body)
	}

	obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>")

	xref := buf.Len()
	buf.WriteString("xref\n0 4\n")
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)

	return buf.Bytes()
}

// signedSamplePDF extends samplePDF with an incremental update carrying an
// INVISIBLE signature (a /Type /Sig dictionary, an AcroForm signature field
// with a zero-rect widget, a chained second xref) — the shape an external
// signing tool produces. Structural only; presence is what detection reads.
func signedSamplePDF() []byte {
	base := samplePDF()
	prevXref := bytes.LastIndex(base, []byte("xref"))

	var b bytes.Buffer
	b.Write(base)
	offsets := map[int]int{}
	obj := func(num int, body string) {
		offsets[num] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", num, body)
	}
	obj(4, "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached"+
		" /ByteRange [0 1024 2048 512] /Contents <3082000a0500> >>")
	obj(5, "<< /FT /Sig /T (Signature1) /V 4 0 R /Type /Annot /Subtype /Widget"+
		" /Rect [0 0 0 0] /F 132 /P 3 0 R >>")
	obj(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] /SigFlags 3 >> >>")

	xrefAt := b.Len()
	fmt.Fprintf(&b, "xref\n0 1\n0000000000 65535 f \n1 1\n%010d 00000 n \n4 2\n%010d 00000 n \n%010d 00000 n \n",
		offsets[1], offsets[4], offsets[5])
	fmt.Fprintf(&b, "trailer\n<< /Size 6 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", prevXref, xrefAt)

	return b.Bytes()
}

// postUpload uploads via the user-facing route and returns the raw response.
func postUpload(t *testing.T, app *azugo.TestApp, owner, filename string, data []byte) *fasthttp.Response {
	t.Helper()
	tc := app.TestClient()
	body, ct := buildMultipart(t, nil, []fileEntry{{"file", filename, data}})
	resp, err := tc.Post("/api/v1/documents", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", owner))
	qt.Assert(t, qt.IsNil(err))

	return resp
}

// getMeta fetches a document's metadata row.
func getMeta(t *testing.T, app *azugo.TestApp, owner, id string) response.Document {
	t.Helper()
	tc := app.TestClient()
	resp, err := tc.Get("/api/v1/documents/"+id,
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", owner))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var meta response.Document
	decode(t, resp, &meta)

	return meta
}

// The gate admits an uploaded ALREADY-SIGNED PDF and records it as a signed
// pdf row — the bring-your-own-signed-PDF path the validate/archive actions
// key on.
func TestIngestSignedPDFDetected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp := postUpload(t, app, "owner-1", "signed.pdf", signedSamplePDF())
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	var out response.Ingested
	decode(t, resp, &out)
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsTrue(out.HasSignatures))

	meta := getMeta(t, app, "owner-1", out.ID)
	qt.Check(t, qt.Equals(meta.Kind, "pdf"))
	qt.Check(t, qt.Equals(meta.Status, "signed"))
}

// An unsigned PDF stays a plain source and reports no signature.
func TestIngestUnsignedPDFStaysSource(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp := postUpload(t, app, "owner-1", "plain.pdf", samplePDF())
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	var out response.Ingested
	decode(t, resp, &out)
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsFalse(out.HasSignatures))

	meta := getMeta(t, app, "owner-1", out.ID)
	qt.Check(t, qt.Equals(meta.Kind, "source"))
	qt.Check(t, qt.Equals(meta.Status, "received"))
}

// Gate rejections come back as typed, clear errors; opaque formats still pass
// (signing-mode admission: any format).
func TestIngestGateRejections(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	cases := []struct {
		name     string
		filename string
		data     []byte
	}{
		{"html renamed to pdf", "fake.pdf", []byte("<html><script>x()</script></html>")},
		{"garbage named pdf", "fake.pdf", []byte{0xde, 0xad, 0xbe, 0xef}},
		// (A path separator in the name is stripped by the multipart layer
		// before the gate sees it — that rule is covered by the gate's own
		// unit tests; here it can't be exercised through the form parser.)
		{"bidi override in name", "evil" + string(rune(0x202E)) + "fdp.pdf", []byte("x")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postUpload(t, app, "owner-1", tc.filename, tc.data)
			defer fasthttp.ReleaseResponse(resp)
			qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
			qt.Assert(t, qt.IsTrue(bytes.Contains(bodyOf(t, resp), []byte("err:document:malformedUpload"))))
		})
	}

	resp := postUpload(t, app, "owner-1", "notes.txt", []byte("hello"))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
}

// fakeClamd runs a minimal clamd INSTREAM responder.
func fakeClamd(t *testing.T, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				cmd := make([]byte, len("zINSTREAM\x00"))
				if _, err := c.Read(cmd); err != nil {
					return
				}
				var size [4]byte
				for {
					if _, err := c.Read(size[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(size[:])
					if n == 0 {
						break
					}
					chunk := make([]byte, n)
					read := 0
					for read < int(n) {
						m, err := c.Read(chunk[read:])
						if err != nil {
							return
						}
						read += m
					}
				}
				_, _ = c.Write([]byte(reply + "\x00"))
			}(conn)
		}
	}()

	return ln.Addr().String()
}

// With CLAMAV_ENDPOINT configured, a FOUND verdict rejects the upload with the
// typed infected reason; a clean verdict admits; an unreachable scanner fails
// open. Unset (every other test in this suite) skips the scan entirely.
func TestIngestClamAVSeam(t *testing.T) {
	run := func(t *testing.T, endpoint string, wantStatus int, wantBody string) {
		t.Helper()
		t.Setenv("CLAMAV_ENDPOINT", endpoint)
		app := testApp(t)
		app.Start(t)
		defer app.Stop()

		resp := postUpload(t, app, "owner-1", "notes.txt", []byte("x"))
		defer fasthttp.ReleaseResponse(resp)
		qt.Assert(t, qt.Equals(resp.StatusCode(), wantStatus))
		if wantBody != "" {
			qt.Assert(t, qt.IsTrue(bytes.Contains(bodyOf(t, resp), []byte(wantBody))))
		}
	}

	t.Run("infected rejected", func(t *testing.T) {
		run(t, fakeClamd(t, "stream: Eicar-Signature FOUND"),
			fasthttp.StatusUnprocessableEntity, "err:document:infectedUpload")
	})
	t.Run("clean admitted", func(t *testing.T) {
		run(t, fakeClamd(t, "stream: OK"), fasthttp.StatusCreated, "")
	})
	t.Run("unreachable fails open", func(t *testing.T) {
		run(t, "127.0.0.1:1", fasthttp.StatusCreated, "")
	})
}
