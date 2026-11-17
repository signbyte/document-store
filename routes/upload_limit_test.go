package routes

import (
	"bytes"
	"strings"
	"testing"

	"azugo.io/azugo"
	asice "github.com/gmb-lib/go-asice"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	api "github.com/signbyte/document-store"
	"github.com/signbyte/document-store/audit"
)

// uploadCap is the file cap these tests run with: above the framework's 4 MiB
// default body limit, so a pass proves the route raised its own limit.
const uploadCap = 5 * 1024 * 1024

func limitApp(t *testing.T) (post func(body []byte, contentType string) *fasthttp.Response, stop func()) {
	t.Helper()
	t.Setenv("MAX_FILE_BYTES", "5242880")

	app := testApp(t)
	app.Start(t)

	return func(body []byte, contentType string) *fasthttp.Response {
		tc := app.TestClient()
		resp, err := tc.Post("/api/v1/documents", body,
			tc.WithHeader("Content-Type", contentType),
			tc.WithHeader("X-Test-Scopes", scopeWrite),
			tc.WithHeader("X-Test-Sub", "owner-1"))
		qt.Assert(t, qt.IsNil(err))

		return resp
	}, app.Stop
}

func TestUploadJustUnderCapPasses(t *testing.T) {
	post, stop := limitApp(t)
	defer stop()

	body, ct := buildMultipart(t, nil, []fileEntry{{"file", "big.bin", bytes.Repeat([]byte{'a'}, uploadCap-1024)}})
	qt.Assert(t, qt.IsTrue(len(body) > 4*1024*1024))

	resp := post(body, ct)
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
}

func TestUploadOverCapAndOverheadAnswers413(t *testing.T) {
	post, stop := limitApp(t)
	defer stop()

	body, ct := buildMultipart(t, nil, []fileEntry{{"file", "big.bin", bytes.Repeat([]byte{'a'}, uploadCap+multipartOverhead+1024)}})

	resp := post(body, ct)
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusRequestEntityTooLarge))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(string(resp.Header.ContentType()), "application/problem+json")))
}

// assemblePost runs the assemble route with a 5 MiB file cap and a 12 MiB body cap.
func assemblePost(t *testing.T, docs []asice.File, sigDocs []asice.File) *fasthttp.Response {
	t.Helper()
	t.Setenv("MAX_FILE_BYTES", "5242880")
	t.Setenv("MAX_ASSEMBLE_BYTES", "12582912")

	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	files := make([]fileEntry, 0, len(docs)+1)
	for _, d := range docs {
		files = append(files, fileEntry{"documents", d.Name, d.Data})
	}
	files = append(files, fileEntry{"signatures", "sig.xml", makeXAdES(t, "SIG1", sigDocs)})

	tc := app.TestClient()
	body, ct := buildMultipart(t, nil, files)
	resp, err := tc.Post("/api/v1/documents/assemble", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))

	return resp
}

func TestAssembleTotalAboveFileCapUnderAssembleCapPasses(t *testing.T) {
	docs := []asice.File{
		{Name: "a.bin", Data: bytes.Repeat([]byte{'a'}, 3*1024*1024)},
		{Name: "b.bin", Data: bytes.Repeat([]byte{'b'}, 3*1024*1024)},
	}
	resp := assemblePost(t, docs, docs)
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
}

func TestAssembleTotalOverAssembleCapAnswers413(t *testing.T) {
	// Each file is under the 5 MiB file cap; the total is over 12 MiB.
	docs := []asice.File{
		{Name: "a.bin", Data: bytes.Repeat([]byte{'a'}, 4*1024*1024)},
		{Name: "b.bin", Data: bytes.Repeat([]byte{'b'}, 4*1024*1024)},
		{Name: "c.bin", Data: bytes.Repeat([]byte{'c'}, 4*1024*1024+64*1024)},
	}
	resp := assemblePost(t, docs, docs[:1])
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusRequestEntityTooLarge))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(string(resp.Header.ContentType()), "application/problem+json")))
}

// capSink records the security events handed to the emitter.
type capSink struct{ events []*broker.Envelope }

func (s *capSink) Emit(_ *azugo.Context, ev *broker.Envelope) error {
	s.events = append(s.events, ev)

	return nil
}

func (s *capSink) capEvents() int {
	n := 0
	for _, ev := range s.events {
		if ev.EventType == audit.EventCapExceeded {
			n++
		}
	}

	return n
}

// postWithSink posts a multipart body to path on an app whose audit recorder
// feeds the returned sink, with a 5 MiB file cap and a 12 MiB assemble cap.
func postWithSink(t *testing.T, path string, files []fileEntry) (*fasthttp.Response, *capSink) {
	t.Helper()
	t.Setenv("MAX_FILE_BYTES", "5242880")
	t.Setenv("MAX_ASSEMBLE_BYTES", "12582912")

	app := api.TestApp(t)
	sink := &capSink{}
	app.SetAuditForTest(audit.New(secevents.NewEmitter(sink), nil, nil, "", nil))
	qt.Assert(t, qt.IsNil(Init(app)))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)

	tc := ta.TestClient()
	body, ct := buildMultipart(t, nil, files)
	resp, err := tc.Post(path, body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))

	return resp, sink
}

// A file far over the cap is refused by the body limit before the per-file
// check; the cap-exceeded event is recorded all the same.
func TestUploadFarOverCapRecordsCapExceeded(t *testing.T) {
	resp, sink := postWithSink(t, "/api/v1/documents",
		[]fileEntry{{"file", "big.bin", bytes.Repeat([]byte{'a'}, uploadCap+1024*1024)}})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusRequestEntityTooLarge))
	qt.Check(t, qt.Equals(sink.capEvents(), 1))
}

// A file just over the cap (inside the framing allowance) is still refused by the
// per-file check, and records the event once.
func TestUploadSlightlyOverCapRecordsCapExceededOnce(t *testing.T) {
	resp, sink := postWithSink(t, "/api/v1/documents",
		[]fileEntry{{"file", "big.bin", bytes.Repeat([]byte{'a'}, uploadCap+32*1024)}})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusRequestEntityTooLarge))
	qt.Check(t, qt.Equals(sink.capEvents(), 1))
}

func TestAssembleOverAssembleCapRecordsCapExceeded(t *testing.T) {
	resp, sink := postWithSink(t, "/api/v1/documents/assemble", []fileEntry{
		{"documents", "a.bin", bytes.Repeat([]byte{'a'}, 4*1024*1024)},
		{"documents", "b.bin", bytes.Repeat([]byte{'b'}, 4*1024*1024)},
		{"documents", "c.bin", bytes.Repeat([]byte{'c'}, 4*1024*1024+64*1024)},
		{"signatures", "sig.xml", []byte("<x/>")},
	})
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusRequestEntityTooLarge))
	qt.Check(t, qt.Equals(sink.capEvents(), 1))
}

func TestUploadMalformedMultipartAnswers400(t *testing.T) {
	post, stop := limitApp(t)
	defer stop()

	resp := post([]byte("this is not a multipart body"), "multipart/form-data; boundary=xyz")
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}
