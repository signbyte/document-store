package routes

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	api "github.com/signbyte/document-store"
)

const (
	scopeRead  = "documents:read"
	scopeWrite = "documents:write"
)

func testApp(t testing.TB) *azugo.TestApp {
	app := api.TestApp(t)

	err := Init(app)
	qt.Assert(t, qt.IsNil(err))

	return azugo.NewTestApp(app.App)
}

type fileEntry struct {
	field    string
	filename string
	data     []byte
}

// buildMultipart builds a multipart/form-data body + its Content-Type.
func buildMultipart(t *testing.T, fields map[string]string, files []fileEntry) ([]byte, string) {
	t.Helper()

	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	for k, v := range fields {
		qt.Assert(t, qt.IsNil(w.WriteField(k, v)))
	}
	for _, f := range files {
		part, err := w.CreateFormFile(f.field, f.filename)
		qt.Assert(t, qt.IsNil(err))
		_, err = part.Write(f.data)
		qt.Assert(t, qt.IsNil(err))
	}
	qt.Assert(t, qt.IsNil(w.Close()))

	return buf.Bytes(), w.FormDataContentType()
}

func bodyOf(t *testing.T, resp *fasthttp.Response) []byte {
	t.Helper()
	b, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	return b
}

func decode(t *testing.T, resp *fasthttp.Response, v any) {
	t.Helper()
	qt.Assert(t, qt.IsNil(json.Unmarshal(bodyOf(t, resp), v)))
}
