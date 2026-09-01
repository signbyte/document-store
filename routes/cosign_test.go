package routes

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"

	"azugo.io/azugo"
	asice "github.com/gmb-lib/go-asice"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/signbyte/document-store/routes/response"
)

// These tests cover the ASiC-E parallel co-sign path: the inner-data-object digest
// listing (GET /data-objects) and the /complete branch that merges a co-signature
// into an existing container instead of wrapping it (which would nest).

func sha256b64(data []byte) string {
	sum := sha256.Sum256(data)

	return base64.StdEncoding.EncodeToString(sum[:])
}

// makeXAdES builds a minimal detached XAdES signature file referencing exactly the
// given data objects with correct SHA-256 digests (enough for asice.CheckReferences
// + the co-sign target check; no real cryptographic signature value).
func makeXAdES(t *testing.T, id string, docs []asice.File) []byte {
	t.Helper()

	var refs strings.Builder
	for i, d := range docs {
		fmt.Fprintf(&refs, `<ds:Reference Id="r%d" URI="%s">`+
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
			`<ds:DigestValue>%s</ds:DigestValue></ds:Reference>`, i, d.Name, sha256b64(d.Data))
	}

	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">`+
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="%s"><ds:SignedInfo>`+
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>%s`+
		`<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#sp">`+
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
		`<ds:DigestValue>%s</ds:DigestValue></ds:Reference></ds:SignedInfo>`+
		`<ds:SignatureValue>Zm9v</ds:SignatureValue></ds:Signature></asic:XAdESSignatures>`,
		id, refs.String(), sha256b64([]byte("props"))))
}

// makeFileless strips the container-root data objects, leaving the mimetype +
// META-INF entries — the shape the signing service returns for a hash-only result.
func makeFileless(t *testing.T, container []byte) []byte {
	t.Helper()

	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	qt.Assert(t, qt.IsNil(err))

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		if f.Name != "mimetype" && !strings.HasPrefix(f.Name, "META-INF/") {
			continue // drop the root data objects
		}
		rc, err := f.Open()
		qt.Assert(t, qt.IsNil(err))
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		qt.Assert(t, qt.IsNil(err))
		w, err := zw.Create(f.Name)
		qt.Assert(t, qt.IsNil(err))
		_, err = w.Write(data)
		qt.Assert(t, qt.IsNil(err))
	}
	qt.Assert(t, qt.IsNil(zw.Close()))

	return buf.Bytes()
}

// assembleContainer builds a container from docs + one XAdES signature via the
// /assemble endpoint and returns the stored container's id.
func assembleContainer(t *testing.T, app *azugo.TestApp, owner string, docs []asice.File, sigID string) string {
	t.Helper()

	files := make([]fileEntry, 0, len(docs)+1)
	for _, d := range docs {
		files = append(files, fileEntry{"documents", d.Name, d.Data})
	}
	files = append(files, fileEntry{"signatures", "sig.xml", makeXAdES(t, sigID, docs)})

	tc := app.TestClient()
	body, ct := buildMultipart(t, nil, files)
	resp, err := tc.Post("/api/v1/documents/assemble", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", owner))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var out response.Container
	decode(t, resp, &out)
	qt.Assert(t, qt.IsTrue(out.ContainerID != ""))

	return out.ContainerID
}

func sampleDocs() []asice.File {
	return []asice.File{
		{Name: "doc1.txt", Data: []byte("hello world")},
		{Name: "report.pdf", Data: []byte("%PDF-1.4 fake pdf bytes")},
	}
}

func TestDataObjectsEndpoint(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	docs := sampleDocs()
	containerID := assembleContainer(t, app, "owner-1", docs, "FIRST")

	resp, err := tc.Get("/api/v1/documents/"+containerID+"/data-objects",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	var out response.DataObjects
	decode(t, resp, &out)
	qt.Check(t, qt.Equals(out.ContainerID, containerID))
	qt.Assert(t, qt.Equals(len(out.DataObjects), len(docs)))

	byName := make(map[string]response.DataObject, len(out.DataObjects))
	for _, o := range out.DataObjects {
		byName[o.Name] = o
	}
	for _, d := range docs {
		got, ok := byName[d.Name]
		qt.Assert(t, qt.IsTrue(ok))
		qt.Check(t, qt.Equals(got.ContentHash, sha256b64(d.Data)))
		qt.Check(t, qt.Equals(got.Algorithm, "SHA-256"))
	}
}

func TestDataObjectsNotAContainer(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	// A plain source upload (Kind=source) has no inner data objects → 422.
	ing := ingestDoc(t, app, "owner-1", "plain.txt", []byte("not a container"))

	resp, err := tc.Get("/api/v1/documents/"+ing.ID+"/data-objects",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
}

// A co-signer whose access is granted by SERIAL (not sub) can be the FIRST signer:
// /complete on a still-`source` document must create the container AND read it back under
// the co-signer's serial (a first container inherits the chain root's ACL, where the
// co-signer is a serial principal). Regression for the 404 where the create read-back
// dropped the serial, so only the owner (a sub principal) could sign first.
func TestCompleteCoSignerSignsFirstOnSource(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	coSerial := testSerial(654321, 99)
	src := asice.File{Name: "deal.txt", Data: []byte("co-sign me first")}

	// Owner uploads the source; the workflow service grants the co-signer's serial.
	id := ingestDoc(t, app, "owner-1", src.Name, src.Data).ID
	gr, err := tc.Post("/api/v1/documents/"+id+"/acl", []byte(`{"serial":"`+coSerial+`"}`),
		tc.WithHeader("Content-Type", "application/json"),
		tc.WithHeader("X-Test-Scopes", scopeGrant),
		tc.WithHeader("X-Test-Sub", "svc:envelope"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(gr.StatusCode(), fasthttp.StatusNoContent))
	fasthttp.ReleaseResponse(gr)

	// The co-signer (a different sub, matched only by serial) signs FIRST: a fileless
	// result over the source file.
	full, err := asice.BuildContainer([]asice.File{src}, []asice.File{{Name: "s1.xml", Data: makeXAdES(t, "COFIRST", []asice.File{src})}}, nil)
	qt.Assert(t, qt.IsNil(err))
	fileless := makeFileless(t, full)

	body, ct := buildMultipart(t, nil, []fileEntry{{"container", "fileless.asice", fileless}})
	resp, err := tc.Post("/api/v1/documents/"+id+"/complete", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "cosigner-first"),
		tc.WithHeader("X-Test-Serial", coSerial))
	qt.Assert(t, qt.IsNil(err))
	// Before the fix this was 404 (read-back dropped the serial → chain ACL miss).
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	fasthttp.ReleaseResponse(resp)
}

func TestCompleteCoSignsContainerInsteadOfNesting(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	docs := sampleDocs()
	containerID := assembleContainer(t, app, "owner-1", docs, "FIRST")

	// A second signer's hash-only result: a fileless container holding only the new
	// signature over the SAME inner data objects.
	secondFull, err := asice.BuildContainer(docs, []asice.File{{Name: "s2.xml", Data: makeXAdES(t, "SECOND", docs)}}, nil)
	qt.Assert(t, qt.IsNil(err))
	fileless := makeFileless(t, secondFull)

	body, ct := buildMultipart(t, nil, []fileEntry{{"container", "fileless.asice", fileless}})
	resp, err := tc.Post("/api/v1/documents/"+containerID+"/complete", body,
		tc.WithHeader("Content-Type", ct),
		tc.WithHeader("X-Test-Scopes", scopeWrite),
		tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var out response.Container
	decode(t, resp, &out)

	// Fetch the co-signed container and assert it holds TWO parallel signatures over
	// the SAME data objects — a merge, not a container nested inside a container.
	resp, err = tc.Get("/api/v1/documents/"+out.ContainerID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	_, sigs, objs, err := asice.Inspect(bodyOf(t, resp))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(sigs), 2))
	qt.Check(t, qt.Equals(len(objs), len(docs))) // inner files unchanged — not nested
}

// Two parties who begin from the SAME source must not each create their own
// container. The first /complete creates the chain's container; the second loses the
// one-container-per-chain race, re-resolves the winner, and co-signs INTO it — so both
// signs land in ONE container with BOTH signatures, not two divergent single-signature
// ones. (Sequential here deterministically drives the same create-conflict → merge path
// a real concurrent double-sign takes.)
func TestCompleteConcurrentFirstSignsMergeNotDiverge(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	src := asice.File{Name: "deal.txt", Data: []byte("both sign at once")}
	id := ingestDoc(t, app, "owner-1", src.Name, src.Data).ID

	// signFirst posts a fileless first-signature of the source under a given signature id.
	signFirst := func(sigID string) response.Container {
		full, err := asice.BuildContainer([]asice.File{src},
			[]asice.File{{Name: sigID + ".xml", Data: makeXAdES(t, sigID, []asice.File{src})}}, nil)
		qt.Assert(t, qt.IsNil(err))
		body, ct := buildMultipart(t, nil, []fileEntry{{"container", "fileless.asice", makeFileless(t, full)}})
		resp, err := tc.Post("/api/v1/documents/"+id+"/complete", body,
			tc.WithHeader("Content-Type", ct),
			tc.WithHeader("X-Test-Scopes", scopeWrite),
			tc.WithHeader("X-Test-Sub", "owner-1"))
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
		var out response.Container
		decode(t, resp, &out)

		return out
	}

	first := signFirst("SIGA")
	second := signFirst("SIGB")

	// Both first-signs resolved to the SAME container (a divergent create would return a
	// different id) — the loser merged instead of forking the chain.
	qt.Check(t, qt.Equals(second.ContainerID, first.ContainerID))

	// And that one container holds BOTH signatures over the single source file.
	resp, err := tc.Get("/api/v1/documents/"+first.ContainerID+"/content",
		tc.WithHeader("X-Test-Scopes", scopeRead), tc.WithHeader("X-Test-Sub", "owner-1"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	_, sigs, objs, err := asice.Inspect(bodyOf(t, resp))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(sigs), 2))
	qt.Check(t, qt.Equals(len(objs), 1)) // one source file, two parallel signatures
}
