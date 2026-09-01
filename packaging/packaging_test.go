package packaging

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/gmb-lib/go-asice"
)

func sha256b64(b []byte) string {
	sum := sha256.Sum256(b)

	return base64.StdEncoding.EncodeToString(sum[:])
}

// makeXAdES builds a minimal detached XAdES signature file referencing the docs —
// enough for go-asice to assemble + Inspect a real container (no real crypto value).
func makeXAdES(docs []asice.File) []byte {
	var refs strings.Builder
	for i, d := range docs {
		fmt.Fprintf(&refs, `<ds:Reference Id="r%d" URI="%s">`+
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
			`<ds:DigestValue>%s</ds:DigestValue></ds:Reference>`, i, d.Name, sha256b64(d.Data))
	}

	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">`+
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="S"><ds:SignedInfo>`+
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>%s`+
		`<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#sp">`+
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
		`<ds:DigestValue>%s</ds:DigestValue></ds:Reference></ds:SignedInfo>`+
		`<ds:SignatureValue>Zm9v</ds:SignatureValue></ds:Signature></asic:XAdESSignatures>`,
		refs.String(), sha256b64([]byte("props"))))
}

func plainZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("hi"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

// TestInspect proves the ingest-time detector: a real ASiC-E is detected AND its
// inner data objects are returned in one pass, while a plain ZIP / arbitrary bytes
// are NOT mistaken for a container (a false positive would make signing them try to
// co-sign a container with nothing to merge into).
func TestInspect(t *testing.T) {
	docs := []asice.File{
		{Name: "contract.txt", Data: []byte("hello world")},
		{Name: "annex.pdf", Data: []byte("%PDF-1.4 fake")},
	}
	container, err := asice.BuildContainer(docs, []asice.File{{Name: "sig.xml", Data: makeXAdES(docs)}}, nil)
	if err != nil {
		t.Fatalf("BuildContainer: %v", err)
	}

	files, isContainer := Inspect(container)
	if !isContainer {
		t.Fatal("a real ASiC-E container must be detected")
	}
	if len(files) != 2 {
		t.Fatalf("inner files = %d, want 2", len(files))
	}
	names := map[string]bool{}
	for _, f := range files {
		names[f.Name] = true
	}
	if !names["contract.txt"] || !names["annex.pdf"] {
		t.Fatalf("inner file names = %v, want contract.txt + annex.pdf", names)
	}

	if _, ok := Inspect([]byte("this is not a zip at all")); ok {
		t.Fatal("arbitrary bytes must NOT be detected as a container")
	}
	if _, ok := Inspect(nil); ok {
		t.Fatal("nil must NOT be detected as a container")
	}
	if _, ok := Inspect(plainZip(t)); ok {
		t.Fatal("a plain ZIP (no ASiC-E manifest/signatures) must NOT be detected as a container")
	}
}
