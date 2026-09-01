//go:build integration

// Phase-B data-plane smoke: exercises the Document Service domain core against a
// LIVE PostgreSQL 16 (the `document` schema reached through its SECURITY DEFINER
// procedures under the EXECUTE-only `document_public` role) and a LIVE MinIO
// (S3-API) blob store, with real KMS envelope encryption. It is the keystone
// proof that the byte/hash owner works end to end on real infrastructure: upload
// (canonical SHA-256 + envelope-encrypt + object store + metadata insert),
// encrypted-bytes round-trip, fileless ASiC-E completion + reference check, the
// completed container stored through the same path, the 24h retention sweep, and
// manual delete — plus the owner filter (no-IDOR), all enforced by the live
// procedures.
//
// Excluded from the normal unit build by the `integration` tag, and skipped when
// DOCUMENT_STORE_DSN is unset, so `go test ./...` stays hermetic. To run it bring
// up postgres + minio (the stack's document subset) and:
//
//	DOCUMENT_STORE_DSN=postgres://document_public:PW@localhost:5432/authbyte?sslmode=disable \
//	S3_ENDPOINT=localhost:9000 S3_ACCESS_KEY=... S3_SECRET_KEY=... S3_USE_SSL=false \
//	S3_BUCKET=documents S3_PREFIX=document/ DOCUMENT_KMS_MASTER_KEY=<base64-32B> \
//	go test -tags integration -run TestPhaseB ./documents/...
package documents

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gmb-lib/go-asice"

	"github.com/signbyte/document-store/kms"
	"github.com/signbyte/document-store/packaging"
	"github.com/signbyte/document-store/s3"
	"github.com/signbyte/document-store/store"
)

// liveBackends wires the real Postgres store, MinIO blob store, and local KMS
// from the environment, skipping the whole test when DOCUMENT_STORE_DSN is unset.
func liveBackends(t *testing.T) (store.Store, s3.Store, kms.KMS) {
	t.Helper()

	dsn := os.Getenv("DOCUMENT_STORE_DSN")
	if dsn == "" {
		t.Skip("DOCUMENT_STORE_DSN unset — bring up the postgres+minio document subset to run this live data-plane smoke")
	}
	ctx := context.Background()

	st, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("store.NewPostgres: %v", err)
	}
	if err := st.Ping(ctx); err != nil {
		t.Fatalf("postgres ping (is the document subset up?): %v", err)
	}

	useSSL, _ := strconv.ParseBool(os.Getenv("S3_USE_SSL"))
	blob, err := s3.New(s3.Options{
		Endpoint:  os.Getenv("S3_ENDPOINT"),
		AccessKey: os.Getenv("S3_ACCESS_KEY"),
		SecretKey: os.Getenv("S3_SECRET_KEY"),
		UseSSL:    useSSL,
		Bucket:    os.Getenv("S3_BUCKET"),
		Prefix:    os.Getenv("S3_PREFIX"),
	})
	if err != nil {
		t.Fatalf("s3.New: %v", err)
	}
	if err := blob.Ping(ctx); err != nil {
		t.Fatalf("minio ping (bucket %q reachable?): %v", os.Getenv("S3_BUCKET"), err)
	}

	// Use the configured master key when present (faithful), else an ephemeral
	// one — either round-trips within this process.
	var master []byte
	if mk := strings.TrimSpace(os.Getenv("DOCUMENT_KMS_MASTER_KEY")); mk != "" {
		master, err = base64.StdEncoding.DecodeString(mk)
		if err != nil {
			t.Fatalf("decode DOCUMENT_KMS_MASTER_KEY: %v", err)
		}
	}
	k, _, err := kms.NewLocal(master)
	if err != nil {
		t.Fatalf("kms.NewLocal: %v", err)
	}

	return st, blob, k
}

func TestPhaseB_DataPlane_LivePGAndMinIO(t *testing.T) {
	st, blob, k := liveBackends(t)
	defer st.Close()

	ctx := context.Background()
	owner := fmt.Sprintf("phaseb-itest-%d", time.Now().UnixNano())
	docBytes := []byte("Phase B live data-plane proof — eIDAS signing portal document bytes\n")

	svc := New(st, blob, k, 24*time.Hour)

	var sourceID, containerID string
	var containerBytes []byte

	t.Run("upload: ingest computes canonical SHA-256, envelope-encrypts to MinIO, inserts the row", func(t *testing.T) {
		doc, err := svc.Ingest(ctx, IngestInput{Owner: owner, Filename: "contract.txt", Mime: "text/plain", Data: docBytes})
		if err != nil {
			t.Fatalf("Ingest source: %v", err)
		}
		sourceID = doc.ID

		if want := CanonicalHash(docBytes); doc.ContentHash != want {
			t.Fatalf("content_hash = %q, want %q (B1 invariant)", doc.ContentHash, want)
		}
		if doc.Kind != "source" || doc.Status != "received" || doc.PreservationClass != "none" {
			t.Fatalf("defaults: kind=%q status=%q presv=%q", doc.Kind, doc.Status, doc.PreservationClass)
		}
		if doc.Size != int64(len(docBytes)) {
			t.Fatalf("size = %d, want %d", doc.Size, len(docBytes))
		}
		if doc.StorageRef == "" || doc.EncryptionKeyRef == "" {
			t.Fatalf("expected a live storage_ref + encryption_key_ref, got ref=%q key=%q", doc.StorageRef, doc.EncryptionKeyRef)
		}
		if !doc.RetentionUntil.After(time.Now()) {
			t.Fatalf("retention_until %v not in the future (24h TTL)", doc.RetentionUntil)
		}
	})

	t.Run("encrypt round-trip: MinIO fetch → KMS unwrap → AES-GCM open returns the original bytes", func(t *testing.T) {
		_, got, err := svc.Content(ctx, sourceID, store.Caller{Sub: owner})
		if err != nil {
			t.Fatalf("Content: %v", err)
		}
		if !bytes.Equal(got, docBytes) {
			t.Fatalf("decrypted bytes != original (len got=%d want=%d)", len(got), len(docBytes))
		}
	})

	t.Run("no-IDOR: the live document.get owner filter hides another owner's row", func(t *testing.T) {
		if _, err := svc.Get(ctx, sourceID, store.Caller{Sub: "phaseb-other-owner"}); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-owner Get: err = %v, want ErrNotFound", err)
		}
		if _, _, err := svc.Content(ctx, sourceID, store.Caller{Sub: "phaseb-other-owner"}); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-owner Content: err = %v, want ErrNotFound", err)
		}
	})

	t.Run("complete(fileless ASiC-E) + CheckReferences (B1 digest invariant, fail-closed)", func(t *testing.T) {
		adoc := asice.File{Name: "contract.txt", Data: docBytes}
		sig := asice.File{Name: "signatures.xml", Data: makeXAdES([]asice.File{adoc})}

		// CheckReferences passes when the signature references exactly the doc.
		if err := packaging.CheckReferences([]asice.File{adoc}, []asice.File{sig}); err != nil {
			t.Fatalf("CheckReferences (matching): %v", err)
		}
		// …and fails closed when the bytes no longer match the recorded digest.
		tampered := asice.File{Name: "contract.txt", Data: append(append([]byte{}, docBytes...), 'X')}
		if err := packaging.CheckReferences([]asice.File{tampered}, []asice.File{sig}); err == nil {
			t.Fatal("CheckReferences must fail closed on a digest mismatch, got nil")
		}

		// Build a full container, strip its data object to synthesize the fileless
		// container LVRTC returns, then Complete re-inserts the source bytes and
		// re-verifies the references — the primary MVP hash-only path.
		full, err := asice.BuildContainer([]asice.File{adoc}, []asice.File{sig}, nil)
		if err != nil {
			t.Fatalf("BuildContainer: %v", err)
		}
		fileless := stripDataObjects(t, full)
		completed, err := packaging.Complete(fileless, []asice.File{adoc})
		if err != nil {
			t.Fatalf("Complete(fileless): %v", err)
		}
		if got := zipEntry(t, completed, "contract.txt"); !bytes.Equal(got, docBytes) {
			t.Fatal("completed container does not carry the source bytes back")
		}
		containerBytes = completed
	})

	t.Run("store the completed container through live infra (kind=container, parent=source)", func(t *testing.T) {
		cdoc, err := svc.Ingest(ctx, IngestInput{
			Owner:             owner,
			Kind:              "container",
			ParentID:          sourceID,
			Filename:          "contract.asice",
			Mime:              asice.MimeType,
			PreservationClass: "b_lt",
			Status:            "signed",
			Data:              containerBytes,
		})
		if err != nil {
			t.Fatalf("Ingest container: %v", err)
		}
		containerID = cdoc.ID
		if cdoc.Kind != "container" || cdoc.Status != "signed" || cdoc.ParentID != sourceID || cdoc.PreservationClass != "b_lt" {
			t.Fatalf("container row: kind=%q status=%q parent=%q presv=%q", cdoc.Kind, cdoc.Status, cdoc.ParentID, cdoc.PreservationClass)
		}
		_, got, err := svc.Content(ctx, containerID, store.Caller{Sub: owner})
		if err != nil {
			t.Fatalf("Content container: %v", err)
		}
		if !bytes.Equal(got, containerBytes) {
			t.Fatal("container bytes did not round-trip through MinIO + KMS")
		}
	})

	t.Run("TTL sweep: document.sweep_retention expires the row, NULLs refs, purges the MinIO object", func(t *testing.T) {
		// A service whose TTL is already in the past → its ingest is born expired.
		expSvc := New(st, blob, k, -time.Second)
		ex, err := expSvc.Ingest(ctx, IngestInput{Owner: owner, Filename: "ephemeral.txt", Data: []byte("expire me")})
		if err != nil {
			t.Fatalf("Ingest ephemeral: %v", err)
		}

		n, err := expSvc.Sweep(ctx, time.Now(), 500)
		if err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		if n < 1 {
			t.Fatalf("sweep purged %d, want >= 1", n)
		}
		if _, _, err := svc.Content(ctx, ex.ID, store.Caller{Sub: owner}); !errors.Is(err, ErrGone) {
			t.Fatalf("expired doc Content: err = %v, want ErrGone", err)
		}
		// The still-valid 24h source must NOT have been swept.
		if _, got, err := svc.Content(ctx, sourceID, store.Caller{Sub: owner}); err != nil || !bytes.Equal(got, docBytes) {
			t.Fatalf("valid source after sweep: err=%v bytesEqual=%v", err, bytes.Equal(got, docBytes))
		}
	})

	t.Run("removing the sole holder's access purges the chain bytes", func(t *testing.T) {
		// The owner is the only ACL entry, so removing access via the container
		// reference-counts to zero and purges the whole chain (source + container);
		// the document then leaves the owner's view entirely (ErrNotFound).
		if _, err := svc.Delete(ctx, containerID, store.Caller{Sub: owner}); err != nil {
			t.Fatalf("Delete container: %v", err)
		}
		if _, _, err := svc.Content(ctx, containerID, store.Caller{Sub: owner}); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Content after remove-access: err = %v, want ErrNotFound", err)
		}
	})

	// Best-effort cleanup (the chain's bytes are already purged above; this is a
	// no-op when the owner's access is already gone).
	if _, err := svc.Delete(ctx, sourceID, store.Caller{Sub: owner}); err != nil {
		t.Logf("cleanup delete source: %v", err)
	}
}

// makeXAdES builds a minimal detached XAdES signature file that references each
// document by filename + correct SHA-256 digest (plus a SignedProperties
// fragment reference that is a same-document URI, ignored as a data object).
// Mirrors go-asice's own test fixture so packaging.CheckReferences / Complete
// accept it — no real signer needed for a data-plane smoke.
func makeXAdES(docs []asice.File) []byte {
	const dsNS = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`

	var refs strings.Builder
	for i, d := range docs {
		sum := sha256Base64(d.Data)
		fmt.Fprintf(&refs, `<ds:Reference Id="r%d" URI="%s">`+
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
			`<ds:DigestValue>%s</ds:DigestValue></ds:Reference>`, i, d.Name, sum)
	}

	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<ds:Signature %s Id="S0"><ds:SignedInfo>`+
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>`+
		`%s`+
		`<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#sp-S0">`+
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
		`<ds:DigestValue>%s</ds:DigestValue></ds:Reference>`+
		`</ds:SignedInfo>`+
		`<ds:SignatureValue>Zm9v</ds:SignatureValue>`+
		`</ds:Signature>`,
		dsNS, refs.String(), sha256Base64([]byte("props")))

	return []byte(xml)
}

func sha256Base64(data []byte) string { return CanonicalHash(data) }

// stripDataObjects rewrites a full ASiC-E container into a fileless one by
// dropping every data object (keeping `mimetype` + the META-INF entries), which
// is the shape LVRTC returns after a hash-only signature.
func stripDataObjects(t *testing.T, container []byte) []byte {
	t.Helper()

	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		t.Fatalf("open container: %v", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name string, data []byte, method uint16) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}

	// mimetype first and uncompressed (ASiC-E layout rule).
	for _, f := range zr.File {
		if f.Name == "mimetype" {
			write(f.Name, readZip(t, f), zip.Store)
			break
		}
	}
	for _, f := range zr.File {
		if f.Name == "mimetype" || !strings.HasPrefix(f.Name, "META-INF/") {
			continue // drop data objects; keep only META-INF/*
		}
		write(f.Name, readZip(t, f), zip.Deflate)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close fileless zip: %v", err)
	}

	return buf.Bytes()
}

func readZip(t *testing.T, f *zip.File) []byte {
	t.Helper()
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("open zip entry %q: %v", f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read zip entry %q: %v", f.Name, err)
	}

	return data
}

func zipEntry(t *testing.T, container []byte, name string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		t.Fatalf("open container: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			return readZip(t, f)
		}
	}
	t.Fatalf("entry %q not found in container", name)

	return nil
}
