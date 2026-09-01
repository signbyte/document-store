package documents

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/signbyte/document-store/kms"
	"github.com/signbyte/document-store/s3"
	"github.com/signbyte/document-store/store"
)

// Signed/unsigned upload detection lives at the user-facing upload route (the
// document gate) — see the routes package tests; this package's Ingest treats
// bytes opaquely apart from the container-manifest capture.

func newTestService(t *testing.T, ttl time.Duration) *Service {
	t.Helper()
	k, _, err := kms.NewLocal(nil)
	if err != nil {
		t.Fatalf("kms: %v", err)
	}

	return New(store.NewMemory(), s3.NewMemory(), k, ttl)
}

func TestIngestCanonicalHashAndRoundTrip(t *testing.T) {
	svc := newTestService(t, time.Hour)
	ctx := context.Background()
	data := []byte("hello eIDAS world")

	doc, err := svc.Ingest(ctx, IngestInput{Owner: "owner-1", Filename: "a.txt", Mime: "text/plain", Data: data})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// B1 invariant: the stored content_hash is exactly base64(SHA-256(bytes)),
	// computed once and never recomputed downstream.
	sum := sha256.Sum256(data)
	want := base64.StdEncoding.EncodeToString(sum[:])
	if doc.ContentHash != want {
		t.Fatalf("content_hash = %q, want %q", doc.ContentHash, want)
	}
	if doc.Kind != "source" || doc.Status != "received" || doc.PreservationClass != "none" {
		t.Fatalf("unexpected defaults: kind=%s status=%s presv=%s", doc.Kind, doc.Status, doc.PreservationClass)
	}
	if doc.Size != int64(len(data)) {
		t.Fatalf("size = %d, want %d", doc.Size, len(data))
	}

	// Content round-trips through envelope encryption.
	_, got, err := svc.Content(ctx, doc.ID, store.Caller{Sub: "owner-1"})
	if err != nil {
		t.Fatalf("Content: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("decrypted bytes != original")
	}
}

func TestNoIDOR(t *testing.T) {
	svc := newTestService(t, time.Hour)
	ctx := context.Background()

	doc, err := svc.Ingest(ctx, IngestInput{Owner: "owner-1", Data: []byte("secret")})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// A different owner cannot read the metadata or the content.
	if _, err := svc.Get(ctx, doc.ID, store.Caller{Sub: "owner-2"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get cross-owner: err = %v, want ErrNotFound", err)
	}
	if _, _, err := svc.Content(ctx, doc.ID, store.Caller{Sub: "owner-2"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Content cross-owner: err = %v, want ErrNotFound", err)
	}
}

func TestDeleteDestroysBytes(t *testing.T) {
	svc := newTestService(t, time.Hour)
	ctx := context.Background()

	doc, err := svc.Ingest(ctx, IngestInput{Owner: "owner-1", Data: []byte("bytes")})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if _, err := svc.Delete(ctx, doc.ID, store.Caller{Sub: "owner-1"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// The sole holder removing access leaves the document's ACL empty, so it
	// leaves their view entirely (ErrNotFound) and its bytes are purged.
	if _, _, err := svc.Content(ctx, doc.ID, store.Caller{Sub: "owner-1"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Content after delete: err = %v, want ErrNotFound", err)
	}
}

func TestReplaceContainerKeepLatest(t *testing.T) {
	svc := newTestService(t, time.Hour)
	ctx := context.Background()

	src, err := svc.Ingest(ctx, IngestInput{Owner: "alice", Data: []byte("orig")})
	if err != nil {
		t.Fatalf("ingest source: %v", err)
	}
	cont, err := svc.Ingest(ctx, IngestInput{Owner: "alice", Kind: "container", ParentID: src.ID, Data: []byte("v1")})
	if err != nil {
		t.Fatalf("ingest container: %v", err)
	}

	updated, err := svc.ReplaceContainer(ctx, cont.ID, cont.ContentHash, []byte("v2"))
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if updated.ID != cont.ID {
		t.Fatalf("replace changed the container id")
	}

	// The bytes round-trip the NEW version through envelope encryption.
	_, got, err := svc.Content(ctx, cont.ID, store.Caller{Sub: "alice"})
	if err != nil {
		t.Fatalf("content: %v", err)
	}
	if string(got) != "v2" {
		t.Fatalf("content = %q, want v2", got)
	}

	// keep-latest: still exactly one container (+ the source) — no version pile.
	docs, err := svc.List(ctx, store.Caller{Sub: "alice"}, 0, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("alice has %d docs, want 2 (source + one container)", len(docs))
	}

	// The stale base hash (the v1 hash) is rejected by the CAS.
	if _, err := svc.ReplaceContainer(ctx, cont.ID, cont.ContentHash, []byte("v3")); !errors.Is(err, store.ErrChainAdvanced) {
		t.Fatalf("stale CAS: err=%v want ErrChainAdvanced", err)
	}
}

func TestSweepExpiresAndPurges(t *testing.T) {
	// ttl = -1s → every ingest is immediately expired.
	svc := newTestService(t, -time.Second)
	ctx := context.Background()

	d1, _ := svc.Ingest(ctx, IngestInput{Owner: "o", Data: []byte("a")})
	d2, _ := svc.Ingest(ctx, IngestInput{Owner: "o", Data: []byte("b")})

	n, err := svc.Sweep(ctx, time.Now(), 100)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n != 2 {
		t.Fatalf("swept %d, want 2", n)
	}
	for _, id := range []string{d1.ID, d2.ID} {
		if _, _, err := svc.Content(ctx, id, store.Caller{Sub: "o"}); !errors.Is(err, ErrGone) {
			t.Fatalf("Content after sweep for %s: err = %v, want ErrGone", id, err)
		}
	}
}
