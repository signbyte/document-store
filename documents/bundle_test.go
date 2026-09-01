package documents

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/signbyte/document-store/packaging"
	"github.com/signbyte/document-store/store"
)

// The multi-document bundle: 3 loose sources become ONE unsigned container
// (the chain root), the sources are absorbed, every original is extractable,
// and a draft rebundle reorders/extends the set in place.
func TestBundleAbsorbExtractRebundle(t *testing.T) {
	svc := newTestService(t, time.Hour)
	ctx := context.Background()
	owner := store.Caller{Sub: "owner-1"}

	up := func(name, body string) *store.Document {
		t.Helper()
		d, err := svc.Ingest(ctx, IngestInput{Owner: owner.Sub, Filename: name, Mime: "text/plain", Data: []byte(body)})
		if err != nil {
			t.Fatalf("Ingest %s: %v", name, err)
		}
		return d
	}
	a, b, c := up("a.txt", "alpha"), up("b.txt", "beta"), up("c.txt", "gamma")

	bundle, err := svc.Bundle(ctx, owner.Sub, "", []string{a.ID, b.ID, c.ID}, "")
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	// ONE unsigned container row, R-C filename, manifest of 3 in sender order.
	if bundle.Kind != "container" || bundle.Status != "received" {
		t.Fatalf("bundle kind/status = %s/%s, want container/received", bundle.Kind, bundle.Status)
	}
	if bundle.Filename != "a.asice" {
		t.Fatalf("bundle filename = %q, want a.asice (first file + .asice)", bundle.Filename)
	}
	if len(bundle.InnerFiles) != 3 || bundle.InnerFiles[0].Name != "a.txt" ||
		bundle.InnerFiles[1].Name != "b.txt" || bundle.InnerFiles[2].Name != "c.txt" {
		t.Fatalf("innerFiles wrong: %+v", bundle.InnerFiles)
	}

	// The loose sources are absorbed: rows gone, blobs gone.
	for _, src := range []*store.Document{a, b, c} {
		if _, err := svc.Get(ctx, src.ID, owner); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("source %s still resolvable after absorb: %v", src.Filename, err)
		}
	}

	// Extract-an-original on demand: the container is the originals' only home.
	_, blob, err := svc.Content(ctx, bundle.ID, owner)
	if err != nil {
		t.Fatalf("Content(bundle): %v", err)
	}
	objs, err := packaging.DataObjects(blob)
	if err != nil {
		t.Fatalf("DataObjects: %v", err)
	}
	want := map[string]string{"a.txt": "alpha", "b.txt": "beta", "c.txt": "gamma"}
	for _, o := range objs {
		if want[o.Name] != string(o.Data) {
			t.Fatalf("inner %s = %q, want %q", o.Name, o.Data, want[o.Name])
		}
	}

	// Rebundle: drop b, reorder c before a, add a new source d — in place.
	d := up("d.txt", "delta")
	re, err := svc.Rebundle(ctx, owner.Sub, bundle.ID, []BundleEntry{
		{Name: "c.txt"}, {SourceID: d.ID}, {Name: "a.txt"},
	})
	if err != nil {
		t.Fatalf("Rebundle: %v", err)
	}
	if re.ID != bundle.ID || re.Status != "received" {
		t.Fatalf("rebundle must keep the same unsigned row: id=%s status=%s", re.ID, re.Status)
	}
	if len(re.InnerFiles) != 3 || re.InnerFiles[0].Name != "c.txt" ||
		re.InnerFiles[1].Name != "d.txt" || re.InnerFiles[2].Name != "a.txt" {
		t.Fatalf("rebundled innerFiles wrong: %+v", re.InnerFiles)
	}
	if _, err := svc.Get(ctx, d.ID, owner); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("new source d not absorbed on rebundle: %v", err)
	}
}

// Bundling anything but the owner's unsigned sources is refused, and duplicate
// filenames are made unique instead of colliding.
func TestBundleGuards(t *testing.T) {
	svc := newTestService(t, time.Hour)
	ctx := context.Background()

	a, _ := svc.Ingest(ctx, IngestInput{Owner: "owner-1", Filename: "same.txt", Mime: "text/plain", Data: []byte("one")})
	b, _ := svc.Ingest(ctx, IngestInput{Owner: "owner-1", Filename: "same.txt", Mime: "text/plain", Data: []byte("two")})

	// A single non-PDF document is a legitimate 1-file bundle now (the ASiC-E
	// container is the universal at-rest form; only a lone natively-signed PDF
	// stays a loose source). Uses a dedicated source so a and b survive for the
	// multi-file bundle below.
	solo, _ := svc.Ingest(ctx, IngestInput{Owner: "owner-1", Filename: "solo.txt", Mime: "text/plain", Data: []byte("solo")})
	oneFile, err := svc.Bundle(ctx, "owner-1", "", []string{solo.ID}, "")
	if err != nil {
		t.Fatalf("1-doc bundle: %v", err)
	}
	if len(oneFile.InnerFiles) != 1 || oneFile.InnerFiles[0].Name != "solo.txt" {
		t.Fatalf("1-doc bundle inner files: %+v", oneFile.InnerFiles)
	}
	// An empty set is still not bundleable.
	if _, err := svc.Bundle(ctx, "owner-1", "", nil, ""); !errors.Is(err, store.ErrNotBundleable) {
		t.Fatalf("empty bundle: want ErrNotBundleable, got %v", err)
	}

	// A foreign document is indistinguishable from a missing one.
	other, _ := svc.Ingest(ctx, IngestInput{Owner: "owner-2", Filename: "x.txt", Mime: "text/plain", Data: []byte("x")})
	if _, err := svc.Bundle(ctx, "owner-1", "", []string{a.ID, other.ID}, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign source: want ErrNotFound, got %v", err)
	}

	// Duplicate filenames are uniquified, not rejected.
	bundle, err := svc.Bundle(ctx, "owner-1", "", []string{a.ID, b.ID}, "pair.asice")
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if bundle.Filename != "pair.asice" {
		t.Fatalf("explicit filename ignored: %q", bundle.Filename)
	}
	if len(bundle.InnerFiles) != 2 || bundle.InnerFiles[0].Name != "same.txt" || bundle.InnerFiles[1].Name != "same (2).txt" {
		t.Fatalf("duplicate names not uniquified: %+v", bundle.InnerFiles)
	}

	// An unsigned bundle stays rebundlable (a signed one is refused by the
	// status gate exercised in the store backends).
	if _, err := svc.Rebundle(ctx, "owner-1", bundle.ID, []BundleEntry{{Name: "same.txt"}, {Name: "same (2).txt"}}); err != nil {
		t.Fatalf("rebundle unsigned: %v", err)
	}
	// A rebundle down to a single inner file is allowed — dropping a set to one
	// file stays a 1-file container; it does not trip the floor.
	if _, err := svc.Rebundle(ctx, "owner-1", bundle.ID, []BundleEntry{{Name: "same.txt"}}); err != nil {
		t.Fatalf("rebundle to one: %v", err)
	}
}

// The first signature reaches the bundle through the ordinary co-sign merge
// (kind=container) and keep-latest replace: the SAME row flips received→signed
// in place — no new row, no chain change.
func TestBundleFirstSignatureFlipsSigned(t *testing.T) {
	svc := newTestService(t, time.Hour)
	ctx := context.Background()
	owner := store.Caller{Sub: "owner-1"}

	a, _ := svc.Ingest(ctx, IngestInput{Owner: owner.Sub, Filename: "a.txt", Mime: "text/plain", Data: []byte("alpha")})
	b, _ := svc.Ingest(ctx, IngestInput{Owner: owner.Sub, Filename: "b.txt", Mime: "text/plain", Data: []byte("beta")})
	bundle, err := svc.Bundle(ctx, owner.Sub, "", []string{a.ID, b.ID}, "")
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	signed, err := svc.ReplaceContainer(ctx, bundle.ID, bundle.ContentHash, []byte("signed container bytes"))
	if err != nil {
		t.Fatalf("ReplaceContainer onto bundle: %v", err)
	}
	if signed.ID != bundle.ID || signed.Status != "signed" {
		t.Fatalf("first signature: id=%s status=%s, want same row + signed", signed.ID, signed.Status)
	}

	// And once signed, the draft-edit door is closed.
	if _, err := svc.Rebundle(ctx, owner.Sub, bundle.ID, []BundleEntry{{Name: "a.txt"}, {Name: "b.txt"}}); !errors.Is(err, store.ErrNotBundleable) {
		t.Fatalf("rebundle of a signed bundle: want ErrNotBundleable, got %v", err)
	}
}

// The dashboard classification: a bundle signed IN PLACE reads platform-signed
// (completed), while an untouched upload stays a draft; chains list last-action
// first.
func TestBundleChainClassificationAndOrder(t *testing.T) {
	svc := newTestService(t, time.Hour)
	ctx := context.Background()
	owner := store.Caller{Sub: "owner-1"}

	a, _ := svc.Ingest(ctx, IngestInput{Owner: owner.Sub, Filename: "a.txt", Mime: "text/plain", Data: []byte("alpha")})
	b, _ := svc.Ingest(ctx, IngestInput{Owner: owner.Sub, Filename: "b.txt", Mime: "text/plain", Data: []byte("beta")})
	loose, _ := svc.Ingest(ctx, IngestInput{Owner: owner.Sub, Filename: "later.txt", Mime: "text/plain", Data: []byte("later")})

	bundle, err := svc.Bundle(ctx, owner.Sub, "", []string{a.ID, b.ID}, "")
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if _, err := svc.ReplaceContainer(ctx, bundle.ID, bundle.ContentHash, []byte("signed bytes")); err != nil {
		t.Fatalf("ReplaceContainer: %v", err)
	}

	chains, err := svc.ListChains(ctx, owner, 10, "", false)
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}
	if len(chains) != 2 {
		t.Fatalf("chains = %d, want 2 (bundle + loose)", len(chains))
	}
	// The just-signed bundle is the LAST ACTION → first row, platform-signed.
	if chains[0].ChainRootID != bundle.ID || !chains[0].PlatformSigned {
		t.Fatalf("first row = %s platformSigned=%v, want the signed bundle first + true",
			chains[0].ChainRootID, chains[0].PlatformSigned)
	}
	// The untouched upload stays an unsigned draft.
	if chains[1].ChainRootID != loose.ID || chains[1].PlatformSigned {
		t.Fatalf("second row = %s platformSigned=%v, want the loose upload + false",
			chains[1].ChainRootID, chains[1].PlatformSigned)
	}
}
