package store

import (
	"context"
	"errors"
	"testing"
)

// A signed chain collapses to ONE row: the container head replaces the source
// in the listing (never both), and the row carries the chain's start time.
func TestListChainsCollapsesSignedChain(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	root := mustInsert(t, m, InsertInput{Owner: "alice", Filename: "a.pdf"})
	cont := mustInsert(t, m, InsertInput{Owner: "alice", Kind: "container", ParentID: root, Filename: "a.asice"})

	chains, err := m.ListChains(ctx, Caller{Sub: "alice"}, 0, "", false)
	if err != nil {
		t.Fatalf("list chains: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("signed chain renders %d rows, want 1 (source must collapse into the head)", len(chains))
	}
	c := chains[0]
	if c.ID != cont || c.ChainRootID != root {
		t.Fatalf("head = %s (root %s), want container %s (root %s)", c.ID, c.ChainRootID, cont, root)
	}
	if !c.HasSignatures || !c.PlatformSigned {
		t.Fatalf("container head flags = hasSignatures %v platformSigned %v, want true/true", c.HasSignatures, c.PlatformSigned)
	}
	if got, want := c.ChainCreatedAt, m.rows[root].CreatedAt; !got.Equal(want) {
		t.Fatalf("chain created at %v, want the root's %v", got, want)
	}
}

// One row per chain: N distinct chains produce exactly N rows, whatever mix of
// plain drafts, pre-signed uploads, and platform-signed chains they are.
func TestListChainsOneRowPerChain(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	// Chain 1: plain unsigned upload (a workflow draft).
	draft := mustInsert(t, m, InsertInput{Owner: "alice", Filename: "draft.md"})
	// Chain 2: upload that arrived already signed (ingested as a pdf head).
	pre := mustInsert(t, m, InsertInput{Owner: "alice", Kind: "pdf", Status: "signed", Filename: "signed.pdf"})
	// Chain 3: platform-signed (source + live container).
	root := mustInsert(t, m, InsertInput{Owner: "alice", Filename: "c.pdf"})
	_ = mustInsert(t, m, InsertInput{Owner: "alice", Kind: "container", ParentID: root, Filename: "c.asice"})

	chains, err := m.ListChains(ctx, Caller{Sub: "alice"}, 0, "", false)
	if err != nil {
		t.Fatalf("list chains: %v", err)
	}
	if len(chains) != 3 {
		t.Fatalf("3 chains render %d rows, want 3", len(chains))
	}

	byRoot := map[string]*Chain{}
	for _, c := range chains {
		byRoot[c.ChainRootID] = c
	}
	if c := byRoot[draft]; c == nil || c.HasSignatures || c.PlatformSigned {
		t.Fatalf("plain draft row = %+v, want hasSignatures/platformSigned false", c)
	}
	// The pre-signed upload IS its chain's head: it carries signatures but was
	// not signed here — the workflow-draft distinction rides on PlatformSigned.
	if c := byRoot[pre]; c == nil || !c.HasSignatures || c.PlatformSigned {
		t.Fatalf("pre-signed upload row = %+v, want hasSignatures true + platformSigned false", c)
	}
}

// Signed-PDF uniqueness is per chain TREE: a live signed ROOT (an uploaded
// already-signed PDF) blocks a signed child from being created next to it —
// the chain-advanced signal routes the caller to supersede the root in place.
// A container chain and a superseded (deleted) root do not block.
func TestInsertSignedPdfUniquePerChainTree(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	pre := mustInsert(t, m, InsertInput{Owner: "alice", Kind: "pdf", Status: "signed", Filename: "signed.pdf"})
	if _, err := m.Insert(ctx, InsertInput{Owner: "alice", Kind: "pdf", Status: "signed", ParentID: pre, Filename: "signed.pdf"}); !errors.Is(err, ErrChainAdvanced) {
		t.Fatalf("signed child under a live signed root: err = %v, want ErrChainAdvanced", err)
	}

	// The root also still resolves as the chain's current signed PDF (its head).
	head, err := m.GetLatestSignedPdfByChain(ctx, pre, Caller{Sub: "alice"})
	if err != nil || head.ID != pre {
		t.Fatalf("head of a pre-signed root chain = %v (err %v), want the root itself", head, err)
	}

	// Once the root is superseded-away (deleted), a fresh signed PDF may ingest.
	m.rows[pre].Status = "deleted"
	if _, err := m.Insert(ctx, InsertInput{Owner: "alice", Kind: "pdf", Status: "signed", ParentID: pre, Filename: "signed.pdf"}); err != nil {
		t.Fatalf("signed child after the root is deleted: err = %v, want nil", err)
	}
}

// An expired head hides the chain (it never falls back to presenting the
// source as a live row); includeExpired surfaces it for the history view.
func TestListChainsExpiredHeadHidesChain(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	root := mustInsert(t, m, InsertInput{Owner: "alice"})
	cont := mustInsert(t, m, InsertInput{Owner: "alice", Kind: "container", ParentID: root})
	m.rows[cont].Status = "expired"

	live, err := m.ListChains(ctx, Caller{Sub: "alice"}, 0, "", false)
	if err != nil {
		t.Fatalf("list chains: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("expired chain renders %d live rows, want 0 (no source fallback)", len(live))
	}

	all, err := m.ListChains(ctx, Caller{Sub: "alice"}, 0, "", true)
	if err != nil {
		t.Fatalf("list chains include expired: %v", err)
	}
	if len(all) != 1 || all[0].ID != cont || all[0].Status != "expired" {
		t.Fatalf("includeExpired rows = %+v, want the expired container head", all)
	}
}

// The chains view is scoped exactly like the raw listing: an invited serial
// sees the shared chain (as one row); a stranger sees nothing.
func TestListChainsACLScoped(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	root := mustInsert(t, m, InsertInput{Owner: "alice"})
	_ = mustInsert(t, m, InsertInput{Owner: "alice", Kind: "container", ParentID: root})
	m.acl = append(m.acl, aclGrant{ChainRoot: root, Kind: "serial", Principal: NormalizeSerial("PNOLV-1"), Rights: []string{"read"}})

	bob, err := m.ListChains(ctx, Caller{Sub: "bob", Serial: "PNOLV-1"}, 0, "", false)
	if err != nil {
		t.Fatalf("co-signer list: %v", err)
	}
	if len(bob) != 1 {
		t.Fatalf("co-signer sees %d chains, want 1", len(bob))
	}

	mallory, err := m.ListChains(ctx, Caller{Sub: "mallory"}, 0, "", false)
	if err != nil {
		t.Fatalf("stranger list: %v", err)
	}
	if len(mallory) != 0 {
		t.Fatalf("stranger sees %d chains, want 0", len(mallory))
	}
}

// Keyset pagination by chain root id: the second page starts strictly below
// the cursor and the pages never overlap.
func TestListChainsPagination(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	for range 3 {
		_ = mustInsert(t, m, InsertInput{Owner: "alice"})
	}

	page1, err := m.ListChains(ctx, Caller{Sub: "alice"}, 2, "", false)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("page 1 has %d rows, want 2", len(page1))
	}

	page2, err := m.ListChains(ctx, Caller{Sub: "alice"}, 2, page1[1].ChainRootID, false)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(page2) != 1 {
		t.Fatalf("page 2 has %d rows, want 1", len(page2))
	}
	if page2[0].ChainRootID >= page1[1].ChainRootID {
		t.Fatalf("page 2 row %s is not below the cursor %s", page2[0].ChainRootID, page1[1].ChainRootID)
	}
}

// A chain signed IN PLACE — a bundle, or an uploaded container co-signed here —
// has no child row: the only evidence is the signature timestamp. Reading just
// the parent link calls such a chain unsigned, which is how a completed signing
// came to render as a draft. The single-chain read and the listing must agree.
func TestGetChainReportsInPlaceSigningAsSignedHere(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	id := mustInsert(t, m, InsertInput{
		Owner: "alice", Kind: "container", Filename: "bundle.asice", ContentHash: "h1",
		InnerFiles: []ManifestFile{{Name: "a.pdf", MediaType: "application/pdf"}},
	})

	// Before signing: it carries signatures (it is a container) but nothing was
	// signed here yet.
	c, err := m.GetChain(ctx, Caller{Sub: "alice"}, id)
	if err != nil {
		t.Fatalf("get chain: %v", err)
	}
	if !c.HasSignatures || c.PlatformSigned {
		t.Fatalf("pre-signing flags = hasSignatures %v platformSigned %v, want true/false", c.HasSignatures, c.PlatformSigned)
	}
	if len(c.InnerFiles) != 1 || c.InnerFiles[0].Name != "a.pdf" {
		t.Fatalf("chain read did not carry the inner files: %+v", c.InnerFiles)
	}

	// Sign it in place, the way the platform does.
	if _, _, err := m.ReplaceContainerBlob(ctx, ReplaceInput{
		ID: id, ExpectedHash: "h1", StorageRef: "blob/2", ContentHash: "h2", Size: 10,
	}); err != nil {
		t.Fatalf("replace container blob: %v", err)
	}

	c, err = m.GetChain(ctx, Caller{Sub: "alice"}, id)
	if err != nil {
		t.Fatalf("get chain after signing: %v", err)
	}
	if !c.PlatformSigned {
		t.Fatal("a chain signed in place must read platformSigned=true")
	}

	// The listing says the same thing about the same document.
	chains, err := m.ListChains(ctx, Caller{Sub: "alice"}, 0, "", false)
	if err != nil {
		t.Fatalf("list chains: %v", err)
	}
	if len(chains) != 1 || !chains[0].PlatformSigned {
		t.Fatalf("the listing disagrees with the chain read: %+v", chains)
	}

	// A stranger is answered exactly like someone asking for an unknown id.
	if _, err := m.GetChain(ctx, Caller{Sub: "mallory"}, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger got %v, want ErrNotFound", err)
	}
	if _, err := m.GetChain(ctx, Caller{Sub: "alice"}, "no-such-id"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id got %v, want ErrNotFound", err)
	}
}
