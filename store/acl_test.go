package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func mustInsert(t *testing.T, m *Memory, in InsertInput) string {
	t.Helper()
	if in.RetentionUntil.IsZero() {
		in.RetentionUntil = time.Now().Add(time.Hour)
	}
	if in.ContentHash == "" {
		in.ContentHash = "hash"
	}
	if in.Mime == "" {
		in.Mime = "text/plain"
	}
	id, err := m.Insert(context.Background(), in)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	return id
}

// The creator reads their own document; nobody else can. A solo document is a
// single-entry ACL, so this is identical to the old owner filter — and an
// unmatched serial fails closed (no enumeration).
func TestACLCreatorReadsOwnOnly(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	id := mustInsert(t, m, InsertInput{Owner: "alice"})

	if _, err := m.Get(ctx, id, Caller{Sub: "alice"}); err != nil {
		t.Fatalf("creator read: %v", err)
	}
	if _, err := m.Get(ctx, id, Caller{Sub: "mallory"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger read: err=%v want ErrNotFound", err)
	}
	if _, err := m.Get(ctx, id, Caller{Sub: "mallory", Serial: ungrantedSerial}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ungranted serial read: err=%v want ErrNotFound", err)
	}
}

// A co-signed container inherits the chain root's ACL: the owner reads it via
// the root entry, and the container adds no ACL entry of its own (access hangs
// off the stable chain root, since the blob is replaced on each co-sign).
func TestACLContainerInheritsRoot(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	root := mustInsert(t, m, InsertInput{Owner: "alice"})

	before := len(m.acl)
	container := mustInsert(t, m, InsertInput{Owner: "alice", Kind: "container", ParentID: root})
	if added := len(m.acl) - before; added != 0 {
		t.Fatalf("container insert added %d ACL entries, want 0 (inherits root)", added)
	}

	if _, err := m.Get(ctx, container, Caller{Sub: "alice"}); err != nil {
		t.Fatalf("owner reads container via root ACL: %v", err)
	}
	if _, err := m.Get(ctx, container, Caller{Sub: "mallory"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger reads container: err=%v want ErrNotFound", err)
	}
}

// An invited eIDAS serial reads the whole shared chain (root + container), the
// match is normalization-aware (case/whitespace), and a different code does not
// match. (The grant is seeded directly here; the workflow service wires the
// grant route in a later increment.)
func TestACLSerialGrantReadsChain(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	root := mustInsert(t, m, InsertInput{Owner: "alice"})
	container := mustInsert(t, m, InsertInput{Owner: "alice", Kind: "container", ParentID: root})

	m.acl = append(m.acl, aclGrant{
		ChainRoot: root,
		Kind:      "serial",
		Principal: NormalizeSerial(lowerTrailingSpace(invitedSerial)), // stored normalized
		Rights:    []string{"read", "cosign"},
	})

	// The co-signer authenticates with a differently-cased/spaced form of the code.
	bob := Caller{Sub: "bob", Serial: leadingSpace(invitedSerial)}
	if _, err := m.Get(ctx, root, bob); err != nil {
		t.Fatalf("co-signer reads root via serial grant: %v", err)
	}
	if _, err := m.Get(ctx, container, bob); err != nil {
		t.Fatalf("co-signer reads container via chain-root grant: %v", err)
	}
	if _, err := m.Get(ctx, root, Caller{Sub: "carol", Serial: strangerSerial}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong serial: err=%v want ErrNotFound", err)
	}
}

// List returns only the chains the caller can read — own uploads plus any chain
// their serial is granted on (so a co-signer sees the shared document).
func TestACLListScopedToCaller(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	a1 := mustInsert(t, m, InsertInput{Owner: "alice"})
	_ = mustInsert(t, m, InsertInput{Owner: "alice"})
	_ = mustInsert(t, m, InsertInput{Owner: "bob"})

	alice, err := m.List(ctx, Caller{Sub: "alice"}, 0, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(alice) != 2 {
		t.Fatalf("alice sees %d docs, want 2", len(alice))
	}

	// Grant bob's serial onto one of alice's chains → it joins bob's list.
	m.acl = append(m.acl, aclGrant{ChainRoot: a1, Kind: "serial", Principal: NormalizeSerial("PNOEE-1"), Rights: []string{"read"}})
	bob, _ := m.List(ctx, Caller{Sub: "bob", Serial: "PNOEE-1"}, 0, "")
	if len(bob) != 2 {
		t.Fatalf("bob sees %d docs, want 2 (own + granted)", len(bob))
	}
}

// Reference-counted delete: a co-signer removing access keeps the bytes (others
// still hold them); only the LAST holder's removal purges every blob in the
// chain (source + container).
func TestRemoveAccessRefCounted(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	root := mustInsert(t, m, InsertInput{Owner: "alice", StorageRef: "obj-root"})
	container := mustInsert(t, m, InsertInput{Owner: "alice", Kind: "container", ParentID: root, StorageRef: "obj-cont"})

	if err := m.Grant(ctx, GrantInput{DocID: root, PrincipalKind: "serial", PrincipalID: "PNOLV-1"}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	bob := Caller{Sub: "bob", Serial: "PNOLV-1"}

	// Bob removes his access via the container → nothing purged; alice still reads.
	purged, err := m.RemoveAccess(ctx, container, bob)
	if err != nil {
		t.Fatalf("bob remove: %v", err)
	}
	if len(purged) != 0 {
		t.Fatalf("bob remove purged %d, want 0 (alice still holds)", len(purged))
	}
	if _, err := m.Get(ctx, container, Caller{Sub: "alice"}); err != nil {
		t.Fatalf("alice still reads after bob removes: %v", err)
	}
	if _, err := m.Get(ctx, container, bob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob read after self-remove: err=%v want ErrNotFound", err)
	}

	// Alice, the last holder, removes access → both chain blobs purge.
	purged, err = m.RemoveAccess(ctx, root, Caller{Sub: "alice"})
	if err != nil {
		t.Fatalf("alice remove: %v", err)
	}
	if len(purged) != 2 {
		t.Fatalf("last-holder remove purged %d blobs, want 2 (root + container)", len(purged))
	}
	if _, err := m.Get(ctx, root, Caller{Sub: "alice"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("root readable after last remove: %v", err)
	}
}

// A solo document is a one-entry ACL: the owner's delete purges it (identical to
// the prior owner-filtered delete).
func TestRemoveAccessSoloPurges(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	id := mustInsert(t, m, InsertInput{Owner: "alice", StorageRef: "obj"})

	purged, err := m.RemoveAccess(ctx, id, Caller{Sub: "alice"})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(purged) != 1 {
		t.Fatalf("solo remove purged %d, want 1", len(purged))
	}
	if _, err := m.Get(ctx, id, Caller{Sub: "alice"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("solo doc readable after remove: %v", err)
	}
}

// keep-latest: a container replace updates the SAME row in place (no new row)
// and returns the prior blob refs; an optimistic CAS rejects a stale base hash.
func TestReplaceContainerBlobKeepLatestAndCAS(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	root := mustInsert(t, m, InsertInput{Owner: "alice"})
	cont := mustInsert(t, m, InsertInput{Owner: "alice", Kind: "container", ParentID: root, ContentHash: "H1", StorageRef: "obj-v1"})

	before := len(m.rows)
	doc, old, err := m.ReplaceContainerBlob(ctx, ReplaceInput{
		ID: cont, ExpectedHash: "H1", StorageRef: "obj-v2", ContentHash: "H2", Size: 9, EncryptionKeyRef: "k2",
	})
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if doc.ID != cont {
		t.Fatalf("replace changed the id: %s != %s", doc.ID, cont)
	}
	if doc.ContentHash != "H2" {
		t.Fatalf("hash not updated: %s", doc.ContentHash)
	}
	if old.StorageRef != "obj-v1" {
		t.Fatalf("old ref = %s, want obj-v1", old.StorageRef)
	}
	if len(m.rows) != before {
		t.Fatalf("replace added a row (%d→%d) — keep-latest must replace in place", before, len(m.rows))
	}

	// Stale CAS: the head is now H2, so a replace expecting H1 is rejected.
	if _, _, err := m.ReplaceContainerBlob(ctx, ReplaceInput{
		ID: cont, ExpectedHash: "H1", StorageRef: "obj-v3", ContentHash: "H3", Size: 9, EncryptionKeyRef: "k3",
	}); !errors.Is(err, ErrChainAdvanced) {
		t.Fatalf("stale CAS: err=%v want ErrChainAdvanced", err)
	}

	// Unknown id → not found.
	if _, _, err := m.ReplaceContainerBlob(ctx, ReplaceInput{
		ID: "no-such-id", ExpectedHash: "H2", StorageRef: "x", ContentHash: "y", Size: 1, EncryptionKeyRef: "z",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: err=%v want ErrNotFound", err)
	}
}

// A legal hold anywhere in the chain refuses the delete entirely (bytes + access
// kept) — fail-closed.
func TestRemoveAccessLegalHoldRefuses(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	root := mustInsert(t, m, InsertInput{Owner: "alice", StorageRef: "obj"})
	m.rows[root].LegalHold = true

	if _, err := m.RemoveAccess(ctx, root, Caller{Sub: "alice"}); !errors.Is(err, ErrLegalHold) {
		t.Fatalf("remove under hold: err=%v want ErrLegalHold", err)
	}
	if _, err := m.Get(ctx, root, Caller{Sub: "alice"}); err != nil {
		t.Fatalf("alice should still read the held doc: %v", err)
	}
}
