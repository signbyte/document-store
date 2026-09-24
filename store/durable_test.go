package store

import (
	"context"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

// The sweep pair, at the layer the background task actually calls. What protects a
// document is having NO date, never which class it carries — and it takes both
// assertions to show that, because either one alone also passes against a sweep
// that simply skips the durable class.
func TestSweepProtectsTheUndatedNotTheClass(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	past := time.Now().Add(-time.Hour)

	// Inserted directly, NOT through mustInsert: that helper supplies a date when
	// none is given, which would make this row ordinary and the assertion below
	// pass for the wrong reason.
	kept, err := m.Insert(ctx, InsertInput{
		Owner:          "product:example:org-a",
		OwnerKind:      PrincipalProduct,
		TenantID:       "org-a",
		ContentHash:    "hash",
		Mime:           "text/plain",
		RetentionClass: RetentionDurable,
		RetentionUntil: nil,
		StorageRef:     "obj-kept",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(m.rows[kept].RetentionUntil))
	dated := mustInsert(t, m, InsertInput{
		Owner:          "product:example:org-a",
		OwnerKind:      PrincipalProduct,
		TenantID:       "org-a",
		RetentionClass: RetentionDurable,
		RetentionUntil: &past,
		StorageRef:     "obj-dated",
	})
	ephemeral := mustInsert(t, m, InsertInput{
		Owner:          "person-1",
		RetentionClass: RetentionTTL,
		RetentionUntil: &past,
		StorageRef:     "obj-ttl",
	})

	purged, err := m.SweepRetention(ctx, time.Now(), 100)
	qt.Assert(t, qt.IsNil(err))

	swept := map[string]bool{}
	for _, p := range purged {
		swept[p.ID] = true
	}

	// No date, so nothing to act on.
	qt.Check(t, qt.IsFalse(swept[kept]))
	// The owner set a date and it passed: that is the owner's own instruction
	// carried out later, not the store overruling the owner.
	qt.Check(t, qt.IsTrue(swept[dated]))
	// And what already worked still works.
	qt.Check(t, qt.IsTrue(swept[ephemeral]))
}

// A product holds its document and may release it; it does not co-sign, which is a
// person's act.
func TestProductOwnerHoldsReadNotCosign(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	owner := Caller{Product: "product:example:org-a", Tenant: "org-a"}
	id := mustInsert(t, m, InsertInput{
		Owner:          owner.Product,
		OwnerKind:      PrincipalProduct,
		TenantID:       "org-a",
		RetentionClass: RetentionDurable,
		StorageRef:     "obj",
	})

	got, err := m.Get(ctx, id, owner)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.ID, id))

	root := chainRootID(got)
	qt.Check(t, qt.IsTrue(m.allows(root, owner, "read")))
	qt.Check(t, qt.IsFalse(m.allows(root, owner, "cosign")))
}

// The organisation is checked on the ROW as well as inside the principal, and this
// is the only way to reach that second check: a row whose own organisation
// disagrees with the one its owner names. Through a route it is unreachable —
// the principal carries the organisation, so a caller acting for another one fails
// the access entry first and never gets here. That makes this check defence in
// depth against a row written some other way (a repair, an import, a future
// principal shape), and it is worth having precisely because nothing else would
// notice.
func TestOrganisationIsCheckedOnTheRowToo(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	owner := Caller{Product: "product:example:org-a", Tenant: "org-a"}
	id := mustInsert(t, m, InsertInput{
		Owner:          owner.Product,
		OwnerKind:      PrincipalProduct,
		TenantID:       "org-a",
		RetentionClass: RetentionDurable,
		StorageRef:     "obj",
	})

	_, err := m.Get(ctx, id, owner)
	qt.Assert(t, qt.IsNil(err))

	// The row now belongs to an organisation its owner does not name.
	m.rows[id].TenantID = "org-b"

	_, err = m.Get(ctx, id, owner)
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))

	// And it cannot be released either — a caller that may not read a document
	// must not be able to destroy it.
	_, err = m.RemoveAccess(ctx, id, owner)
	qt.Check(t, qt.ErrorIs(err, ErrNotFound))
}
