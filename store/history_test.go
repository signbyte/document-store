package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// History lists only fully-terminal chains (every row expired/deleted), one row
// per chain as its terminal head; live chains never appear.
func TestListHistoryTerminalChainsOnly(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	// A live chain — not history.
	_ = mustInsert(t, m, InsertInput{Owner: "alice", Filename: "live.pdf"})

	// A fully-expired signed chain — history, presented as its container head.
	root := mustInsert(t, m, InsertInput{Owner: "alice", Filename: "done.pdf"})
	cont := mustInsert(t, m, InsertInput{Owner: "alice", Kind: "container", ParentID: root, Filename: "done.asice"})
	m.rows[root].Status = "expired"
	m.rows[cont].Status = "expired"

	hist, err := m.ListHistory(ctx, "alice", 0, "")
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("history rows = %d, want 1 (live chain must not appear)", len(hist))
	}
	h := hist[0]
	if h.ID != cont || !h.PlatformSigned || h.Status != "expired" {
		t.Fatalf("history head = %+v, want the expired container head", h)
	}

	// Another owner sees nothing.
	other, _ := m.ListHistory(ctx, "bob", 0, "")
	if len(other) != 0 {
		t.Fatalf("bob sees %d history rows, want 0", len(other))
	}
}

// The history sweep erases terminal records older than the keep window (never
// legal-hold), and drops ACL entries whose chain has no rows left.
func TestSweepHistoryErasesOldRecords(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	oldID := mustInsert(t, m, InsertInput{Owner: "alice"})
	m.rows[oldID].Status = "expired"
	m.rows[oldID].UpdatedAt = time.Now().Add(-100 * 24 * time.Hour)

	freshID := mustInsert(t, m, InsertInput{Owner: "alice"})
	m.rows[freshID].Status = "expired"
	m.rows[freshID].UpdatedAt = time.Now().Add(-time.Hour)

	heldID := mustInsert(t, m, InsertInput{Owner: "alice"})
	m.rows[heldID].Status = "expired"
	m.rows[heldID].UpdatedAt = time.Now().Add(-100 * 24 * time.Hour)
	m.rows[heldID].LegalHold = true

	n, err := m.SweepHistory(ctx, time.Now().Add(-90*24*time.Hour), 0)
	if err != nil {
		t.Fatalf("sweep history: %v", err)
	}
	if n != 1 {
		t.Fatalf("erased %d, want 1 (only the old, unheld record)", n)
	}
	if _, ok := m.rows[oldID]; ok {
		t.Fatalf("old record still present after sweep")
	}
	if _, ok := m.rows[freshID]; !ok {
		t.Fatalf("fresh record erased — it is inside the keep window")
	}
	if _, ok := m.rows[heldID]; !ok {
		t.Fatalf("legal-hold record erased — holds must survive every sweep")
	}
}

// Early removal: the owner erases one record; a live chain refuses.
func TestDeleteHistoryChain(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	gone := mustInsert(t, m, InsertInput{Owner: "alice"})
	m.rows[gone].Status = "expired"

	live := mustInsert(t, m, InsertInput{Owner: "alice"})

	if err := m.DeleteHistoryChain(ctx, "alice", live); !errors.Is(err, ErrChainLive) {
		t.Fatalf("live chain removal: err=%v want ErrChainLive", err)
	}
	if err := m.DeleteHistoryChain(ctx, "alice", gone); err != nil {
		t.Fatalf("history removal: %v", err)
	}
	if _, ok := m.rows[gone]; ok {
		t.Fatalf("record still present after early removal")
	}
	if err := m.DeleteHistoryChain(ctx, "alice", gone); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second removal: err=%v want ErrNotFound", err)
	}
}
