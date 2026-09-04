package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// Memory is an in-memory Store for development and tests. It mirrors the
// procedures' ACL authorization + legal-hold + sweep semantics, but holds
// nothing across restarts. NEVER used when DOCUMENT_STORE_DSN is set.
type Memory struct {
	mu   sync.Mutex
	rows map[string]*Document
	acl  []aclGrant
}

// aclGrant mirrors one document.document_acl row: standing access to a chain
// root for a subject or an eIDAS serial.
type aclGrant struct {
	ChainRoot string
	Kind      string // sub | serial
	Principal string // the sub, or the normalized serial
	Rights    []string
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{rows: map[string]*Document{}} }

// chainRootID is a document's chain root: its parent (every co-signed container
// keeps the original source as parent) or itself when it is the root.
func chainRootID(d *Document) string {
	if d.ParentID != "" {
		return d.ParentID
	}

	return d.ID
}

// allows mirrors document.acl_allows: true when the caller holds right on the
// chain root, as the owning subject OR an invited (normalized) serial.
func (m *Memory) allows(chainRoot string, caller Caller, right string) bool {
	nserial := NormalizeSerial(caller.Serial)
	for _, g := range m.acl {
		if g.ChainRoot != chainRoot || !hasRight(g.Rights, right) {
			continue
		}
		if g.Kind == "sub" && caller.Sub != "" && g.Principal == caller.Sub {
			return true
		}
		if g.Kind == "serial" && nserial != "" && g.Principal == nserial {
			return true
		}
	}

	return false
}

func hasRight(rights []string, want string) bool {
	for _, r := range rights {
		if r == want {
			return true
		}
	}

	return false
}

// Close is a no-op for the in-memory backend.
func (m *Memory) Close() {}

// Ping always succeeds for the in-memory backend.
func (m *Memory) Ping(context.Context) error { return nil }

func clone(d *Document) *Document {
	c := *d

	return &c
}

// Insert stores a copy and returns a fresh ULID id.
func (m *Memory) Insert(_ context.Context, in InsertInput) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	kind := in.Kind
	if kind == "" {
		kind = "source"
	}
	// One live signed artifact per chain, per form: a second concurrent creation
	// from the same source loses so the caller re-resolves the current one (a
	// container is co-signed into; a PDF is re-signed on top — it can't be merged).
	// Containers are unique per parent; signed PDFs per chain TREE — an uploaded
	// already-signed PDF is a signed root (no parent), and a child under it would
	// be a second live signed PDF for the same chain. Mirrors
	// uq_one_container_per_chain + uq_one_signed_pdf_per_chain.
	if (kind == "container" || kind == "pdf") && in.ParentID != "" {
		for _, d := range m.rows {
			if d.Kind != kind || d.Status == "deleted" {
				continue
			}
			if d.ParentID == in.ParentID || (kind == "pdf" && d.ID == in.ParentID) {
				return "", ErrChainAdvanced
			}
		}
	}

	id := ulid.Make().String()
	now := time.Now().UTC()
	status := in.Status
	if status == "" {
		status = "received"
	}
	presv := in.PreservationClass
	if presv == "" {
		presv = "none"
	}
	m.rows[id] = &Document{
		ID:                id,
		Owner:             in.Owner,
		TenantID:          in.TenantID,
		Kind:              kind,
		ParentID:          in.ParentID,
		Filename:          in.Filename,
		StorageRef:        in.StorageRef,
		ContentHash:       in.ContentHash,
		Mime:              in.Mime,
		Size:              in.Size,
		Status:            status,
		EncryptionKeyRef:  in.EncryptionKeyRef,
		PreservationClass: presv,
		RetentionUntil:    in.RetentionUntil,
		InnerFiles:        in.InnerFiles,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// A newly-uploaded source (a chain root) seeds its creator's standing access;
	// a co-signed container inherits the root's entry, so it adds none.
	if in.ParentID == "" {
		m.acl = append(m.acl, aclGrant{
			ChainRoot: id,
			Kind:      "sub",
			Principal: in.Owner,
			Rights:    []string{"read", "cosign"},
		})
	}

	return id, nil
}

// ReplaceContainerBlob hard-replaces a container's bytes in place (keep-latest)
// under the optimistic CAS, returning the updated row + the prior blob refs.
func (m *Memory) ReplaceContainerBlob(_ context.Context, in ReplaceInput) (*Document, *PurgedRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Mirrors the procedure's input check: a preservation class, when given,
	// is one of the closed set — refused before anything is touched.
	switch in.PreservationClass {
	case "", "none", "b_lt", "preservation":
	default:
		return nil, nil, fmt.Errorf("document: invalid preservation class %q", in.PreservationClass)
	}

	// Only a signed head form (container or signed PDF) may be replaced in
	// place — a merged co-signature or an archive-timestamped refresh. A plain
	// source is never replaced.
	d, ok := m.rows[in.ID]
	if !ok || d.Status == "deleted" || d.Kind == "source" {
		return nil, nil, ErrNotFound
	}
	if d.ContentHash != in.ExpectedHash {
		return nil, nil, ErrChainAdvanced
	}

	old := &PurgedRef{ID: d.ID, StorageRef: d.StorageRef, EncryptionKeyRef: d.EncryptionKeyRef}
	now := time.Now().UTC()
	d.StorageRef = in.StorageRef
	d.ContentHash = in.ContentHash
	d.Size = in.Size
	d.EncryptionKeyRef = in.EncryptionKeyRef
	d.Status = "signed"
	// The platform applied this signature in place — lets a root-headed chain
	// (a bundle, or an uploaded file co-signed here) read as signed-here.
	d.SignedAt = &now
	// The fact rides with the bytes: an archive-timestamped refresh records its
	// class in the same write as the swap.
	if in.PreservationClass != "" {
		d.PreservationClass = in.PreservationClass
	}
	d.UpdatedAt = now

	return clone(d), old, nil
}

// absorbSource validates one loose source for absorption under the bundle
// rules; the caller holds the lock. Mirrors the per-source checks of
// document.bundle_sources.
func (m *Memory) absorbSource(id, owner string) (*Document, error) {
	d, ok := m.rows[id]
	if !ok || d.Owner != owner || d.Status == "deleted" || d.Status == "expired" {
		return nil, ErrNotFound
	}
	if !Bundleable(d.Kind, d.Status) {
		return nil, ErrNotBundleable
	}
	if d.LegalHold {
		return nil, ErrLegalHold
	}

	return d, nil
}

// Bundle inserts the unsigned container row and absorbs (hard-deletes) the
// loose sources + their ACL entries, mirroring document.bundle_sources.
func (m *Memory) Bundle(_ context.Context, in BundleInput) (string, []PurgedRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(in.SourceIDs) < 1 {
		return "", nil, ErrNotBundleable
	}
	seen := map[string]bool{}
	docs := make([]*Document, 0, len(in.SourceIDs))
	for _, sid := range in.SourceIDs {
		if seen[sid] {
			return "", nil, ErrNotBundleable
		}
		seen[sid] = true
		d, err := m.absorbSource(sid, in.Owner)
		if err != nil {
			return "", nil, err
		}
		docs = append(docs, d)
	}

	id := ulid.Make().String()
	now := time.Now().UTC()
	presv := in.PreservationClass
	if presv == "" {
		presv = "none"
	}
	m.rows[id] = &Document{
		ID:                id,
		Owner:             in.Owner,
		TenantID:          in.TenantID,
		Kind:              "container",
		Filename:          in.Filename,
		StorageRef:        in.StorageRef,
		ContentHash:       in.ContentHash,
		Mime:              in.Mime,
		Size:              in.Size,
		Status:            "received",
		EncryptionKeyRef:  in.EncryptionKeyRef,
		PreservationClass: presv,
		RetentionUntil:    in.RetentionUntil,
		InnerFiles:        in.InnerFiles,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	m.acl = append(m.acl, aclGrant{ChainRoot: id, Kind: "sub", Principal: in.Owner, Rights: []string{"read", "cosign"}})

	absorbed := make([]PurgedRef, 0, len(docs))
	for _, d := range docs {
		absorbed = append(absorbed, PurgedRef{ID: d.ID, StorageRef: d.StorageRef, EncryptionKeyRef: d.EncryptionKeyRef})
		delete(m.rows, d.ID)
		kept := m.acl[:0]
		for _, g := range m.acl {
			if g.ChainRoot != d.ID {
				kept = append(kept, g)
			}
		}
		m.acl = kept
	}

	return id, absorbed, nil
}

// Rebundle replaces an unsigned bundle's bytes in place under the CAS,
// refreshing the manifest and absorbing newly staged sources; mirrors
// document.rebundle_container (status stays "received").
func (m *Memory) Rebundle(_ context.Context, in RebundleInput) (*Document, *PurgedRef, []PurgedRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.rows[in.ID]
	if !ok || d.Owner != in.Owner || d.Status == "deleted" || d.Status == "expired" {
		return nil, nil, nil, ErrNotFound
	}
	if d.Kind != "container" || d.Status != "received" {
		return nil, nil, nil, ErrNotBundleable
	}
	if d.LegalHold {
		return nil, nil, nil, ErrLegalHold
	}
	if d.ContentHash != in.ExpectedHash {
		return nil, nil, nil, ErrChainAdvanced
	}

	docs := make([]*Document, 0, len(in.AbsorbSourceIDs))
	for _, sid := range in.AbsorbSourceIDs {
		src, err := m.absorbSource(sid, in.Owner)
		if err != nil {
			return nil, nil, nil, err
		}
		docs = append(docs, src)
	}

	old := &PurgedRef{ID: d.ID, StorageRef: d.StorageRef, EncryptionKeyRef: d.EncryptionKeyRef}
	d.StorageRef = in.StorageRef
	d.ContentHash = in.ContentHash
	d.Size = in.Size
	d.EncryptionKeyRef = in.EncryptionKeyRef
	d.InnerFiles = in.InnerFiles
	d.UpdatedAt = time.Now().UTC()

	absorbed := make([]PurgedRef, 0, len(docs))
	for _, src := range docs {
		absorbed = append(absorbed, PurgedRef{ID: src.ID, StorageRef: src.StorageRef, EncryptionKeyRef: src.EncryptionKeyRef})
		delete(m.rows, src.ID)
		kept := m.acl[:0]
		for _, g := range m.acl {
			if g.ChainRoot != src.ID {
				kept = append(kept, g)
			}
		}
		m.acl = kept
	}

	return clone(d), old, absorbed, nil
}

// Grant records standing ACL access to a document's chain (idempotent). A serial
// principal is stored normalized; empty rights default to {read, cosign}.
func (m *Memory) Grant(_ context.Context, in GrantInput) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.rows[in.DocID]
	if !ok {
		return ErrNotFound
	}
	root := chainRootID(d)
	pid := in.PrincipalID
	if in.PrincipalKind == "serial" {
		pid = NormalizeSerial(pid)
	}
	rights := in.Rights
	if len(rights) == 0 {
		rights = []string{"read", "cosign"}
	}

	for i := range m.acl {
		if m.acl[i].ChainRoot == root && m.acl[i].Kind == in.PrincipalKind && m.acl[i].Principal == pid {
			m.acl[i].Rights = rights

			return nil
		}
	}
	m.acl = append(m.acl, aclGrant{ChainRoot: root, Kind: in.PrincipalKind, Principal: pid, Rights: rights})

	return nil
}

// Get returns a document the caller may read, or ErrNotFound.
func (m *Memory) Get(_ context.Context, id string, caller Caller) (*Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.rows[id]
	if !ok || !m.allows(chainRootID(d), caller, "read") {
		return nil, ErrNotFound
	}

	// The chain's download freeze lives on the ROOT row; project the effective
	// flag onto whichever row was fetched (mirrors document.get).
	out := clone(d)
	if root, ok := m.rows[chainRootID(d)]; ok {
		out.ResultFrozen = root.ResultFrozen
	}

	return out, nil
}

// GetContainerByParent returns the chain's single container the caller may read,
// or ErrNotFound (no container yet, or the caller is not on the chain ACL).
func (m *Memory) GetContainerByParent(_ context.Context, parentID string, caller Caller) (*Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if parentID == "" || !m.allows(parentID, caller, "read") {
		return nil, ErrNotFound
	}
	for _, d := range m.rows {
		if d.Kind == "container" && d.ParentID == parentID && d.Status != "deleted" {
			return clone(d), nil
		}
	}

	return nil, ErrNotFound
}

// GetLatestSignedPdfByChain returns the chain's current live signed PDF the caller
// may read (latest by id — ULIDs are time-sortable), or ErrNotFound (none yet, or
// the caller is not on the chain ACL). The chain root itself counts: an uploaded
// already-signed PDF is a signed root, and until a signing supersedes it in place
// it IS the chain's signed PDF.
func (m *Memory) GetLatestSignedPdfByChain(_ context.Context, parentID string, caller Caller) (*Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if parentID == "" || !m.allows(parentID, caller, "read") {
		return nil, ErrNotFound
	}
	var latest *Document
	for _, d := range m.rows {
		if d.Kind == "pdf" && (d.ParentID == parentID || d.ID == parentID) && d.Status != "deleted" {
			if latest == nil || d.ID > latest.ID {
				latest = d
			}
		}
	}
	if latest == nil {
		return nil, ErrNotFound
	}

	return clone(latest), nil
}

// List returns the non-deleted documents the caller may read, descending by id.
func (m *Memory) List(_ context.Context, caller Caller, limit int, after string) ([]*Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []*Document
	for _, d := range m.rows {
		if d.Status == "deleted" || !m.allows(chainRootID(d), caller, "read") {
			continue
		}
		if after != "" && d.ID >= after {
			continue
		}
		out = append(out, clone(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if limit <= 0 {
		limit = 100
	}
	if len(out) > limit {
		out = out[:limit]
	}

	return out, nil
}

// SetStatus changes an owned document's status.
// ListChains mirrors the database projection: one live head per chain (the
// signed artifact outranks the source, then the newest row wins), read-
// authorized on the chain root, keyset-paginated by descending chain root id.
// A chain whose head has expired is omitted unless includeExpired.
func (m *Memory) ListChains(_ context.Context, caller Caller, limit int, after string, includeExpired bool) ([]*Chain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// The cursor pages by LAST ACTION: "<updated_at RFC3339>|<chain_root_id>";
	// a legacy bare root id pages by root id alone.
	var afterTS time.Time
	afterID := after
	if i := strings.IndexByte(after, '|'); i >= 0 {
		if ts, err := time.Parse(time.RFC3339Nano, after[:i]); err == nil {
			afterTS = ts
		}
		afterID = after[i+1:]
	}

	heads := map[string]*Document{}
	for _, d := range m.rows {
		if d.Status == "deleted" {
			continue
		}
		root := chainRootID(d)
		if !m.allows(root, caller, "read") {
			continue
		}
		cur := heads[root]
		if cur == nil || headOutranks(d, cur) {
			heads[root] = d
		}
	}

	out := make([]*Chain, 0, len(heads))
	for root, h := range heads {
		if !includeExpired && h.Status == "expired" {
			continue
		}
		// Last-action keyset: strictly older than the cursor instant, or the
		// same instant with a smaller root id.
		if afterID != "" {
			if !afterTS.IsZero() {
				if h.UpdatedAt.After(afterTS) || (h.UpdatedAt.Equal(afterTS) && root >= afterID) {
					continue
				}
			} else if root >= afterID {
				continue
			}
		}
		chainCreated := h.CreatedAt
		frozen := false
		if r, ok := m.rows[root]; ok {
			chainCreated = r.CreatedAt
			frozen = r.ResultFrozen
		}
		out = append(out, &Chain{
			ChainRootID:       root,
			ID:                h.ID,
			Kind:              h.Kind,
			Status:            h.Status,
			Filename:          h.Filename,
			Mime:              h.Mime,
			Size:              h.Size,
			RetentionUntil:    h.RetentionUntil,
			LegalHold:         h.LegalHold,
			PreservationClass: h.PreservationClass,
			HasSignatures:     chainHasSignatures(h),
			PlatformSigned:    chainPlatformSigned(h),
			ResultFrozen:      frozen,
			ChainCreatedAt:    chainCreated,
			CreatedAt:         h.CreatedAt,
			UpdatedAt:         h.UpdatedAt,
		})
	}
	// Last action first; ties break on the newer chain root.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].UpdatedAt.After(out[j].UpdatedAt)
		}
		return out[i].ChainRootID > out[j].ChainRootID
	})
	if limit <= 0 {
		limit = 100
	}
	if len(out) > limit {
		out = out[:limit]
	}

	return out, nil
}

// headOutranks reports whether a should be a chain's head over b: a signed
// artifact outranks the plain source; between equals the newest row wins.
// GetChain mirrors the database read: ONE chain as its live head, addressed by
// any id in it. Independent of any listing — an expired chain still answers; a
// chain with no live row left, and one the caller may not read, are both
// ErrNotFound.
func (m *Memory) GetChain(_ context.Context, caller Caller, id string) (*Chain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	anyRow := m.rows[id]
	if anyRow == nil {
		return nil, ErrNotFound
	}
	root := chainRootID(anyRow)
	if !m.allows(root, caller, "read") {
		return nil, ErrNotFound
	}

	var head *Document
	for _, d := range m.rows {
		if chainRootID(d) != root || d.Status == "deleted" {
			continue
		}
		if head == nil || headOutranks(d, head) {
			head = d
		}
	}
	if head == nil {
		return nil, ErrNotFound
	}

	chainCreated := head.CreatedAt
	frozen := false
	if r, ok := m.rows[root]; ok {
		chainCreated = r.CreatedAt
		frozen = r.ResultFrozen
	}

	return &Chain{
		ChainRootID:       root,
		ID:                head.ID,
		Kind:              head.Kind,
		Status:            head.Status,
		Filename:          head.Filename,
		Mime:              head.Mime,
		Size:              head.Size,
		RetentionUntil:    head.RetentionUntil,
		LegalHold:         head.LegalHold,
		PreservationClass: head.PreservationClass,
		HasSignatures:     chainHasSignatures(head),
		PlatformSigned:    chainPlatformSigned(head),
		ResultFrozen:      frozen,
		InnerFiles:        head.InnerFiles,
		ChainCreatedAt:    chainCreated,
		CreatedAt:         head.CreatedAt,
		UpdatedAt:         head.UpdatedAt,
	}, nil
}

// chainHasSignatures and chainPlatformSigned mirror the data layer's single
// derivation of a row's chain facts. Every projection here goes through them, so
// this double cannot tell one caller a chain is signed and another that it is
// not — the disagreement that made a completed signing render as a draft.
//
// The explicit "no signatures yet" marker a freshly bundled container carries is
// not modelled by this double (the row type has no such field), so the kind
// proxy stands in for it here.
func chainHasSignatures(d *Document) bool {
	return d.Kind != "source" || d.SignedAt != nil
}

// chainPlatformSigned reports a signature applied HERE: the head is a signed
// child of its root, or the head IS the root and was signed in place. Both
// branches are required — a chain signed in place has no child row.
func chainPlatformSigned(d *Document) bool {
	return d.ParentID != "" || d.SignedAt != nil
}

func headOutranks(a, b *Document) bool {
	as, bs := a.Kind != "source", b.Kind != "source"
	if as != bs {
		return as
	}

	return a.ID > b.ID
}

// terminalChain reports whether every row of the chain is expired or deleted.
// Caller holds the lock.
func (m *Memory) terminalChain(root string) bool {
	for _, d := range m.rows {
		if chainRootID(d) == root && d.Status != "expired" && d.Status != "deleted" {
			return false
		}
	}

	return true
}

// ListHistory mirrors document.list_history: the owner's terminal chains (no
// live row left), one row per chain as its terminal head, keyset-paginated by
// descending chain root id.
func (m *Memory) ListHistory(_ context.Context, owner string, limit int, after string) ([]*HistoryChain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	heads := map[string]*Document{}
	for _, d := range m.rows {
		if d.Owner != owner || (d.Status != "expired" && d.Status != "deleted") {
			continue
		}
		root := chainRootID(d)
		if !m.terminalChain(root) {
			continue
		}
		if after != "" && root >= after {
			continue
		}
		cur := heads[root]
		if cur == nil || headOutranks(d, cur) {
			heads[root] = d
		}
	}

	out := make([]*HistoryChain, 0, len(heads))
	for root, h := range heads {
		chainCreated := h.CreatedAt
		if r, ok := m.rows[root]; ok {
			chainCreated = r.CreatedAt
		}
		out = append(out, &HistoryChain{
			ChainRootID:    root,
			ID:             h.ID,
			Kind:           h.Kind,
			Status:         h.Status,
			Filename:       h.Filename,
			Mime:           h.Mime,
			Size:           h.Size,
			HasSignatures:  chainHasSignatures(h),
			PlatformSigned: chainPlatformSigned(h),
			ChainCreatedAt: chainCreated,
			DestroyedAt:    h.UpdatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChainRootID > out[j].ChainRootID })
	if limit <= 0 {
		limit = 50
	}
	if len(out) > limit {
		out = out[:limit]
	}

	return out, nil
}

// SweepHistory mirrors document.sweep_history: hard-delete terminal rows older
// than before (never legal-hold), then drop ACL entries whose chain has no rows
// left.
func (m *Memory) SweepHistory(_ context.Context, before time.Time, limit int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limit <= 0 {
		limit = 500
	}
	removed := 0
	for id, d := range m.rows {
		if removed >= limit {
			break
		}
		if (d.Status == "expired" || d.Status == "deleted") && !d.LegalHold && d.UpdatedAt.Before(before) {
			delete(m.rows, id)
			removed++
		}
	}

	kept := m.acl[:0]
	for _, g := range m.acl {
		alive := false
		for _, d := range m.rows {
			if chainRootID(d) == g.ChainRoot {
				alive = true
				break
			}
		}
		if alive {
			kept = append(kept, g)
		}
	}
	m.acl = kept

	return removed, nil
}

// DeleteHistoryChain mirrors document.delete_history_chain: an early record
// removal — refused while any row is live or held; hard-deletes the owner's
// terminal chain rows + orphaned ACL entries.
func (m *Memory) DeleteHistoryChain(_ context.Context, owner, chainRootID_ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, d := range m.rows {
		if chainRootID(d) == chainRootID_ && (d.Status != "expired" && d.Status != "deleted" || d.LegalHold) {
			return ErrChainLive
		}
	}

	removed := 0
	for id, d := range m.rows {
		if chainRootID(d) == chainRootID_ && d.Owner == owner {
			delete(m.rows, id)
			removed++
		}
	}
	if removed == 0 {
		return ErrNotFound
	}

	kept := m.acl[:0]
	for _, g := range m.acl {
		if g.ChainRoot != chainRootID_ {
			kept = append(kept, g)
		}
	}
	m.acl = kept

	return nil
}

func (m *Memory) SetStatus(_ context.Context, id, caller, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.rows[id]
	if !ok || d.Owner != caller {
		return ErrNotFound
	}
	d.Status = status
	d.UpdatedAt = time.Now().UTC()

	return nil
}

// SetResultFreeze sets/clears the chain-level download freeze on the ROOT row,
// resolved from any row of the chain (mirrors document.set_result_freeze).
func (m *Memory) SetResultFreeze(_ context.Context, id string, frozen bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.rows[id]
	if !ok {
		return ErrNotFound
	}
	root, ok := m.rows[chainRootID(d)]
	if !ok {
		return ErrNotFound
	}
	root.ResultFrozen = frozen
	root.UpdatedAt = time.Now()

	return nil
}

// ChainRetention reports the latest retention instant across the chain's rows that
// still hold storage (mirrors document.chain_retention). Rows already purged are
// ignored: a purged row's retention is in the past and says nothing about what is
// left to read.
func (m *Memory) ChainRetention(_ context.Context, id string) (time.Time, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.rows[id]
	if !ok {
		return time.Time{}, 0, ErrNotFound
	}

	root := chainRootID(d)
	var until time.Time
	live := 0
	for _, row := range m.rows {
		if chainRootID(row) != root || row.StorageRef == "" {
			continue
		}
		live++
		if row.RetentionUntil.After(until) {
			until = row.RetentionUntil
		}
	}

	return until, live, nil
}

// ExtendRetention rolls retention_until forward (never shortens).
func (m *Memory) ExtendRetention(_ context.Context, id, caller string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.rows[id]
	if !ok || d.Owner != caller {
		return ErrNotFound
	}
	if until.After(d.RetentionUntil) {
		d.RetentionUntil = until
	}
	d.UpdatedAt = time.Now().UTC()

	return nil
}

// RemoveAccess drops the caller's ACL entry on a document's chain; only when the
// last entry is gone are the chain's blobs purged (returned for destruction). A
// legal hold anywhere in the chain refuses.
func (m *Memory) RemoveAccess(_ context.Context, docID string, caller Caller) ([]PurgedRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.rows[docID]
	if !ok {
		return nil, ErrNotFound
	}
	root := chainRootID(d)
	if !m.allows(root, caller, "read") {
		return nil, ErrNotFound
	}

	// Legal hold anywhere in the chain refuses the whole delete (fail-closed).
	for _, r := range m.rows {
		if (r.ID == root || r.ParentID == root) && r.LegalHold {
			return nil, ErrLegalHold
		}
	}

	// Drop the caller's own ACL entries (their sub and/or normalized serial).
	nserial := NormalizeSerial(caller.Serial)
	kept := make([]aclGrant, 0, len(m.acl))
	for _, g := range m.acl {
		mine := g.ChainRoot == root &&
			((g.Kind == "sub" && caller.Sub != "" && g.Principal == caller.Sub) ||
				(g.Kind == "serial" && nserial != "" && g.Principal == nserial))
		if !mine {
			kept = append(kept, g)
		}
	}
	m.acl = kept

	for _, g := range m.acl {
		if g.ChainRoot == root {
			return nil, nil // others still hold access — nothing purged
		}
	}

	// Last access removed → purge every blob in the chain.
	var purged []PurgedRef
	for _, r := range m.rows {
		if (r.ID == root || r.ParentID == root) && r.Status != "deleted" {
			purged = append(purged, PurgedRef{ID: r.ID, StorageRef: r.StorageRef, EncryptionKeyRef: r.EncryptionKeyRef})
			r.Status = "deleted"
			r.StorageRef = ""
			r.EncryptionKeyRef = ""
			r.UpdatedAt = time.Now().UTC()
		}
	}

	return purged, nil
}

// SweepRetention flips expired non-hold docs to "expired" and returns prior refs.
func (m *Memory) SweepRetention(_ context.Context, now time.Time, limit int) ([]PurgedRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var purged []PurgedRef
	for _, d := range m.rows {
		if limit > 0 && len(purged) >= limit {
			break
		}
		if d.LegalHold || d.Status == "deleted" || d.Status == "expired" {
			continue
		}
		if d.RetentionUntil.Before(now) {
			purged = append(purged, PurgedRef{ID: d.ID, StorageRef: d.StorageRef, EncryptionKeyRef: d.EncryptionKeyRef})
			d.Status = "expired"
			d.StorageRef = ""
			d.EncryptionKeyRef = ""
			d.UpdatedAt = time.Now().UTC()
		}
	}

	return purged, nil
}
