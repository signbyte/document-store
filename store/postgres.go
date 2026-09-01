package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the platform store: the `document` schema reached ONLY through
// SECURITY DEFINER procedures under the EXECUTE-only `document_public` role
// (authbyte-db/document). This package never issues raw table SQL — it only CALLs
// the procedures (mirrors access-audit/store and eidas-audit/store).
//
// Selected when DOCUMENT_STORE_DSN is set; the in-memory backend is the
// development/test default.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a connection pool to the platform PostgreSQL. The pool is
// lazy; connectivity is verified on first use (or via Ping).
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: postgres connect: %w", err)
	}

	return &Postgres{pool: pool}, nil
}

// Close releases the connection pool.
func (p *Postgres) Close() { p.pool.Close() }

// Ping verifies backend connectivity.
func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// envelope is the structured result every procedure returns
// (util.result_success / util.result_error).
type envelope struct {
	Result  string          `json:"result"`
	Data    json.RawMessage `json:"data"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
}

// mapCode turns a document:<reason> error code into a sentinel error where one
// exists, so callers/routes can pick the right HTTP status.
func mapCode(proc, code, msg string) error {
	switch {
	case strings.HasSuffix(code, ":not_found"):
		return ErrNotFound
	case strings.HasSuffix(code, ":legal_hold"):
		return ErrLegalHold
	case strings.HasSuffix(code, ":chain_advanced"):
		return ErrChainAdvanced
	case strings.HasSuffix(code, ":chain_live"):
		return ErrChainLive
	case strings.HasSuffix(code, ":not_bundleable"):
		return ErrNotBundleable
	default:
		return fmt.Errorf("store: %s: %s: %s", proc, code, msg)
	}
}

// call invokes a SECURITY DEFINER procedure with the uniform JSONB envelope and
// returns the decoded `data` payload, or a typed error from result_error.
func (p *Postgres) call(ctx context.Context, proc string, in any) (json.RawMessage, error) {
	inJSON, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("store: marshal input: %w", err)
	}

	// CALL with an INOUT parameter returns a single-column row carrying po_data;
	// NULL seeds the INOUT slot.
	q := fmt.Sprintf("CALL %s($1::jsonb, NULL::jsonb)", proc)

	var out []byte
	if err := p.pool.QueryRow(ctx, q, inJSON).Scan(&out); err != nil {
		// A procedure that fails after a write re-raises a structured error with
		// SQLSTATE P0001 (Pattern B); its message is the util.result_error JSON.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "P0001" {
			var env envelope
			if json.Unmarshal([]byte(pgErr.Message), &env) == nil && env.Result == "error" {
				return nil, mapCode(proc, env.Code, env.Message)
			}
		}

		return nil, fmt.Errorf("store: %s: %w", proc, err)
	}

	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, fmt.Errorf("store: %s: decode result: %w", proc, err)
	}
	if env.Result != "success" {
		return nil, mapCode(proc, env.Code, env.Message)
	}

	return env.Data, nil
}

// Insert persists a metadata row via document.insert.
func (p *Postgres) Insert(ctx context.Context, in InsertInput) (string, error) {
	body := map[string]any{
		"owner":           in.Owner,
		"content_hash":    in.ContentHash,
		"mime":            in.Mime,
		"size":            in.Size,
		"retention_until": in.RetentionUntil.UTC().Format(time.RFC3339Nano),
	}
	putOpt(body, "tenant_id", in.TenantID)
	putOpt(body, "kind", in.Kind)
	putOpt(body, "parent_id", in.ParentID)
	putOpt(body, "filename", in.Filename)
	putOpt(body, "storage_ref", in.StorageRef)
	putOpt(body, "status", in.Status)
	putOpt(body, "encryption_key_ref", in.EncryptionKeyRef)
	putOpt(body, "preservation_class", in.PreservationClass)
	if len(in.InnerFiles) > 0 {
		body["inner_files"] = in.InnerFiles
	}

	data, err := p.call(ctx, "document.insert", body)
	if err != nil {
		return "", err
	}

	var res struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return "", fmt.Errorf("store: insert: decode: %w", err)
	}

	return res.ID, nil
}

// ReplaceContainerBlob hard-replaces a container's bytes in place (keep-latest)
// via document.replace_container_blob, under the optimistic CAS.
func (p *Postgres) ReplaceContainerBlob(ctx context.Context, in ReplaceInput) (*Document, *PurgedRef, error) {
	data, err := p.call(ctx, "document.replace_container_blob", map[string]any{
		"id":                 in.ID,
		"expected_hash":      in.ExpectedHash,
		"storage_ref":        in.StorageRef,
		"content_hash":       in.ContentHash,
		"size":               in.Size,
		"encryption_key_ref": in.EncryptionKeyRef,
	})
	if err != nil {
		return nil, nil, err
	}

	var res struct {
		Document            *Document `json:"document"`
		OldStorageRef       string    `json:"oldStorageRef"`
		OldEncryptionKeyRef string    `json:"oldEncryptionKeyRef"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, nil, fmt.Errorf("store: replace_container_blob: decode: %w", err)
	}

	return res.Document, &PurgedRef{ID: in.ID, StorageRef: res.OldStorageRef, EncryptionKeyRef: res.OldEncryptionKeyRef}, nil
}

// Bundle creates the unsigned multi-document container + absorbs its loose
// sources via document.bundle_sources.
func (p *Postgres) Bundle(ctx context.Context, in BundleInput) (string, []PurgedRef, error) {
	body := map[string]any{
		"caller_sub":      in.Owner,
		"source_ids":      in.SourceIDs,
		"filename":        in.Filename,
		"storage_ref":     in.StorageRef,
		"content_hash":    in.ContentHash,
		"mime":            in.Mime,
		"size":            in.Size,
		"retention_until": in.RetentionUntil.UTC().Format(time.RFC3339Nano),
	}
	putOpt(body, "tenant_id", in.TenantID)
	putOpt(body, "encryption_key_ref", in.EncryptionKeyRef)
	putOpt(body, "preservation_class", in.PreservationClass)
	if len(in.InnerFiles) > 0 {
		body["inner_files"] = in.InnerFiles
	}

	data, err := p.call(ctx, "document.bundle_sources", body)
	if err != nil {
		return "", nil, err
	}

	var res struct {
		ID       string      `json:"id"`
		Absorbed []PurgedRef `json:"absorbed"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return "", nil, fmt.Errorf("store: bundle_sources: decode: %w", err)
	}

	return res.ID, res.Absorbed, nil
}

// Rebundle replaces an unsigned bundle's bytes in place via
// document.rebundle_container.
func (p *Postgres) Rebundle(ctx context.Context, in RebundleInput) (*Document, *PurgedRef, []PurgedRef, error) {
	body := map[string]any{
		"caller_sub":         in.Owner,
		"doc_id":             in.ID,
		"expected_hash":      in.ExpectedHash,
		"storage_ref":        in.StorageRef,
		"content_hash":       in.ContentHash,
		"size":               in.Size,
		"encryption_key_ref": in.EncryptionKeyRef,
		"inner_files":        in.InnerFiles,
	}
	if len(in.AbsorbSourceIDs) > 0 {
		body["absorb_source_ids"] = in.AbsorbSourceIDs
	}

	data, err := p.call(ctx, "document.rebundle_container", body)
	if err != nil {
		return nil, nil, nil, err
	}

	var res struct {
		Document            *Document   `json:"document"`
		OldStorageRef       string      `json:"oldStorageRef"`
		OldEncryptionKeyRef string      `json:"oldEncryptionKeyRef"`
		Absorbed            []PurgedRef `json:"absorbed"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, nil, nil, fmt.Errorf("store: rebundle_container: decode: %w", err)
	}

	old := &PurgedRef{ID: in.ID, StorageRef: res.OldStorageRef, EncryptionKeyRef: res.OldEncryptionKeyRef}

	return res.Document, old, res.Absorbed, nil
}

// Grant records standing ACL access to a document's chain via document.grant_acl.
func (p *Postgres) Grant(ctx context.Context, in GrantInput) error {
	body := map[string]any{
		"doc_id":         in.DocID,
		"principal_kind": in.PrincipalKind,
		"principal_id":   in.PrincipalID,
	}
	if len(in.Rights) > 0 {
		body["rights"] = in.Rights
	}
	putOpt(body, "tenant_id", in.TenantID)
	putOpt(body, "granted_by", in.GrantedBy)

	_, err := p.call(ctx, "document.grant_acl", body)

	return err
}

// Get reads one document the caller may read via document.get (ACL-authorized).
func (p *Postgres) Get(ctx context.Context, id string, caller Caller) (*Document, error) {
	body := map[string]any{"id": id, "caller_sub": caller.Sub}
	putOpt(body, "caller_serial", caller.Serial)

	data, err := p.call(ctx, "document.get", body)
	if err != nil {
		return nil, err
	}

	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("store: get: decode: %w", err)
	}

	return &d, nil
}

// GetContainerByParent reads a chain's single container via
// document.get_container_by_parent (ACL-authorized like Get).
func (p *Postgres) GetContainerByParent(ctx context.Context, parentID string, caller Caller) (*Document, error) {
	body := map[string]any{"parent_id": parentID, "caller_sub": caller.Sub}
	putOpt(body, "caller_serial", caller.Serial)

	data, err := p.call(ctx, "document.get_container_by_parent", body)
	if err != nil {
		return nil, err
	}

	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("store: get_container_by_parent: decode: %w", err)
	}

	return &d, nil
}

// GetLatestSignedPdfByChain reads a chain's current signed PDF via
// document.get_latest_signed_pdf_by_chain (ACL-authorized like Get).
func (p *Postgres) GetLatestSignedPdfByChain(ctx context.Context, parentID string, caller Caller) (*Document, error) {
	body := map[string]any{"parent_id": parentID, "caller_sub": caller.Sub}
	putOpt(body, "caller_serial", caller.Serial)

	data, err := p.call(ctx, "document.get_latest_signed_pdf_by_chain", body)
	if err != nil {
		return nil, err
	}

	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("store: get_latest_signed_pdf_by_chain: decode: %w", err)
	}

	return &d, nil
}

// List returns the documents the caller may read via document.list (ACL-scoped).
func (p *Postgres) List(ctx context.Context, caller Caller, limit int, after string) ([]*Document, error) {
	body := map[string]any{"caller_sub": caller.Sub}
	putOpt(body, "caller_serial", caller.Serial)
	if limit > 0 {
		body["limit"] = limit
	}
	putOpt(body, "after", after)

	data, err := p.call(ctx, "document.list", body)
	if err != nil {
		return nil, err
	}

	var res struct {
		Documents []*Document `json:"documents"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: list: decode: %w", err)
	}

	return res.Documents, nil
}

// ListChains returns one live-head row per chain via document.list_chains
// (ACL-scoped like List).
func (p *Postgres) ListChains(ctx context.Context, caller Caller, limit int, after string, includeExpired bool) ([]*Chain, error) {
	body := map[string]any{"caller_sub": caller.Sub}
	putOpt(body, "caller_serial", caller.Serial)
	if limit > 0 {
		body["limit"] = limit
	}
	putOpt(body, "after", after)
	if includeExpired {
		body["include_expired"] = true
	}

	data, err := p.call(ctx, "document.list_chains", body)
	if err != nil {
		return nil, err
	}

	var res struct {
		Chains []*Chain `json:"chains"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: list_chains: decode: %w", err)
	}

	return res.Chains, nil
}

// GetChain returns ONE chain as its live head via document.get_chain, addressed
// by any id in it (ACL-scoped like Get: absent and not-permitted are the same
// answer).
func (p *Postgres) GetChain(ctx context.Context, caller Caller, id string) (*Chain, error) {
	body := map[string]any{"caller_sub": caller.Sub, "id": id}
	putOpt(body, "caller_serial", caller.Serial)

	data, err := p.call(ctx, "document.get_chain", body)
	if err != nil {
		return nil, err
	}

	var res struct {
		Chain *Chain `json:"chain"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: get_chain: decode: %w", err)
	}
	if res.Chain == nil {
		return nil, ErrNotFound
	}

	return res.Chain, nil
}

// ListHistory returns the owner's terminal chains via document.list_history.
func (p *Postgres) ListHistory(ctx context.Context, owner string, limit int, after string) ([]*HistoryChain, error) {
	body := map[string]any{"caller_sub": owner}
	if limit > 0 {
		body["limit"] = limit
	}
	putOpt(body, "after", after)

	data, err := p.call(ctx, "document.list_history", body)
	if err != nil {
		return nil, err
	}

	var res struct {
		Chains []*HistoryChain `json:"chains"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: list_history: decode: %w", err)
	}

	return res.Chains, nil
}

// SweepHistory hard-deletes terminal metadata rows older than before via
// document.sweep_history.
func (p *Postgres) SweepHistory(ctx context.Context, before time.Time, limit int) (int, error) {
	body := map[string]any{"before": before.UTC().Format(time.RFC3339Nano)}
	if limit > 0 {
		body["limit"] = limit
	}

	data, err := p.call(ctx, "document.sweep_history", body)
	if err != nil {
		return 0, err
	}

	var res struct {
		Removed int `json:"removed"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return 0, fmt.Errorf("store: sweep_history: decode: %w", err)
	}

	return res.Removed, nil
}

// DeleteHistoryChain removes one owned history record via
// document.delete_history_chain.
func (p *Postgres) DeleteHistoryChain(ctx context.Context, owner, chainRootID string) error {
	_, err := p.call(ctx, "document.delete_history_chain",
		map[string]any{"chain_root_id": chainRootID, "caller_sub": owner})

	return err
}

// SetStatus changes an owned document's status via document.set_status.
func (p *Postgres) SetStatus(ctx context.Context, id, caller, status string) error {
	_, err := p.call(ctx, "document.set_status", map[string]any{"id": id, "caller": caller, "status": status})

	return err
}

// SetPreservationClass sets the B4 class via document.set_preservation_class.
func (p *Postgres) SetPreservationClass(ctx context.Context, id, caller, class string) error {
	_, err := p.call(ctx, "document.set_preservation_class",
		map[string]any{"id": id, "caller": caller, "preservation_class": class})

	return err
}

// SetResultFreeze sets/clears the chain download freeze via document.set_result_freeze.
func (p *Postgres) SetResultFreeze(ctx context.Context, id string, frozen bool) error {
	_, err := p.call(ctx, "document.set_result_freeze", map[string]any{"id": id, "frozen": frozen})

	return err
}

// ChainRetention reads a chain's last downloadable instant via
// document.chain_retention. A chain with nothing stored comes back with a null
// instant, which decodes to the zero time — the caller reads that as "there is no
// download left to outlive", not as an error.
func (p *Postgres) ChainRetention(ctx context.Context, id string) (time.Time, int, error) {
	data, err := p.call(ctx, "document.chain_retention", map[string]any{"id": id})
	if err != nil {
		return time.Time{}, 0, err
	}

	var out struct {
		RetentionUntil *time.Time `json:"retentionUntil"`
		LiveRows       int        `json:"liveRows"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return time.Time{}, 0, fmt.Errorf("store: chain_retention: decode: %w", err)
	}
	if out.RetentionUntil == nil {
		return time.Time{}, out.LiveRows, nil
	}

	return out.RetentionUntil.UTC(), out.LiveRows, nil
}

// ExtendRetention rolls retention_until forward via document.extend_retention.
func (p *Postgres) ExtendRetention(ctx context.Context, id, caller string, until time.Time) error {
	_, err := p.call(ctx, "document.extend_retention",
		map[string]any{"id": id, "caller": caller, "retention_until": until.UTC().Format(time.RFC3339Nano)})

	return err
}

// RemoveAccess drops the caller's ACL entry on a document's chain via
// document.remove_access; returns the chain blobs purged when the last entry
// was removed (empty otherwise).
func (p *Postgres) RemoveAccess(ctx context.Context, docID string, caller Caller) ([]PurgedRef, error) {
	body := map[string]any{"doc_id": docID, "caller_sub": caller.Sub}
	putOpt(body, "caller_serial", caller.Serial)

	data, err := p.call(ctx, "document.remove_access", body)
	if err != nil {
		return nil, err
	}

	var res struct {
		Purged []PurgedRef `json:"purged"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: remove_access: decode: %w", err)
	}

	return res.Purged, nil
}

// SweepRetention flips expired non-hold docs via document.sweep_retention.
func (p *Postgres) SweepRetention(ctx context.Context, now time.Time, limit int) ([]PurgedRef, error) {
	body := map[string]any{"now": now.UTC().Format(time.RFC3339Nano)}
	if limit > 0 {
		body["limit"] = limit
	}

	data, err := p.call(ctx, "document.sweep_retention", body)
	if err != nil {
		return nil, err
	}

	var res struct {
		Purged []PurgedRef `json:"purged"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("store: sweep_retention: decode: %w", err)
	}

	return res.Purged, nil
}

// putOpt adds key=val to body only when val is non-empty (so the procedure's
// COALESCE/NULLIF defaults apply for omitted optionals).
func putOpt(body map[string]any, key, val string) {
	if val != "" {
		body[key] = val
	}
}
