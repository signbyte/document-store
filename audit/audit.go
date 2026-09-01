// Package audit records the document-store service's audit events across the
// platform regimes it participates in:
//
// - GDPR-audit (GDPR personal-data access) via go-gdpr-audit → access-audit: on
// every DECRYPTED-bytes retrieval (/content) and any PII reveal. The data
// subject is the document owner's identity `sub` (already a pseudonymous
// internal identity ref from authbyte-core — never a national id). Optional —
// wired only when access-audit is configured.
// - NIS2-audit (NIS2 security telemetry) via go-sec-events → SIEM: authZ denials,
// cap-exceeded, IDOR attempts, integrity failures, ingest/delete outcomes.
// - Document domain events (uploaded/deleted) → broker: the Signing Orchestrator
// is the eIDAS-audit producer that lands MATERIAL events on the eidas-audit
// chain. The Document Service does NOT write the eidas_audit
// chain directly (cross-team contract). Published with CategorySigning (a
// signing-domain lifecycle event) when a broker transport is configured.
//
// All request-path methods take the *azugo.Context (correlation/GDPR-audit/domain
// publish need it); the background retention sweep takes the security library's
// background path instead, which has no request to correlate against.
package audit

import (
	"context"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"

	"github.com/signbyte/document-store/store"
)

// NIS2-audit security event types.
const (
	EventAuthzDenied      = "authz.denied" // platform-standard type (via secevents.AuthZDenied)
	EventIngest           = "document.ingest"
	EventDelete           = "document.delete"
	EventCapExceeded      = "document.cap_exceeded"
	EventIDORAttempt      = "document.idor_attempt"
	EventIntegrityFailure = "document.integrity_failure"
	EventRetentionSwept   = "document.retention_swept"
)

// Document domain (lifecycle) event types — published to the broker for the
// Signing Orchestrator's eIDAS-audit.
const (
	EventDocUploaded = "document.uploaded"
	EventDocDeleted  = "document.deleted"
)

// Recorder emits the regimes. sec is required; gdpr (GDPR-audit) and pub (domain
// events) are optional (nil → that channel no-ops).
type Recorder struct {
	sec   *secevents.Emitter
	gdpr  *gdpr.Client
	pub   *broker.Publisher
	topic string
	log   *zap.Logger
}

// New builds a Recorder. log may be nil.
func New(sec *secevents.Emitter, gdprClient *gdpr.Client, pub *broker.Publisher, topic string, log *zap.Logger) *Recorder {
	if log == nil {
		log = zap.NewNop()
	}

	return &Recorder{sec: sec, gdpr: gdprClient, pub: pub, topic: topic, log: log}
}

// logger returns the request-correlated logger when a request context is present —
// so a fallback/diagnostic line is joinable to its request by correlation id +
// trace id — else the component logger for a context-free background path.
func (r *Recorder) logger(ctx *azugo.Context) *zap.Logger {
	if ctx != nil {
		return ctx.Log()
	}

	return r.log
}

// ---- NIS2-audit — security telemetry -----------------------------------------

// Denied records a scope/authZ denial on a document endpoint.
func (r *Recorder) Denied(ctx *azugo.Context, caller, requiredScope string) {
	if r == nil || r.sec == nil {
		return
	}
	if err := r.sec.AuthZDenied(ctx, secevents.Denial{
		Actor:         broker.Actor{ID: caller, Type: "service"},
		RequiredScope: requiredScope,
		Reason:        "missing scope",
	}); err != nil {
		r.logger(ctx).Error("secevents denied emit failed", zap.Error(err))
	}
}

// IngestOutcome records the outcome of an ingest.
func (r *Recorder) IngestOutcome(ctx *azugo.Context, caller string, success bool) {
	r.security(ctx, EventIngest, caller, secevents.SeverityInfo, outcomeOf(success), nil)
}

// DeleteOutcome records the outcome of a manual delete.
func (r *Recorder) DeleteOutcome(ctx *azugo.Context, caller string, success bool) {
	r.security(ctx, EventDelete, caller, secevents.SeverityInfo, outcomeOf(success), nil)
}

// CapExceeded records an upload that exceeded MAX_FILE_BYTES.
func (r *Recorder) CapExceeded(ctx *azugo.Context, caller string) {
	r.security(ctx, EventCapExceeded, caller, secevents.SeverityWarning, broker.OutcomeDenied, nil)
}

// IDORAttempt records a read/mutate of a document the caller does not own (the
// store returns the same :not_found, but the attempt is worth a SIEM signal).
func (r *Recorder) IDORAttempt(ctx *azugo.Context, caller, documentID string) {
	r.security(ctx, EventIDORAttempt, caller, secevents.SeverityWarning, broker.OutcomeDenied,
		map[string]any{"document_id": documentID})
}

// IntegrityFailure records a decrypt/packaging integrity failure (high severity).
func (r *Recorder) IntegrityFailure(ctx *azugo.Context, caller, detail string) {
	r.security(ctx, EventIntegrityFailure, caller, secevents.SeverityHigh, broker.OutcomeFailure,
		map[string]any{"detail": detail})
}

// RetentionSwept records a background retention sweep (no request behind it).
// Anything purged is informational; an error path logs separately.
func (r *Recorder) RetentionSwept(purged int) {
	r.security(nil, EventRetentionSwept, "", secevents.SeverityInfo, broker.OutcomeSuccess,
		map[string]any{"purged": purged})
}

// security emits one NIS2-audit event, supporting a nil ctx for background work
// (the security library's own background path).
func (r *Recorder) security(ctx *azugo.Context, eventType, caller string, sev secevents.Severity, outcome broker.Outcome, attrs map[string]any) {
	if r == nil || r.sec == nil {
		return
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs[secevents.AttrSeverity] = string(sev)

	ev := &broker.Envelope{
		EventType:  eventType,
		Categories: []broker.Category{broker.CategorySecurity},
		Outcome:    outcome,
		Attributes: attrs,
	}
	if caller != "" {
		ev.Actor = &broker.Actor{ID: caller, Type: "service"}
	}

	if ctx != nil {
		if err := r.sec.Emit(ctx, ev); err != nil {
			r.logger(ctx).Error("security event emission failed", zap.String("event_type", eventType), zap.Error(err))
		}

		return
	}

	// The retention sweep has no request. Same tagging, sanitizing, stamping and
	// rendered shape; only the correlation ids are absent, because there is no
	// request to take them from.
	if err := r.sec.EmitBackground(context.Background(), ev); err != nil {
		r.log.Error("security event emission failed", zap.String("event_type", eventType), zap.Error(err))
	}
}

// ---- GDPR-audit — GDPR personal-data access ----------------------------------

// DocumentAccessed records a decrypted-bytes retrieval (or any PII reveal). owner
// is the document owner's identity `sub` (a pseudonymous internal ref). No-op when
// GDPR-audit is off. Routine / fail-open — never breaks the read on audit
// back-pressure.
func (r *Recorder) DocumentAccessed(ctx *azugo.Context, caller, owner, documentID string) {
	if r == nil || r.gdpr == nil || owner == "" {
		return
	}
	err := r.gdpr.Record(ctx, gdpr.EventDocumentAccess, gdpr.Access{
		Actor:        broker.Actor{ID: caller, Type: "service"},
		DataSubjects: []string{owner},
		Resource:     broker.Resource{Type: "document", ID: documentID},
		Operation:    broker.OpRead,
		LawfulBasis:  gdpr.BasisContract,
		Purpose:      gdpr.PurposeSigning,
		Channel:      gdpr.ChannelBackground,
	})
	if err != nil {
		r.logger(ctx).Warn("gdpr access record not persisted (non-fatal)", zap.Error(err))
	}
}

// ---- Document domain events (broker → Orchestrator eIDAS-audit) ----------------

// Uploaded publishes document.uploaded. No-op without a broker publisher.
func (r *Recorder) Uploaded(ctx *azugo.Context, caller string, doc *store.Document) {
	r.domain(ctx, EventDocUploaded, caller, broker.OpCreate, doc)
}

// Deleted publishes document.deleted. No-op without a broker publisher.
func (r *Recorder) Deleted(ctx *azugo.Context, caller string, doc *store.Document) {
	r.domain(ctx, EventDocDeleted, caller, broker.OpDelete, doc)
}

func (r *Recorder) domain(ctx *azugo.Context, eventType, caller string, op broker.Operation, doc *store.Document) {
	if r == nil || r.pub == nil || doc == nil {
		return
	}
	ev := &broker.Envelope{
		EventType:  eventType,
		Categories: []broker.Category{broker.CategorySigning}, // signing-domain lifecycle event
		Actor:      &broker.Actor{ID: caller, Type: "service"},
		Resource:   &broker.Resource{Type: "document", ID: doc.ID},
		Operation:  op,
		Outcome:    broker.OutcomeSuccess,
		Attributes: map[string]any{
			"kind":               doc.Kind,
			"content_hash":       doc.ContentHash, // a digest, not content — safe
			"mime":               doc.Mime,
			"size":               doc.Size,
			"preservation_class": doc.PreservationClass,
		},
	}
	if doc.ParentID != "" {
		ev.Attributes["parent_id"] = doc.ParentID
	}
	if err := r.pub.Publish(ctx, r.topic, ev); err != nil {
		r.logger(ctx).Warn("document domain event not published (non-fatal)",
			zap.String("event_type", eventType), zap.Error(err))
	}
}

func outcomeOf(success bool) broker.Outcome {
	if success {
		return broker.OutcomeSuccess
	}

	return broker.OutcomeFailure
}
