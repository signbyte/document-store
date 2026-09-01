package audit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"

	"github.com/signbyte/document-store/store"
)

// withCtx runs fn inside a real request handler so it receives a fully
// initialized *azugo.Context — MockContext supplies a nil request and is
// unusable for context operations (mirrors go-platform-kit/broker's own test
// helper).
func withCtx(t *testing.T, fn func(ctx *azugo.Context)) {
	t.Helper()

	app := azugo.NewTestApp()
	app.Get("/t", func(ctx *azugo.Context) {
		fn(ctx)
		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/t")
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	fasthttp.ReleaseResponse(resp)
}

// capturingSink is a secevents.Sink test double that records every envelope
// handed to it instead of writing to a logger/SIEM. It implements the background
// half too, so both paths are observable through the same double.
type capturingSink struct {
	events []*broker.Envelope
}

func (s *capturingSink) Emit(_ *azugo.Context, ev *broker.Envelope) error {
	s.events = append(s.events, ev)

	return nil
}

func (s *capturingSink) EmitBackground(_ context.Context, ev *broker.Envelope) error {
	s.events = append(s.events, ev)

	return nil
}

// failingSink always rejects delivery, to exercise the emit-failure fallback.
type failingSink struct{ err error }

func (s *failingSink) Emit(*azugo.Context, *broker.Envelope) error { return s.err }

// capturingTransport is a broker.Transport test double for the domain-event
// publisher.
type capturingTransport struct {
	topic, key string
	payload    []byte
}

func (t *capturingTransport) Publish(_ context.Context, topic, key string, payload []byte) error {
	t.topic, t.key, t.payload = topic, key, payload

	return nil
}

func gdprTestConfig() gdpr.Configuration {
	return gdpr.Configuration{
		Endpoint:         "http://example.invalid",
		Audience:         "svc:access-audit",
		Scope:            "access-audit:write",
		Timeout:          gdpr.DefaultTimeout,
		OutboxCapacity:   gdpr.DefaultOutboxCapacity,
		MaxRetries:       gdpr.DefaultMaxRetries,
		RetryBackoff:     gdpr.DefaultRetryBackoff,
		BreakerThreshold: gdpr.DefaultBreakerThreshold,
		BreakerCooldown:  gdpr.DefaultBreakerCooldown,
	}
}

func TestNewDefaultsNilLoggerToNop(t *testing.T) {
	rec := New(nil, nil, nil, "", nil)
	if rec.log == nil {
		t.Fatal("New(..., nil) must default log to a non-nil logger")
	}
}

// TestNilRecorderIsSafe proves every method tolerates a nil *Recorder (the
// package doc promises "sec is required; gdpr and pub are optional" — but a
// caller that forgot to wire the recorder at all must not crash the request).
func TestNilRecorderIsSafe(t *testing.T) {
	var rec *Recorder
	doc := &store.Document{ID: "doc-1"}

	withCtx(t, func(ctx *azugo.Context) {
		rec.Denied(ctx, "caller", "scope")
		rec.IngestOutcome(ctx, "caller", true)
		rec.DeleteOutcome(ctx, "caller", false)
		rec.CapExceeded(ctx, "caller")
		rec.IDORAttempt(ctx, "caller", "doc-1")
		rec.IntegrityFailure(ctx, "caller", "detail")
		rec.DocumentAccessed(ctx, "caller", "owner-1", "doc-1")
		rec.Uploaded(ctx, "caller", doc)
		rec.Deleted(ctx, "caller", doc)
	})
	rec.RetentionSwept(3) // background/nil-ctx path
}

// TestNoOpWithoutSubClients proves a Recorder with every sub-client left nil
// (sec/gdpr/pub all off) is inert rather than panicking on the request path.
func TestNoOpWithoutSubClients(t *testing.T) {
	rec := New(nil, nil, nil, "", nil)
	doc := &store.Document{ID: "doc-1"}

	withCtx(t, func(ctx *azugo.Context) {
		rec.Denied(ctx, "caller", "scope")
		rec.IngestOutcome(ctx, "caller", true)
		rec.CapExceeded(ctx, "caller")
		rec.DocumentAccessed(ctx, "caller", "owner-1", "doc-1")
		rec.Uploaded(ctx, "caller", doc)
	})
}

func TestUploadedAndDeletedNoOpOnNilDocument(t *testing.T) {
	tr := &capturingTransport{}
	rec := New(nil, nil, broker.NewPublisher(tr, "document-store"), "document.events", nil)

	withCtx(t, func(ctx *azugo.Context) {
		rec.Uploaded(ctx, "caller", nil)
		rec.Deleted(ctx, "caller", nil)
	})

	if tr.payload != nil {
		t.Fatalf("a nil document must not publish anything; got payload %s", tr.payload)
	}
}

func TestDocumentAccessedNoOpWithoutOwner(t *testing.T) {
	var posted bool
	client, err := gdpr.New(gdprTestConfig(), gdpr.PosterFunc(func(context.Context, *broker.Envelope) error {
		posted = true

		return nil
	}))
	if err != nil {
		t.Fatalf("gdpr.New: %v", err)
	}
	rec := New(nil, client, nil, "", nil)

	withCtx(t, func(ctx *azugo.Context) {
		rec.DocumentAccessed(ctx, "caller", "" /* no owner */, "doc-1")
	})

	if posted {
		t.Fatal("DocumentAccessed with an empty owner must not post a record")
	}
}

// --- background (nil-ctx) NIS2-audit path — exercised via RetentionSwept and
// the unexported security() severity mapping directly. ---

// The background sweep goes THROUGH the sink now, rather than around it. That is
// the point of the change: the service no longer writes the sink's line itself, so
// the two paths cannot drift apart, and a deployment that swapped the sink gets its
// background events wherever it configured them.
func TestSecurityBackgroundPathGoesThroughTheSink(t *testing.T) {
	sink := &capturingSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, "", zap.NewNop())

	rec.RetentionSwept(7)

	if len(sink.events) != 1 {
		t.Fatalf("the background path must go through the sink; got %d events", len(sink.events))
	}
	ev := sink.events[0]
	if ev.EventType != EventRetentionSwept {
		t.Fatalf("event_type = %v, want %v", ev.EventType, EventRetentionSwept)
	}
	if ev.Outcome != broker.OutcomeSuccess {
		t.Fatalf("outcome = %v, want %v", ev.Outcome, broker.OutcomeSuccess)
	}
	// Stamped even without a request, so the event validates and the SIEM can
	// order and deduplicate it.
	if ev.EventID == "" || ev.OccurredAt.IsZero() {
		t.Fatalf("background event not stamped: id=%q occurred_at=%v", ev.EventID, ev.OccurredAt)
	}
	// …but with no request there is no correlation to inherit.
	if ev.CorrelationID != "" {
		t.Fatalf("correlation_id = %q, want empty (there is no request)", ev.CorrelationID)
	}
}

func TestSecurityNoOpWithoutEmitter(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	rec := New(nil, nil, nil, "", zap.New(core))

	rec.RetentionSwept(1)

	if logs.Len() != 0 {
		t.Fatalf("got %d log entries, want 0 (no sec emitter configured)", logs.Len())
	}
}

func TestSecuritySeverityMapsToLogLevel(t *testing.T) {
	cases := []struct {
		sev  secevents.Severity
		want zapcore.Level
	}{
		{secevents.SeverityInfo, zapcore.InfoLevel},
		{secevents.SeverityWarning, zapcore.WarnLevel},
		{secevents.SeverityHigh, zapcore.ErrorLevel},
		{secevents.SeverityCritical, zapcore.ErrorLevel},
	}

	for _, c := range cases {
		core, logs := observer.New(zap.DebugLevel)
		// The real log sink, so this asserts what actually reaches the SIEM: the
		// mapping lives in the library now, and what is service-specific is which
		// severity each event is given.
		rec := New(secevents.NewEmitter(secevents.NewLogSinkFor(zap.New(core))), nil, nil, "", zap.New(core))

		rec.security(nil, "test.event", "caller-1", c.sev, broker.OutcomeSuccess, nil)

		entries := logs.TakeAll()
		if len(entries) != 1 {
			t.Fatalf("severity %s: got %d entries, want 1", c.sev, len(entries))
		}
		if entries[0].Level != c.want {
			t.Fatalf("severity %s: level = %v, want %v", c.sev, entries[0].Level, c.want)
		}
	}
}

// --- request-path (ctx != nil) NIS2-audit path — goes through the sec sink. ---

func TestSecurityRequestPathGoesThroughSink(t *testing.T) {
	sink := &capturingSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, "", nil)

	withCtx(t, func(ctx *azugo.Context) {
		rec.CapExceeded(ctx, "svc:caller")
	})

	if len(sink.events) != 1 {
		t.Fatalf("got %d events, want 1", len(sink.events))
	}
	ev := sink.events[0]
	if ev.EventType != EventCapExceeded {
		t.Fatalf("event_type = %q, want %q", ev.EventType, EventCapExceeded)
	}
	if ev.Outcome != broker.OutcomeDenied {
		t.Fatalf("outcome = %q, want %q", ev.Outcome, broker.OutcomeDenied)
	}
	if ev.Actor == nil || ev.Actor.ID != "svc:caller" {
		t.Fatalf("actor = %+v, want ID=svc:caller", ev.Actor)
	}
}

func TestDeniedRecordsAuthZDenial(t *testing.T) {
	sink := &capturingSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, "", nil)

	withCtx(t, func(ctx *azugo.Context) {
		rec.Denied(ctx, "svc:caller", "documents:write")
	})

	if len(sink.events) != 1 {
		t.Fatalf("got %d events, want 1", len(sink.events))
	}
	if sink.events[0].EventType != string(secevents.EventAuthZDenied) {
		t.Fatalf("event_type = %q, want %q", sink.events[0].EventType, secevents.EventAuthZDenied)
	}
}

func TestIDORAttemptCarriesDocumentID(t *testing.T) {
	sink := &capturingSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, "", nil)

	withCtx(t, func(ctx *azugo.Context) {
		rec.IDORAttempt(ctx, "svc:caller", "doc-42")
	})

	if len(sink.events) != 1 {
		t.Fatalf("got %d events, want 1", len(sink.events))
	}
	if got := sink.events[0].Attributes["document_id"]; got != "doc-42" {
		t.Fatalf("attributes[document_id] = %v, want doc-42", got)
	}
}

func TestIngestAndDeleteOutcomeMapSuccessFailure(t *testing.T) {
	sink := &capturingSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, "", nil)

	withCtx(t, func(ctx *azugo.Context) {
		rec.IngestOutcome(ctx, "caller", true)
		rec.IngestOutcome(ctx, "caller", false)
		rec.DeleteOutcome(ctx, "caller", true)
		rec.DeleteOutcome(ctx, "caller", false)
	})

	if len(sink.events) != 4 {
		t.Fatalf("got %d events, want 4", len(sink.events))
	}
	want := []broker.Outcome{broker.OutcomeSuccess, broker.OutcomeFailure, broker.OutcomeSuccess, broker.OutcomeFailure}
	for i, ev := range sink.events {
		if ev.Outcome != want[i] {
			t.Fatalf("event %d outcome = %q, want %q", i, ev.Outcome, want[i])
		}
	}
}

func TestIntegrityFailureCarriesDetail(t *testing.T) {
	sink := &capturingSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, "", nil)

	withCtx(t, func(ctx *azugo.Context) {
		rec.IntegrityFailure(ctx, "caller", "checksum mismatch")
	})

	if len(sink.events) != 1 {
		t.Fatalf("got %d events, want 1", len(sink.events))
	}
	if got := sink.events[0].Attributes["detail"]; got != "checksum mismatch" {
		t.Fatalf("attributes[detail] = %v, want %q", got, "checksum mismatch")
	}
}

// TestSecurityLogsWhenSinkFails proves a sink error on the request path is
// swallowed (logged, not propagated) — audit emission must never break the
// request it is observing.
func TestSecurityLogsWhenSinkFails(t *testing.T) {
	rec := New(secevents.NewEmitter(&failingSink{err: errors.New("sink down")}), nil, nil, "", nil)

	withCtx(t, func(ctx *azugo.Context) {
		rec.CapExceeded(ctx, "caller") // must not panic despite the sink erroring
	})
}

// --- GDPR-audit (DocumentAccessed) ---

func TestDocumentAccessedPostsAccessRecord(t *testing.T) {
	var got *broker.Envelope
	client, err := gdpr.New(gdprTestConfig(), gdpr.PosterFunc(func(_ context.Context, rec *broker.Envelope) error {
		got = rec

		return nil
	}))
	if err != nil {
		t.Fatalf("gdpr.New: %v", err)
	}
	rec := New(nil, client, nil, "", nil)

	withCtx(t, func(ctx *azugo.Context) {
		rec.DocumentAccessed(ctx, "svc:caller", "owner-1", "doc-1")
	})

	if got == nil {
		t.Fatal("expected an access record to be posted")
	}
	if len(got.DataSubjects) != 1 || got.DataSubjects[0] != "owner-1" {
		t.Fatalf("data_subjects = %v, want [owner-1]", got.DataSubjects)
	}
	if got.Resource == nil || got.Resource.ID != "doc-1" {
		t.Fatalf("resource = %+v, want id=doc-1", got.Resource)
	}
}

func TestDocumentAccessedNoOpWithoutClient(t *testing.T) {
	rec := New(nil, nil, nil, "", nil)

	withCtx(t, func(ctx *azugo.Context) {
		rec.DocumentAccessed(ctx, "caller", "owner-1", "doc-1") // must not panic
	})
}

// --- Document domain events (broker publish for the Orchestrator's eIDAS-audit) ---

func TestUploadedPublishesDomainEvent(t *testing.T) {
	tr := &capturingTransport{}
	rec := New(nil, nil, broker.NewPublisher(tr, "document-store"), "document.events", nil)

	doc := &store.Document{
		ID: "doc-1", Kind: "source", ContentHash: "hash==", Mime: "text/plain", Size: 10,
		PreservationClass: "none", ParentID: "parent-1",
	}

	withCtx(t, func(ctx *azugo.Context) {
		rec.Uploaded(ctx, "svc:caller", doc)
	})

	if tr.topic != "document.events" {
		t.Fatalf("topic = %q, want document.events", tr.topic)
	}

	var decoded broker.Envelope
	if err := json.Unmarshal(tr.payload, &decoded); err != nil {
		t.Fatalf("decode published payload: %v", err)
	}
	if decoded.EventType != EventDocUploaded {
		t.Fatalf("event_type = %q, want %q", decoded.EventType, EventDocUploaded)
	}
	if decoded.Resource == nil || decoded.Resource.ID != "doc-1" {
		t.Fatalf("resource = %+v, want id=doc-1", decoded.Resource)
	}
	if decoded.Attributes["parent_id"] != "parent-1" {
		t.Fatalf("attributes[parent_id] = %v, want parent-1", decoded.Attributes["parent_id"])
	}
}

func TestDeletedPublishesDomainEventWithoutParentID(t *testing.T) {
	tr := &capturingTransport{}
	rec := New(nil, nil, broker.NewPublisher(tr, "document-store"), "document.events", nil)

	doc := &store.Document{ID: "doc-1", Kind: "source", ContentHash: "hash=="}

	withCtx(t, func(ctx *azugo.Context) {
		rec.Deleted(ctx, "svc:caller", doc)
	})

	var decoded broker.Envelope
	if err := json.Unmarshal(tr.payload, &decoded); err != nil {
		t.Fatalf("decode published payload: %v", err)
	}
	if decoded.EventType != EventDocDeleted {
		t.Fatalf("event_type = %q, want %q", decoded.EventType, EventDocDeleted)
	}
	if _, ok := decoded.Attributes["parent_id"]; ok {
		t.Fatalf("attributes must omit parent_id for a chain root, got %v", decoded.Attributes["parent_id"])
	}
}
