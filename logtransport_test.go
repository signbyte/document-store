package documentstore

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewLogTransportDefaultsNilLogger(t *testing.T) {
	tr := newLogTransport(nil)

	if err := tr.Publish(context.Background(), "topic", "key", []byte(`{}`)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
}

func TestLogTransportPublishLogsTheEvent(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	tr := newLogTransport(zap.New(core))

	payload := []byte(`{"event_type":"document.uploaded"}`)
	if err := tr.Publish(context.Background(), "document.events", "evt-1", payload); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	entries := logs.TakeAll()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}
	if entries[0].Message != "document_event" {
		t.Fatalf("message = %q, want %q", entries[0].Message, "document_event")
	}
	fields := entries[0].ContextMap()
	if fields["topic"] != "document.events" {
		t.Fatalf("topic = %v, want document.events", fields["topic"])
	}
	if fields["key"] != "evt-1" {
		t.Fatalf("key = %v, want evt-1", fields["key"])
	}
}
