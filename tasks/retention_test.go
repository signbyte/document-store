package tasks

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/signbyte/document-store/audit"
	"github.com/signbyte/document-store/documents"
	"github.com/signbyte/document-store/kms"
	"github.com/signbyte/document-store/s3"
	"github.com/signbyte/document-store/store"
)

func newTestServiceAndRecorder(t *testing.T, ttl time.Duration) (*documents.Service, *audit.Recorder) {
	t.Helper()

	k, _, err := kms.NewLocal(nil)
	if err != nil {
		t.Fatalf("kms.NewLocal: %v", err)
	}
	svc := documents.New(store.NewMemory(), s3.NewMemory(), k, ttl)
	rec := audit.New(nil, nil, nil, "", nil) // sec/gdpr/pub off — RetentionSwept no-ops

	return svc, rec
}

func TestRetentionTaskName(t *testing.T) {
	task := NewRetentionTask(RetentionConfig{})
	if got := task.Name(); got != "document-retention" {
		t.Fatalf("Name() = %q, want %q", got, "document-retention")
	}
}

func TestRunOnceSweepsAllExpiredAcrossBatches(t *testing.T) {
	svc, rec := newTestServiceAndRecorder(t, -time.Second) // every ingest is immediately expired
	ctx := context.Background()

	const n = 5
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		doc, err := svc.Ingest(ctx, documents.IngestInput{Owner: "o", Data: []byte("bytes")})
		if err != nil {
			t.Fatalf("Ingest: %v", err)
		}
		ids = append(ids, doc.ID)
	}

	task := NewRetentionTask(RetentionConfig{Service: svc, Audit: rec, Batch: 2}).(*retentionTask)
	task.runOnce(ctx)

	for _, id := range ids {
		if _, _, err := svc.Content(ctx, id, store.Caller{Sub: "o"}); !errors.Is(err, documents.ErrGone) {
			t.Fatalf("Content(%s) after sweep: err = %v, want ErrGone", id, err)
		}
	}
}

func TestRunOnceLeavesUnexpiredDocumentsAlone(t *testing.T) {
	svc, rec := newTestServiceAndRecorder(t, time.Hour) // not yet expired
	ctx := context.Background()

	doc, err := svc.Ingest(ctx, documents.IngestInput{Owner: "o", Data: []byte("bytes")})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	task := NewRetentionTask(RetentionConfig{Service: svc, Audit: rec}).(*retentionTask)
	task.runOnce(ctx)

	if _, _, err := svc.Content(ctx, doc.ID, store.Caller{Sub: "o"}); err != nil {
		t.Fatalf("Content after no-op sweep: err = %v, want nil", err)
	}
}

func TestRunOnceDefaultsBatchWhenUnset(t *testing.T) {
	svc, rec := newTestServiceAndRecorder(t, -time.Second)
	ctx := context.Background()

	if _, err := svc.Ingest(ctx, documents.IngestInput{Owner: "o", Data: []byte("bytes")}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// Batch left at zero must fall back to the internal default rather than
	// looping forever or sweeping nothing.
	task := NewRetentionTask(RetentionConfig{Service: svc, Audit: rec}).(*retentionTask)
	task.runOnce(ctx)
}

func TestStartAndStopRunsSweepOnSchedule(t *testing.T) {
	svc, rec := newTestServiceAndRecorder(t, -time.Second)
	ctx := context.Background()

	doc, err := svc.Ingest(ctx, documents.IngestInput{Owner: "o", Data: []byte("bytes")})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	task := NewRetentionTask(RetentionConfig{Service: svc, Audit: rec, Interval: time.Hour})
	if err := task.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer task.Stop()

	// Start runs an initial sweep synchronously-ish in its own goroutine; poll
	// briefly rather than sleep a fixed guess.
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, _, err := svc.Content(ctx, doc.ID, store.Caller{Sub: "o"})
		if errors.Is(err, documents.ErrGone) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("initial sweep did not purge the expired document in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStopWithoutStartIsSafe(t *testing.T) {
	task := NewRetentionTask(RetentionConfig{})
	task.Stop() // ticker is nil — must not panic or block
}
