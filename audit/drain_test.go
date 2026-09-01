package audit

import (
	"context"
	"testing"

	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/broker"
)

func TestDrainTaskName(t *testing.T) {
	task := NewDrainTask(nil)
	if got := task.Name(); got != "gdpr-audit-drain" {
		t.Fatalf("Name() = %q, want %q", got, "gdpr-audit-drain")
	}
}

// TestDrainTaskStartStop proves the Tasker lifecycle (background outbox drain
// + a bounded flush-and-close on shutdown) runs without hanging or panicking
// against a real gdpr.Client backed by a local, no-op Poster.
func TestDrainTaskStartStop(t *testing.T) {
	client, err := gdpr.New(gdprTestConfig(), gdpr.PosterFunc(func(context.Context, *broker.Envelope) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("gdpr.New: %v", err)
	}

	task := NewDrainTask(client)
	if err := task.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	task.Stop()
}
