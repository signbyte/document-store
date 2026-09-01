// Package tasks holds the document-store background tasks. The retention task is
// the operational half of the 24h-TTL invariant (B2): on a schedule it sweeps
// documents whose retention_until has passed (and that are not under legal hold),
// destroying their S3 object + KMS data key and flipping the row to "expired", so
// minimized/deleted-on-TTL is enforced without an operator.
package tasks

import (
	"context"
	"time"

	"azugo.io/core"
	"go.uber.org/zap"

	"github.com/signbyte/document-store/audit"
	"github.com/signbyte/document-store/documents"
)

// RetentionConfig wires the retention task's dependencies. HistoryKeep is how
// long a terminal chain's metadata record stays readable as history after its
// storage is destroyed — older records are erased on the same schedule (zero
// disables the erasure).
type RetentionConfig struct {
	Service     *documents.Service
	Audit       *audit.Recorder
	Interval    time.Duration
	Batch       int
	HistoryKeep time.Duration
	Logger      *zap.Logger
}

type retentionTask struct {
	cfg    RetentionConfig
	ticker *time.Ticker
	stop   chan bool
}

// NewRetentionTask returns the retention sweep task.
func NewRetentionTask(cfg RetentionConfig) core.Tasker {
	return &retentionTask{cfg: cfg}
}

func (t *retentionTask) Name() string { return "document-retention" }

func (t *retentionTask) Start(ctx context.Context) error {
	t.stop = make(chan bool)
	t.ticker = time.NewTicker(t.cfg.Interval)

	go func() {
		t.runOnce(ctx) // initial sweep on start
		for {
			select {
			case <-t.stop:
				return
			case <-t.ticker.C:
				t.runOnce(ctx)
			}
		}
	}()

	return nil
}

func (t *retentionTask) Stop() {
	if t.ticker != nil {
		t.ticker.Stop()
		t.stop <- true
		t.ticker = nil
	}
}

// runOnce performs one sweep, purging expired non-hold documents in batches until
// a batch returns fewer than requested (drained).
func (t *retentionTask) runOnce(ctx context.Context) {
	now := time.Now().UTC()
	batch := t.cfg.Batch
	if batch <= 0 {
		batch = 500
	}

	total := 0
	for {
		n, err := t.cfg.Service.Sweep(ctx, now, batch)
		if err != nil {
			t.log().Error("retention sweep failed", zap.Error(err))

			return
		}
		total += n
		if n < batch {
			break
		}
	}

	if total > 0 {
		t.cfg.Audit.RetentionSwept(total)
		t.log().Info("retention sweep complete", zap.Int("purged", total))
	}

	// Second stage: erase terminal metadata records older than the history keep
	// window (the bytes are long gone; this removes the record itself).
	if t.cfg.HistoryKeep <= 0 {
		return
	}
	erased := 0
	for {
		n, err := t.cfg.Service.SweepHistory(ctx, now.Add(-t.cfg.HistoryKeep), batch)
		if err != nil {
			t.log().Error("history sweep failed", zap.Error(err))

			return
		}
		erased += n
		if n < batch {
			break
		}
	}
	if erased > 0 {
		t.log().Info("history sweep complete", zap.Int("erased", erased))
	}
}

func (t *retentionTask) log() *zap.Logger {
	if t.cfg.Logger != nil {
		return t.cfg.Logger
	}

	return zap.NewNop()
}
