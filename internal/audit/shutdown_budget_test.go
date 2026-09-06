package audit

import (
	"context"
	"testing"
	"time"
)

type stuckAuditWriter struct{ entered, release chan struct{} }

func (w *stuckAuditWriter) Insert(context.Context, *Entry) error {
	close(w.entered)
	<-w.release
	return nil
}
func TestAuditStopBoundsNeverReturningRepositoryAndReportsUnconfirmed(t *testing.T) {
	writer := &stuckAuditWriter{make(chan struct{}), make(chan struct{})}
	defer close(writer.release)
	logger := NewLogger(writer, 16)
	logger.Log(&Entry{Category: CatSystem})
	<-writer.entered
	logger.Log(&Entry{Category: CatSystem})
	logger.Log(&Entry{Category: CatSystem})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	pending, err := logger.Stop(ctx)
	if err == nil || pending != 3 {
		t.Fatalf("stop pending=%d err=%v", pending, err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("audit drain exceeded its total deadline")
	}
	logger.Log(&Entry{Category: CatSystem})
}
