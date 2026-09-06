package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type pendingWork struct{ count atomic.Int64 }

func (w *pendingWork) Unconfirmed() int64 { return w.count.Load() }

func TestShutdownReportsBeforeReturningWithCleanupStillBlocked(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	release, cleanupDone := make(chan struct{}), make(chan struct{})
	defer func() { close(release); <-cleanupDone }()
	var reports atomic.Int32
	var output bytes.Buffer
	auditWork, mailWork := &pendingWork{}, &pendingWork{}
	auditWork.count.Store(3)
	mailWork.count.Store(2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err = serveHTTPWithTimeout(ctx, &http.Server{}, listener, func(ctx context.Context) error {
		defer close(cleanupDone)
		<-ctx.Done()
		<-release // Stop has not returned and cannot emit its own final report.
		return ctx.Err()
	}, 50*time.Millisecond, func() {
		reports.Add(1)
		reportShutdownLosses(zerolog.New(&output), auditWork, mailWork)
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v", err)
	}
	if got := reports.Load(); got != 1 {
		t.Errorf("final reports before process exit = %d, want 1", got)
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Error("accounting waited for blocked cleanup")
	}
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event["unconfirmed_entries"] != float64(3) || event["unconfirmed_messages"] != float64(2) {
		t.Fatalf("missing final accounting: %s", output.String())
	}
}

func TestShutdownDoesNotReportLossForConfirmedWork(t *testing.T) {
	var output bytes.Buffer
	reportShutdownLosses(zerolog.New(&output), &pendingWork{}, &pendingWork{})
	if output.Len() != 0 {
		t.Fatalf("misleading loss report: %s", output.String())
	}
}
