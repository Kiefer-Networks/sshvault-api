package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
)

// mockRepo collects inserted entries for assertion.
type mockRepo struct {
	mu      sync.Mutex
	entries []*Entry
	err     error
}

func (m *mockRepo) Insert(_ context.Context, e *Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.entries = append(m.entries, e)
	return nil
}

func (m *mockRepo) getEntries() []*Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*Entry, len(m.entries))
	copy(cp, m.entries)
	return cp
}

// newTestLogger creates a Logger backed by a mockRepo.
// Uses a real Logger but with an injected mock for the insert path.
func newTestLogger(bufSize int) (*Logger, *mockRepo) {
	mock := &mockRepo{}
	l := &Logger{
		repo: nil, // won't be used directly
		ch:   make(chan *Entry, bufSize),
		done: make(chan struct{}),
	}
	// Override the run goroutine to use mock
	go func() {
		defer close(l.done)
		for entry := range l.ch {
			_ = mock.Insert(context.Background(), entry)
		}
	}()
	return l, mock
}

func TestLoggerBuffersAndSends(t *testing.T) {
	l, mock := newTestLogger(16)

	l.Log(&Entry{Category: CatAuth, Action: ActLogin})
	l.Log(&Entry{Category: CatVault, Action: ActSyncPush})

	l.Stop()

	entries := mock.getEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Category != CatAuth {
		t.Errorf("expected CatAuth, got %s", entries[0].Category)
	}
	if entries[1].Action != ActSyncPush {
		t.Errorf("expected ActSyncPush, got %s", entries[1].Action)
	}
}

func TestLoggerBufferFull(t *testing.T) {
	l, mock := newTestLogger(1)

	// Fill buffer — the goroutine may or may not have consumed the first yet
	// so send enough to guarantee at least one drop
	for i := 0; i < 100; i++ {
		l.Log(&Entry{Category: CatAuth, Action: ActLogin})
	}

	l.Stop()

	// We should have received some but likely not all 100
	entries := mock.getEntries()
	if len(entries) == 0 {
		t.Fatal("expected at least 1 entry to be processed")
	}
	// With a buffer of 1, it's very likely some were dropped
	// (depends on goroutine scheduling, so we just verify non-zero processing)
}

func TestLoggerStopDrains(t *testing.T) {
	l, mock := newTestLogger(100)

	for i := 0; i < 50; i++ {
		l.Log(&Entry{Category: CatSystem, Action: ActStartup})
	}

	l.Stop()

	entries := mock.getEntries()
	if len(entries) != 50 {
		t.Fatalf("expected 50 entries after drain, got %d", len(entries))
	}
}

func TestLoggerStopIdempotent(t *testing.T) {
	l, _ := newTestLogger(16)

	l.Log(&Entry{Category: CatSystem, Action: ActStartup})

	// Multiple Stop calls should not panic
	l.Stop()
	l.Stop()
	l.Stop()
}

func TestLogSetsTimestamp(t *testing.T) {
	l, mock := newTestLogger(16)

	before := time.Now()
	l.Log(&Entry{Category: CatAuth, Action: ActLogin})
	l.Stop()

	entries := mock.getEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Timestamp.Before(before) {
		t.Error("timestamp should be >= before")
	}
}

func TestEntryBuilderSetsAllFields(t *testing.T) {
	l, mock := newTestLogger(16)

	actorID := uuid.New()
	dur := 42 * time.Millisecond

	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.Header.Set("User-Agent", "TestAgent/1.0")

	l.LogFromRequest(r, CatVault, ActSyncPush).
		Level(LevelWarn).
		Actor(actorID, "test@example.com").
		Resource("vault", "res-123").
		Detail("key1", "value1").
		Detail("key2", 42).
		Duration(dur).
		Send()

	l.Stop()

	entries := mock.getEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.Category != CatVault {
		t.Errorf("category = %s, want VAULT", e.Category)
	}
	if e.Action != ActSyncPush {
		t.Errorf("action = %s, want SYNC_PUSH", e.Action)
	}
	if e.Level != LevelWarn {
		t.Errorf("level = %s, want warn", e.Level)
	}
	if e.ActorID == nil || *e.ActorID != actorID {
		t.Errorf("actorID = %v, want %s", e.ActorID, actorID)
	}
	if e.ActorEmail != "test@example.com" {
		t.Errorf("actorEmail = %s, want test@example.com", e.ActorEmail)
	}
	if e.ResourceType != "vault" {
		t.Errorf("resourceType = %s, want vault", e.ResourceType)
	}
	if e.ResourceID != "res-123" {
		t.Errorf("resourceID = %s, want res-123", e.ResourceID)
	}
	if e.Details["key1"] != "value1" {
		t.Errorf("details[key1] = %v, want value1", e.Details["key1"])
	}
	if e.DurationMS == nil || *e.DurationMS != 42 {
		t.Errorf("durationMS = %v, want 42", e.DurationMS)
	}
	if e.UserAgent != "TestAgent/1.0" {
		t.Errorf("userAgent = %s, want TestAgent/1.0", e.UserAgent)
	}
}

func TestLogFromRequestExtractsContext(t *testing.T) {
	l, mock := newTestLogger(16)

	userID := uuid.New()
	reqID := "test-request-123"

	r := httptest.NewRequest(http.MethodPost, "/v1/vault", nil)
	r.Header.Set("User-Agent", "Flutter/3.0")

	// Set context values like the middleware would
	ctx := context.WithValue(r.Context(), middleware.RequestIDKey, reqID)
	ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
	r = r.WithContext(ctx)

	l.LogFromRequest(r, CatVault, ActSyncPull).Send()
	l.Stop()

	entries := mock.getEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.RequestID != reqID {
		t.Errorf("requestID = %s, want %s", e.RequestID, reqID)
	}
	if e.ActorID == nil || *e.ActorID != userID {
		t.Errorf("actorID = %v, want %s", e.ActorID, userID)
	}
	if e.UserAgent != "Flutter/3.0" {
		t.Errorf("userAgent = %s, want Flutter/3.0", e.UserAgent)
	}
}
