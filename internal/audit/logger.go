package audit

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/rs/zerolog/log"
)

// Logger is an async audit logger that buffers entries and writes them
// to the database in a background goroutine.
type EntryWriter interface {
	Insert(context.Context, *Entry) error
}

type Logger struct {
	repo    EntryWriter
	ch      chan *Entry
	done    chan struct{}
	once    sync.Once
	mu      sync.RWMutex
	stopped bool
	dropped atomic.Int64
	lost    atomic.Int64
	unsaved atomic.Int64
	ctx     context.Context
	cancel  context.CancelFunc
	nop     bool
}

// NewLogger creates a new async audit logger with the given buffer size.
func NewLogger(repo EntryWriter, bufferSize int) *Logger {
	if bufferSize <= 0 {
		bufferSize = 4096
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Logger{
		ctx: ctx, cancel: cancel,
		repo: repo,
		ch:   make(chan *Entry, bufferSize),
		done: make(chan struct{}),
	}
	go l.run()
	go l.reportDropped()
	return l
}

// NewNopLogger creates a Logger that silently discards all entries.
// Useful for testing handlers that require a non-nil audit logger.
func NewNopLogger() *Logger { return &Logger{nop: true} }

// run is the background goroutine that processes buffered entries.
func (l *Logger) run() {
	defer close(l.done)
	for entry := range l.ch {
		if l.ctx.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(l.ctx, 5*time.Second)
		if err := l.repo.Insert(ctx, entry); err != nil {
			log.Error().Err(err).
				Str("category", string(entry.Category)).
				Str("action", string(entry.Action)).
				Msg("failed to write audit log")
		} else {
			l.unsaved.Add(-1)
		}
		cancel()
	}
}

// Log sends an entry to the async buffer. Non-blocking: drops the entry
// if the buffer is full and increments the drop counter.
func (l *Logger) Log(entry *Entry) {
	if l.nop {
		return
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.stopped {
		l.lost.Add(1)
		log.Warn().Msg("audit entry rejected after logger shutdown")
		return
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	l.unsaved.Add(1)
	select {
	case l.ch <- entry:
	default:
		l.unsaved.Add(-1)
		l.lost.Add(1)
		l.dropped.Add(1)
	}
}

// reportDropped periodically logs the count of dropped entries.
func (l *Logger) reportDropped() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			if n := l.dropped.Swap(0); n > 0 {
				log.Warn().Int64("count", n).Msg("audit log entries dropped due to full buffer")
			}
		}
	}
}

// Stop drains within the shared process deadline. The count includes dropped,
// failed, and still-unconfirmed entries; an uncooperative in-flight writer may
// finish later, so its persistence cannot be claimed at deadline expiry.
func (l *Logger) Stop(ctx context.Context) (int64, error) {
	if l.nop {
		return 0, nil
	}
	l.once.Do(func() { l.mu.Lock(); l.stopped = true; close(l.ch); l.mu.Unlock() })
	select {
	case <-l.done:
		l.cancel()
		n := l.unsaved.Load() + l.lost.Load()
		if n > 0 {
			return n, fmt.Errorf("%d audit entries were not confirmed written", n)
		}
		return 0, nil
	case <-ctx.Done():
		l.cancel()
		return l.unsaved.Load() + l.lost.Load(), ctx.Err()
	}
}

// EntryBuilder provides a fluent API for constructing audit entries.
type EntryBuilder struct {
	entry  *Entry
	logger *Logger
}

// LogFromRequest creates a new EntryBuilder pre-populated with request context.
func (l *Logger) LogFromRequest(r *http.Request, category Category, action Action) *EntryBuilder {
	entry := &Entry{
		Category: category,
		Action:   action,
		Level:    LevelInfo,
	}

	// Extract request ID from context
	if reqID, ok := r.Context().Value(middleware.RequestIDKey).(string); ok {
		entry.RequestID = reqID
	}

	// Extract user ID from context
	if userID, ok := middleware.GetUserID(r.Context()); ok {
		entry.ActorID = &userID
	}

	// User-Agent from request (IP intentionally not stored — zero-knowledge)
	entry.UserAgent = r.UserAgent()

	return &EntryBuilder{entry: entry, logger: l}
}

// Level sets the log level.
func (b *EntryBuilder) Level(level Level) *EntryBuilder {
	b.entry.Level = level
	return b
}

// Actor sets the actor ID and email.
func (b *EntryBuilder) Actor(id uuid.UUID, email string) *EntryBuilder {
	b.entry.ActorID = &id
	b.entry.ActorEmail = email
	return b
}

// Resource sets the resource type and ID.
func (b *EntryBuilder) Resource(typ string, id string) *EntryBuilder {
	b.entry.ResourceType = typ
	b.entry.ResourceID = id
	return b
}

// Detail adds a key-value pair to the details map.
func (b *EntryBuilder) Detail(key string, value any) *EntryBuilder {
	if b.entry.Details == nil {
		b.entry.Details = map[string]any{}
	}
	b.entry.Details[key] = value
	return b
}

// Duration sets the operation duration.
func (b *EntryBuilder) Duration(d time.Duration) *EntryBuilder {
	ms := int(d.Milliseconds())
	b.entry.DurationMS = &ms
	return b
}

// Send dispatches the entry to the async logger.
func (b *EntryBuilder) Send() {
	b.logger.Log(b.entry)
}
