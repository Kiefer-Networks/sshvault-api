package audit

import (
	"context"
	"net"
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
type Logger struct {
	repo    *Repository
	ch      chan *Entry
	done    chan struct{}
	once    sync.Once
	dropped atomic.Int64
}

// NewLogger creates a new async audit logger with the given buffer size.
func NewLogger(repo *Repository, bufferSize int) *Logger {
	if bufferSize <= 0 {
		bufferSize = 4096
	}
	l := &Logger{
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
func NewNopLogger() *Logger {
	l := &Logger{
		ch:   make(chan *Entry, 1024),
		done: make(chan struct{}),
	}
	go func() {
		defer close(l.done)
		for range l.ch {
			// discard
		}
	}()
	return l
}

// run is the background goroutine that processes buffered entries.
func (l *Logger) run() {
	defer close(l.done)
	for entry := range l.ch {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := l.repo.Insert(ctx, entry); err != nil {
			log.Error().Err(err).
				Str("category", string(entry.Category)).
				Str("action", string(entry.Action)).
				Msg("failed to write audit log")
		}
		cancel()
	}
}

// Log sends an entry to the async buffer. Non-blocking: drops the entry
// if the buffer is full and increments the drop counter.
func (l *Logger) Log(entry *Entry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	select {
	case l.ch <- entry:
	default:
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
		case <-ticker.C:
			if n := l.dropped.Swap(0); n > 0 {
				log.Warn().Int64("count", n).Msg("audit log entries dropped due to full buffer")
			}
		}
	}
}

// Stop drains the buffer and waits for all pending entries to be written.
func (l *Logger) Stop() {
	l.once.Do(func() {
		close(l.ch)
		<-l.done
	})
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

	// IP (strip port) and User-Agent from request
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr // fallback if no port
	}
	entry.IPAddress = ip
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
