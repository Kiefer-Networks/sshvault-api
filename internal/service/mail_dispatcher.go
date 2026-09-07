package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
)

var ErrMailQueueFull = errors.New("mail queue is full")
var ErrMailDispatcherStopped = errors.New("mail dispatcher is stopped")

type MailDelivery interface {
	MailSender
	EmailChangeSender
}
type queuedMail struct{ purpose, email, token string }

// MailDispatcher uses a fixed worker count and a bounded, non-blocking queue.
// Request contexts do not own delivery after enqueue; Stop owns its cancellation.
type MailDispatcher struct {
	unconfirmed atomic.Int64
	delivery    MailDelivery
	queue       chan queuedMail
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	stopped     bool
	done        chan struct{}
}

func NewMailDispatcher(delivery MailDelivery, capacity, workers int) *MailDispatcher {
	if capacity < 1 || workers < 1 {
		panic("mail dispatcher requires positive capacity and workers")
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &MailDispatcher{delivery: delivery, queue: make(chan queuedMail, capacity), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).Msg("recovered from panic in mail dispatcher worker")
				}
			}()
			d.work()
		}()
	}
	go func() { wg.Wait(); close(d.done) }()
	return d
}
func (d *MailDispatcher) enqueue(ctx context.Context, purpose, email, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.stopped {
		return ErrMailDispatcherStopped
	}
	d.unconfirmed.Add(1)
	select {
	case d.queue <- queuedMail{purpose, email, token}:
		return nil
	default:
		d.unconfirmed.Add(-1)
		return ErrMailQueueFull
	}
}
func (d *MailDispatcher) SendVerificationEmail(ctx context.Context, email, token string) error {
	return d.enqueue(ctx, "verification", email, token)
}
func (d *MailDispatcher) SendPasswordResetEmail(ctx context.Context, email, token string) error {
	return d.enqueue(ctx, "reset", email, token)
}
func (d *MailDispatcher) SendEmailChangeEmail(ctx context.Context, email, token string) error {
	return d.enqueue(ctx, "change", email, token)
}
func (d *MailDispatcher) work() {
	for message := range d.queue {
		if d.ctx.Err() != nil {
			return
		}
		var err error
		switch message.purpose {
		case "verification":
			err = d.delivery.SendVerificationEmail(d.ctx, message.email, message.token)
		case "reset":
			err = d.delivery.SendPasswordResetEmail(d.ctx, message.email, message.token)
		case "change":
			err = d.delivery.SendEmailChangeEmail(d.ctx, message.email, message.token)
		}
		if err != nil {
			log.Warn().Str("purpose", message.purpose).Msg("mail delivery failed")
		} else {
			d.unconfirmed.Add(-1)
		}
	}
}

// Stop drains queued messages within ctx, then cancels remaining delivery work.
func (d *MailDispatcher) Stop(ctx context.Context) error {
	d.mu.Lock()
	if !d.stopped {
		d.stopped = true
		close(d.queue)
	}
	d.mu.Unlock()
	select {
	case <-d.done:
		d.cancel()
		return nil
	case <-ctx.Done():
		d.cancel()
		return ctx.Err()
	}
}

// Unconfirmed counts accepted messages without a confirmed successful delivery.
func (d *MailDispatcher) Unconfirmed() int64 { return d.unconfirmed.Load() }
