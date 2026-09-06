package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stalledMailDelivery struct{ entered chan struct{} }

func (m stalledMailDelivery) SendVerificationEmail(ctx context.Context, _ string, _ string) error {
	m.entered <- struct{}{}
	<-ctx.Done()
	return ctx.Err()
}
func (m stalledMailDelivery) SendPasswordResetEmail(ctx context.Context, email, token string) error {
	return m.SendVerificationEmail(ctx, email, token)
}
func (m stalledMailDelivery) SendEmailChangeEmail(ctx context.Context, email, token string) error {
	return m.SendVerificationEmail(ctx, email, token)
}
func TestMailDispatcherBoundedQueueAndStop(t *testing.T) {
	delivery := stalledMailDelivery{entered: make(chan struct{}, 3)}
	dispatcher := NewMailDispatcher(delivery, 1, 1)
	if err := dispatcher.SendVerificationEmail(context.Background(), "first@example.com", "token"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-delivery.entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	if err := dispatcher.SendVerificationEmail(context.Background(), "second@example.com", "token"); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.SendVerificationEmail(context.Background(), "third@example.com", "token"); !errors.Is(err, ErrMailQueueFull) {
		t.Fatalf("queue was not bounded: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := dispatcher.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stop deadline: %v", err)
	}
	if dispatcher.Unconfirmed() != 2 {
		t.Errorf("lost delivery count=%d", dispatcher.Unconfirmed())
	}
	select {
	case <-dispatcher.done:
	case <-time.After(time.Second):
		t.Fatal("canceled workers did not stop")
	}
	if err := dispatcher.SendVerificationEmail(context.Background(), "late@example.com", "token"); !errors.Is(err, ErrMailDispatcherStopped) {
		t.Fatalf("stopped queue accepted work: %v", err)
	}
	if err := dispatcher.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}
