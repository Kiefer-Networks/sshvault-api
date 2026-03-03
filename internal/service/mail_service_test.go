package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// --- Mock Mailer ---

type testMailer struct {
	sentEmails []sentEmail
	sendErr    error
}

type sentEmail struct {
	To      string
	Subject string
	Body    string
}

func newTestMailer() *testMailer {
	return &testMailer{}
}

func (m *testMailer) Send(_ context.Context, to, subject, body string) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sentEmails = append(m.sentEmails, sentEmail{To: to, Subject: subject, Body: body})
	return nil
}

// --- NewMailService Tests ---

func TestNewMailServiceDefaults(t *testing.T) {
	svc := NewMailService(newTestMailer(), "", "")

	if svc.appBaseURL != "https://app.sshvault.app" {
		t.Errorf("appBaseURL = %q, want default", svc.appBaseURL)
	}
	if svc.apiBaseURL != "https://api.sshvault.app" {
		t.Errorf("apiBaseURL = %q, want default", svc.apiBaseURL)
	}
}

func TestNewMailServiceCustomURLs(t *testing.T) {
	svc := NewMailService(newTestMailer(), "https://custom-app.example.com", "https://custom-api.example.com")

	if svc.appBaseURL != "https://custom-app.example.com" {
		t.Errorf("appBaseURL = %q, want custom URL", svc.appBaseURL)
	}
	if svc.apiBaseURL != "https://custom-api.example.com" {
		t.Errorf("apiBaseURL = %q, want custom URL", svc.apiBaseURL)
	}
}

func TestNewMailServicePartialDefaults(t *testing.T) {
	svc := NewMailService(newTestMailer(), "https://my-app.example.com", "")

	if svc.appBaseURL != "https://my-app.example.com" {
		t.Errorf("appBaseURL = %q, want custom URL", svc.appBaseURL)
	}
	if svc.apiBaseURL != "https://api.sshvault.app" {
		t.Errorf("apiBaseURL = %q, want default", svc.apiBaseURL)
	}
}

// --- SendVerificationEmail Tests ---

func TestSendVerificationEmailSuccess(t *testing.T) {
	mailer := newTestMailer()
	svc := NewMailService(mailer, "", "https://api.test.com")

	err := svc.SendVerificationEmail(context.Background(), "user@example.com", "verify-token-123")
	if err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}
	if len(mailer.sentEmails) != 1 {
		t.Fatalf("sent emails = %d, want 1", len(mailer.sentEmails))
	}

	email := mailer.sentEmails[0]
	if email.To != "user@example.com" {
		t.Errorf("To = %q, want %q", email.To, "user@example.com")
	}
	if email.Subject != "Verify your ShellVault email" {
		t.Errorf("Subject = %q, want verification subject", email.Subject)
	}
	if !strings.Contains(email.Body, "verify-token-123") {
		t.Error("body should contain the verification token")
	}
	if !strings.Contains(email.Body, "https://api.test.com") {
		t.Error("body should contain the API base URL")
	}
}

func TestSendVerificationEmailUsesAPIBaseURL(t *testing.T) {
	mailer := newTestMailer()
	svc := NewMailService(mailer, "", "https://api.custom.dev")

	err := svc.SendVerificationEmail(context.Background(), "test@example.com", "tok-abc")
	if err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}

	email := mailer.sentEmails[0]
	if !strings.Contains(email.Body, "https://api.custom.dev/v1/auth/verify-email?token=tok-abc") {
		t.Errorf("body should contain full verification URL, got: %s", email.Body[:200])
	}
}

func TestSendVerificationEmailMailerError(t *testing.T) {
	mailer := newTestMailer()
	mailer.sendErr = fmt.Errorf("SMTP connection refused")
	svc := NewMailService(mailer, "", "")

	err := svc.SendVerificationEmail(context.Background(), "user@example.com", "token")
	if err == nil {
		t.Fatal("expected error when mailer fails")
	}
	if !strings.Contains(err.Error(), "sending verification email") {
		t.Errorf("error = %q, want 'sending verification email'", err.Error())
	}
	if !strings.Contains(err.Error(), "SMTP connection refused") {
		t.Errorf("error should wrap original error, got: %q", err.Error())
	}
}

func TestSendVerificationEmailEmptyToken(t *testing.T) {
	mailer := newTestMailer()
	svc := NewMailService(mailer, "", "")

	err := svc.SendVerificationEmail(context.Background(), "user@example.com", "")
	if err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}
	if len(mailer.sentEmails) != 1 {
		t.Fatal("email should still be sent with empty token")
	}
}

func TestSendVerificationEmailEmptyRecipient(t *testing.T) {
	mailer := newTestMailer()
	svc := NewMailService(mailer, "", "")

	// The service does not validate the email — it passes through to the mailer.
	err := svc.SendVerificationEmail(context.Background(), "", "token-123")
	if err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}
	if mailer.sentEmails[0].To != "" {
		t.Errorf("To = %q, want empty", mailer.sentEmails[0].To)
	}
}

// --- SendPasswordResetEmail Tests ---

func TestSendPasswordResetEmailSuccess(t *testing.T) {
	mailer := newTestMailer()
	svc := NewMailService(mailer, "https://app.test.com", "")

	err := svc.SendPasswordResetEmail(context.Background(), "user@example.com", "reset-token-456")
	if err != nil {
		t.Fatalf("SendPasswordResetEmail: %v", err)
	}
	if len(mailer.sentEmails) != 1 {
		t.Fatalf("sent emails = %d, want 1", len(mailer.sentEmails))
	}

	email := mailer.sentEmails[0]
	if email.To != "user@example.com" {
		t.Errorf("To = %q, want %q", email.To, "user@example.com")
	}
	if email.Subject != "Reset your ShellVault password" {
		t.Errorf("Subject = %q, want reset subject", email.Subject)
	}
	if !strings.Contains(email.Body, "reset-token-456") {
		t.Error("body should contain the reset token")
	}
	if !strings.Contains(email.Body, "https://app.test.com") {
		t.Error("body should contain the app base URL")
	}
}

func TestSendPasswordResetEmailUsesAppBaseURL(t *testing.T) {
	mailer := newTestMailer()
	svc := NewMailService(mailer, "https://app.custom.dev", "")

	err := svc.SendPasswordResetEmail(context.Background(), "test@example.com", "tok-reset")
	if err != nil {
		t.Fatalf("SendPasswordResetEmail: %v", err)
	}

	email := mailer.sentEmails[0]
	if !strings.Contains(email.Body, "https://app.custom.dev/reset-password?token=tok-reset") {
		t.Errorf("body should contain full reset URL, got: %s", email.Body[:200])
	}
}

func TestSendPasswordResetEmailMailerError(t *testing.T) {
	mailer := newTestMailer()
	mailer.sendErr = fmt.Errorf("network timeout")
	svc := NewMailService(mailer, "", "")

	err := svc.SendPasswordResetEmail(context.Background(), "user@example.com", "token")
	if err == nil {
		t.Fatal("expected error when mailer fails")
	}
	if !strings.Contains(err.Error(), "sending password reset email") {
		t.Errorf("error = %q, want 'sending password reset email'", err.Error())
	}
	if !strings.Contains(err.Error(), "network timeout") {
		t.Errorf("error should wrap original error, got: %q", err.Error())
	}
}

func TestSendPasswordResetEmailDefaultURLs(t *testing.T) {
	mailer := newTestMailer()
	svc := NewMailService(mailer, "", "")

	err := svc.SendPasswordResetEmail(context.Background(), "user@example.com", "tok-default")
	if err != nil {
		t.Fatalf("SendPasswordResetEmail: %v", err)
	}

	email := mailer.sentEmails[0]
	if !strings.Contains(email.Body, "https://app.sshvault.app/reset-password?token=tok-default") {
		t.Error("body should use default app base URL")
	}
}

// --- Multiple Emails ---

func TestSendMultipleEmails(t *testing.T) {
	mailer := newTestMailer()
	svc := NewMailService(mailer, "", "")
	ctx := context.Background()

	if err := svc.SendVerificationEmail(ctx, "a@example.com", "t1"); err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}
	if err := svc.SendPasswordResetEmail(ctx, "b@example.com", "t2"); err != nil {
		t.Fatalf("SendPasswordResetEmail: %v", err)
	}
	if err := svc.SendVerificationEmail(ctx, "c@example.com", "t3"); err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}

	if len(mailer.sentEmails) != 3 {
		t.Fatalf("sent emails = %d, want 3", len(mailer.sentEmails))
	}

	if mailer.sentEmails[0].To != "a@example.com" {
		t.Errorf("first email To = %q, want a@example.com", mailer.sentEmails[0].To)
	}
	if mailer.sentEmails[1].To != "b@example.com" {
		t.Errorf("second email To = %q, want b@example.com", mailer.sentEmails[1].To)
	}
	if mailer.sentEmails[2].To != "c@example.com" {
		t.Errorf("third email To = %q, want c@example.com", mailer.sentEmails[2].To)
	}
}
