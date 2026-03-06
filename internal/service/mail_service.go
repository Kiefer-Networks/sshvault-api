package service

import (
	"context"
	"fmt"

	"github.com/kiefernetworks/shellvault-server/internal/mail"
)

type MailService struct {
	mailer     mail.Mailer
	appBaseURL string
	apiBaseURL string
}

func NewMailService(mailer mail.Mailer, appBaseURL, apiBaseURL string) *MailService {
	if appBaseURL == "" {
		appBaseURL = "https://app.sshvault.app"
	}
	if apiBaseURL == "" {
		apiBaseURL = "https://api.sshvault.app"
	}
	return &MailService{mailer: mailer, appBaseURL: appBaseURL, apiBaseURL: apiBaseURL}
}

func (s *MailService) SendVerificationEmail(ctx context.Context, email, token string) error {
	subject := "Verify your SSHVault email"
	body := mail.VerificationEmailBody(s.apiBaseURL, token)

	if err := s.mailer.Send(ctx, email, subject, body); err != nil {
		return fmt.Errorf("sending verification email: %w", err)
	}
	return nil
}

func (s *MailService) SendPasswordResetEmail(ctx context.Context, email, token string) error {
	subject := "Reset your SSHVault password"
	body := mail.PasswordResetEmailBody(s.appBaseURL, token)

	if err := s.mailer.Send(ctx, email, subject, body); err != nil {
		return fmt.Errorf("sending password reset email: %w", err)
	}
	return nil
}
