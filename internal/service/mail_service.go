package service

import (
	"context"
	"fmt"

	"github.com/kiefernetworks/shellvault-server/internal/mail"
)

type MailService struct {
	mailer mail.Mailer
}

func NewMailService(mailer mail.Mailer) *MailService {
	return &MailService{mailer: mailer}
}

func (s *MailService) SendVerificationEmail(ctx context.Context, email, token string) error {
	subject := "Verify your ShellVault email"
	body := mail.VerificationEmailBody(token)

	if err := s.mailer.Send(ctx, email, subject, body); err != nil {
		return fmt.Errorf("sending verification email: %w", err)
	}
	return nil
}

func (s *MailService) SendPasswordResetEmail(ctx context.Context, email, token string) error {
	subject := "Reset your ShellVault password"
	body := mail.PasswordResetEmailBody(token)

	if err := s.mailer.Send(ctx, email, subject, body); err != nil {
		return fmt.Errorf("sending password reset email: %w", err)
	}
	return nil
}
