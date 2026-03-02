package mail

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/rs/zerolog/log"
)

type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

type SMTPMailer struct {
	host string
	port int
	user string
	pass string
	from string
}

func NewSMTPMailer(host string, port int, user, pass, from string) *SMTPMailer {
	return &SMTPMailer{
		host: host,
		port: port,
		user: user,
		pass: pass,
		from: from,
	}
}

func (m *SMTPMailer) Send(ctx context.Context, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", m.host, m.port)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		m.from, to, subject, body)

	auth := smtp.PlainAuth("", m.user, m.pass, m.host)

	if err := smtp.SendMail(addr, auth, m.from, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("sending email: %w", err)
	}
	return nil
}

// NoopMailer is a no-op mailer for development/self-hosted without SMTP config.
type NoopMailer struct{}

func NewNoopMailer() *NoopMailer {
	return &NoopMailer{}
}

func (m *NoopMailer) Send(_ context.Context, to, subject, _ string) error {
	log.Info().Str("to", to).Str("subject", subject).Msg("noop mailer: would send email")
	return nil
}
