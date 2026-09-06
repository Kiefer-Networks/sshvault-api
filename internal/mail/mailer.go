package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// sanitizeHeader strips CR and LF characters to prevent SMTP header injection.
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

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
	addr := net.JoinHostPort(m.host, strconv.Itoa(m.port))

	to = sanitizeHeader(to)
	subject = sanitizeHeader(subject)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		m.from, to, subject, body)

	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connecting SMTP: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()
	client, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err = client.StartTLS(&tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if ok, _ := client.Extension("AUTH"); ok {
		if err = client.Auth(smtp.PlainAuth("", m.user, m.pass, m.host)); err != nil {
			return err
		}
	}
	if err = client.Mail(m.from); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err = writer.Write([]byte(msg)); err != nil {
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	if err = client.Quit(); err != nil {
		return err
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
