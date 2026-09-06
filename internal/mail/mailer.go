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

type Timeouts struct{ Connect, Command, Overall time.Duration }

type SMTPMailer struct {
	timeouts    Timeouts
	implicitTLS bool
	host        string
	port        int
	user        string
	pass        string
	from        string
}

func NewSMTPMailer(host string, port int, user, pass, from string) *SMTPMailer {
	return NewSMTPMailerWithTimeouts(host, port, user, pass, from, Timeouts{10 * time.Second, 10 * time.Second, 30 * time.Second})
}
func NewSMTPMailerWithTimeouts(host string, port int, user, pass, from string, timeouts Timeouts) *SMTPMailer {
	if timeouts.Connect <= 0 || timeouts.Command <= 0 || timeouts.Overall < timeouts.Connect || timeouts.Overall < timeouts.Command {
		panic("invalid SMTP timeouts")
	}
	return &SMTPMailer{
		implicitTLS: port == 465,
		timeouts:    timeouts,
		host:        host,
		port:        port,
		user:        user,
		pass:        pass,
		from:        from,
	}
}

func (m *SMTPMailer) Send(ctx context.Context, to, subject, body string) error {
	ctx, cancel := context.WithTimeout(ctx, m.timeouts.Overall)
	defer cancel()
	addr := net.JoinHostPort(m.host, strconv.Itoa(m.port))

	to = sanitizeHeader(to)
	subject = sanitizeHeader(subject)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		m.from, to, subject, body)

	conn, err := (&net.Dialer{Timeout: m.timeouts.Connect}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connecting SMTP: %w", err)
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(m.timeouts.Overall)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()
	tlsConfig := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}
	var smtpConn net.Conn = &commandDeadlineConn{Conn: conn, command: m.timeouts.Command, overall: deadline}
	if m.implicitTLS {
		secure := tls.Client(smtpConn, tlsConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("SMTP TLS handshake: %w", err)
		}
		smtpConn = secure
	}
	client, err := smtp.NewClient(smtpConn, m.host)
	if err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}
	defer func() { _ = client.Close() }()
	if !m.implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP requires STARTTLS")
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("SMTP STARTTLS: %w", err)
		}
	}
	if m.user != "" || m.pass != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return fmt.Errorf("SMTP credentials configured but AUTH is unavailable")
		}
		if err = client.Auth(smtp.PlainAuth("", m.user, m.pass, m.host)); err != nil {
			return fmt.Errorf("SMTP authentication: %w", err)
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

// NoopMailer discards messages when SMTP is not configured. Development flows
// that need activation or recovery links require a local SMTP test server.
type NoopMailer struct{}

func NewNoopMailer() *NoopMailer {
	return &NoopMailer{}
}

func (m *NoopMailer) Send(_ context.Context, _, _, _ string) error {
	log.Warn().Msg("mail discarded: configure SMTP_HOST to enable delivery")
	return nil
}

// Per-operation deadlines prevent a stalled SMTP command from consuming the
// entire delivery allowance; the overall deadline also bounds trickle traffic.
type commandDeadlineConn struct {
	net.Conn
	command time.Duration
	overall time.Time
}

func (c *commandDeadlineConn) deadline() time.Time {
	next := time.Now().Add(c.command)
	if next.After(c.overall) {
		return c.overall
	}
	return next
}
func (c *commandDeadlineConn) Read(p []byte) (int, error) {
	if err := c.SetReadDeadline(c.deadline()); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}
func (c *commandDeadlineConn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(c.deadline()); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}
