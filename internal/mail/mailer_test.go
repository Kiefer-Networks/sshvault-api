package mail

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSMTPRejectsMissingSTARTTLSBeforeMessage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	commands := make(chan []string, 1)
	go func() {
		var seen []string
		defer func() { commands <- seen }()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		fmt.Fprint(conn, "220 localhost ESMTP\r\n")
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			seen = append(seen, line)
			switch {
			case strings.HasPrefix(line, "EHLO"):
				fmt.Fprint(conn, "250 localhost\r\n")
			case strings.HasPrefix(line, "DATA"):
				fmt.Fprint(conn, "354 continue\r\n")
			case strings.HasPrefix(line, "QUIT"):
				fmt.Fprint(conn, "221 bye\r\n")
				return
			default:
				fmt.Fprint(conn, "250 OK\r\n")
			}
		}
	}()
	m := NewSMTPMailer("127.0.0.1", listener.Addr().(*net.TCPAddr).Port, "configured-user", "configured-password", "sender@example.com")
	if err = m.Send(context.Background(), "owner@example.com", "subject", "secret-token-body"); err == nil {
		t.Error("SMTP accepted an unencrypted connection without STARTTLS")
	}
	for _, line := range <-commands {
		if strings.HasPrefix(line, "MAIL") || strings.HasPrefix(line, "AUTH") || strings.Contains(line, "secret-token-body") {
			t.Errorf("sensitive SMTP operation before TLS: %q", line)
		}
	}
}

func TestSMTPDeliveryCancellationClosesStalledConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(350 * time.Millisecond)
	}()
	address := listener.Addr().(*net.TCPAddr)
	mailer := NewSMTPMailer("127.0.0.1", address.Port, "", "", "server@example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err = mailer.Send(ctx, "new@example.com", "subject", "body"); err == nil {
		t.Fatal("stalled SMTP unexpectedly completed")
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("SMTP ignored dispatcher cancellation")
	}
	<-finished
}

func TestSMTPCommandTimeoutBoundsStalledGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 1)
		_, _ = conn.Read(buffer)
	}()
	m := NewSMTPMailerWithTimeouts("127.0.0.1", listener.Addr().(*net.TCPAddr).Port, "", "", "sender@example.com", Timeouts{Connect: time.Second, Command: 30 * time.Millisecond, Overall: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err = m.Send(ctx, "recipient@example.com", "subject", "secret"); err == nil {
		t.Fatal("stalled command succeeded")
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("SMTP command used the longer overall deadline")
	}
	<-finished
}
