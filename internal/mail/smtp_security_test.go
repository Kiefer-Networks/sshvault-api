package mail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

var smtpTestTLSOnce sync.Once
var smtpTestTLSConfig *tls.Config

// Trust a local CA through Go's standard root selection; production TLS settings
// and certificate verification remain unchanged throughout these protocol tests.
func TestSMTPSecureProtocols(t *testing.T) {
	t.Setenv("GODEBUG", "x509usefallbackroots=1")
	smtpTestTLSOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SMTP test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(certificate)
		x509.SetFallbackRoots(roots)
		smtpTestTLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	})
	serverTLS := smtpTestTLSConfig
	for _, tc := range []struct {
		name                                                                    string
		implicit, advertiseAuth, rejectAuth, noCredentials, wrongHost, stallTLS bool
		success                                                                 bool
	}{
		{name: "STARTTLS authenticated delivery", advertiseAuth: true, success: true},
		{name: "implicit TLS authenticated delivery", implicit: true, advertiseAuth: true, success: true},
		{name: "missing AUTH with configured credentials"},
		{name: "rejected AUTH", advertiseAuth: true, rejectAuth: true},
		{name: "secure relay without configured credentials", noCredentials: true, success: true},
		{name: "server name mismatch", advertiseAuth: true, wrongHost: true},
		{name: "cancel stalled TLS handshake", stallTLS: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			type observation struct {
				commands           []string
				message            string
				sensitiveBeforeTLS bool
			}
			finished := make(chan observation, 1)
			go func() {
				seen := observation{}
				defer func() { finished <- seen }()
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				secure := false
				upgrade := func() bool {
					c := tls.Server(conn, serverTLS)
					if err := c.Handshake(); err != nil {
						return false
					}
					conn = c
					secure = true
					return true
				}
				if tc.implicit && !upgrade() {
					return
				}
				_, _ = fmt.Fprint(conn, "220 localhost ESMTP\r\n")
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					seen.commands = append(seen.commands, line)
					switch {
					case strings.HasPrefix(line, "EHLO"):
						_, _ = fmt.Fprint(conn, "250-localhost\r\n")
						if !secure {
							_, _ = fmt.Fprint(conn, "250-STARTTLS\r\n")
						}
						if secure && tc.advertiseAuth {
							_, _ = fmt.Fprint(conn, "250-AUTH PLAIN\r\n")
						}
						_, _ = fmt.Fprint(conn, "250 OK\r\n")
					case strings.HasPrefix(line, "STARTTLS"):
						_, _ = fmt.Fprint(conn, "220 ready\r\n")
						if tc.stallTLS {
							_, _ = io.Copy(io.Discard, conn)
							return
						}
						if !upgrade() {
							return
						}
						reader = bufio.NewReader(conn)
					case strings.HasPrefix(line, "AUTH"):
						seen.sensitiveBeforeTLS = seen.sensitiveBeforeTLS || !secure
						if tc.rejectAuth {
							_, _ = fmt.Fprint(conn, "535 rejected\r\n")
						} else {
							_, _ = fmt.Fprint(conn, "235 authenticated\r\n")
						}
					case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
						seen.sensitiveBeforeTLS = seen.sensitiveBeforeTLS || !secure
						_, _ = fmt.Fprint(conn, "250 OK\r\n")
					case strings.HasPrefix(line, "DATA"):
						seen.sensitiveBeforeTLS = seen.sensitiveBeforeTLS || !secure
						_, _ = fmt.Fprint(conn, "354 continue\r\n")
						for {
							body, err := reader.ReadString('\n')
							if err != nil {
								return
							}
							if body == ".\r\n" {
								break
							}
							seen.message += body
						}
						_, _ = fmt.Fprint(conn, "250 queued\r\n")
					case strings.HasPrefix(line, "QUIT"):
						_, _ = fmt.Fprint(conn, "221 bye\r\n")
						return
					default:
						_, _ = fmt.Fprint(conn, "500 unknown\r\n")
					}
				}
			}()
			host := "127.0.0.1"
			if tc.wrongHost {
				host = "localhost"
			}
			configuredPort := listener.Addr().(*net.TCPAddr).Port
			if tc.implicit {
				configuredPort = 465
			}
			username, password := "user", "password"
			if tc.noCredentials {
				username, password = "", ""
			}
			m := NewSMTPMailer(host, configuredPort, username, password, "sender@example.com")
			m.port = listener.Addr().(*net.TCPAddr).Port
			duration := time.Second
			if tc.stallTLS {
				duration = 60 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			start := time.Now()
			err = m.Send(ctx, "owner@example.com", "subject", "secret-token-body")
			if (err == nil) != tc.success {
				t.Errorf("Send success=%v, want %v (error %v)", err == nil, tc.success, err)
			}
			seen := <-finished
			if seen.sensitiveBeforeTLS {
				t.Error("credentials or message operations preceded verified TLS")
			}
			if tc.success && !strings.Contains(seen.message, "secret-token-body") {
				t.Error("secure delivery lost message")
			}
			if !tc.success && seen.message != "" {
				t.Error("failed security negotiation still sent message body")
			}
			if !tc.success {
				for _, line := range seen.commands {
					if strings.HasPrefix(line, "MAIL") {
						t.Error("failed security negotiation reached MAIL")
					}
				}
			}
			if tc.stallTLS && time.Since(start) > 500*time.Millisecond {
				t.Error("TLS handshake ignored cancellation")
			}
		})
	}
}
