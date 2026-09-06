package mail

import (
	"context"
	"net"
	"testing"
	"time"
)

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
