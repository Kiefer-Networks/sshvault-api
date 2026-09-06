package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestNoopMailerDoesNotLogMailContents(t *testing.T) {
	var output bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&output)
	t.Cleanup(func() { log.Logger = previous })

	const body = "Activate at https://api.example.test/v1/auth/verify-email?token=local-token"
	const recipient = "owner@example.test"
	const subject = "Activate private account"
	if err := NewNoopMailer().Send(context.Background(), recipient, subject, body); err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode log event: %v", err)
	}
	for _, sensitive := range []string{recipient, subject, body, "local-token"} {
		if strings.Contains(output.String(), sensitive) {
			t.Errorf("mail content leaked to logs: %q", sensitive)
		}
	}
	if event["level"] != "warn" || event["message"] == "" {
		t.Fatal("missing warning about disabled mail delivery")
	}
}
