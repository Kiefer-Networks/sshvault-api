package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestNoopMailerLogsDeliverableBody(t *testing.T) {
	var output bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&output)
	t.Cleanup(func() { log.Logger = previous })

	const body = "Activate at https://api.example.test/v1/auth/verify-email?token=local-token"
	if err := NewNoopMailer().Send(context.Background(), "owner@example.test", "Activate", body); err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode log event: %v", err)
	}
	if event["body"] != body {
		t.Fatalf("logged body = %q, want activation message", event["body"])
	}
}
