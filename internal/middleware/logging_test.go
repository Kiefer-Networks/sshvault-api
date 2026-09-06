package middleware

import (
	"bytes"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLoggerDoesNotRetainMailboxTokens(t *testing.T) {
	var output bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&output)
	defer func() { log.Logger = previous }()
	req := httptest.NewRequest("GET", "/v1/auth/confirm-email-change?token=secret-confirmation&email=private@example.com", nil)
	RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(output.String(), "secret-confirmation") || strings.Contains(output.String(), "private@example.com") {
		t.Fatalf("query secrets retained: %s", output.String())
	}
	if !strings.Contains(output.String(), "/v1/auth/confirm-email-change") {
		t.Fatal("request route was not recorded")
	}
}
