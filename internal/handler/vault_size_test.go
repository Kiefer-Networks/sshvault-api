package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
)

func TestPutVaultOversizedChunkedRequestReturns413(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})
	req := authedRequest(httptest.NewRequest(http.MethodPut, "/v1/vault", strings.NewReader(`{"version":1,"blob":"`+strings.Repeat("A", 128)+`","checksum":"test"}`)), uuid.New())
	req.ContentLength = -1
	w := httptest.NewRecorder()
	middleware.BodyLimit(64)(http.HandlerFunc(h.PutVault)).ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d; want 413", w.Code)
	}
}
