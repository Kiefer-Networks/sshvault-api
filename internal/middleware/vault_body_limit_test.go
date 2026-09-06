package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type base64Zeros struct{}

func (base64Zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

func TestVaultBodyLimitAcceptsEncoded15MiB(t *testing.T) {
	// A 15 MiB blob occupies exactly 20 MiB in base64, plus its JSON envelope.
	body := io.MultiReader(strings.NewReader(`{"version":1,"blob":"`), io.LimitReader(base64Zeros{}, 20*1024*1024), strings.NewReader(`","checksum":"test"}`))
	h := APIBodyLimit(15 * 1024 * 1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Errorf("valid encoded vault rejected: %v", err)
		}
		if n <= 20*1024*1024 {
			t.Errorf("truncated request: %d bytes", n)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPut, "/v1/vault", body)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestVaultBodyLimitKeepsOtherEndpointsSmall(t *testing.T) {
	h := APIBodyLimit(15 * 1024 * 1024)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("oversized auth request reached handler") }))
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	req.ContentLength = 11 * 1024 * 1024
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestVaultBodyLimitRejectsOversizedWirePayload(t *testing.T) {
	h := APIBodyLimit(15 * 1024 * 1024)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("oversized vault reached handler") }))
	req := httptest.NewRequest(http.MethodPut, "/v1/vault", nil)
	req.ContentLength = 21 * 1024 * 1024
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d", w.Code)
	}
}
