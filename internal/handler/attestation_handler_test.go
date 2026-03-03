package handler

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestAttestationHandler() (*AttestationHandler, ed25519.PublicKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	h := NewAttestationHandler(priv, "test-server", "v1")
	return h, pub
}

func TestAttestationSuccess(t *testing.T) {
	h, pub := newTestAttestationHandler()

	req := httptest.NewRequest("GET", "/v1/attestation?nonce=test123", nil)
	w := httptest.NewRecorder()
	h.GetAttestation(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp AttestationResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.ServerID != "test-server" {
		t.Errorf("server_id = %q, want %q", resp.ServerID, "test-server")
	}
	if resp.APIVersion != "v1" {
		t.Errorf("api_version = %q, want %q", resp.APIVersion, "v1")
	}
	if resp.Nonce != "test123" {
		t.Errorf("nonce = %q, want %q", resp.Nonce, "test123")
	}

	// Verify signature
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	message := fmt.Sprintf("%s|%d|%s|%s", resp.ServerID, resp.Timestamp, resp.APIVersion, resp.Nonce)
	if !ed25519.Verify(pub, []byte(message), sig) {
		t.Error("signature verification failed")
	}
}

func TestAttestationMissingNonce(t *testing.T) {
	h, _ := newTestAttestationHandler()

	req := httptest.NewRequest("GET", "/v1/attestation", nil)
	w := httptest.NewRecorder()
	h.GetAttestation(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAttestationNonceReplay(t *testing.T) {
	h, _ := newTestAttestationHandler()

	// First request with nonce
	req := httptest.NewRequest("GET", "/v1/attestation?nonce=unique1", nil)
	w := httptest.NewRecorder()
	h.GetAttestation(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w.Code)
	}

	// Replay same nonce
	req = httptest.NewRequest("GET", "/v1/attestation?nonce=unique1", nil)
	w = httptest.NewRecorder()
	h.GetAttestation(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("replay: expected 409, got %d", w.Code)
	}
}

func TestAttestationDifferentNonces(t *testing.T) {
	h, _ := newTestAttestationHandler()

	for i := 0; i < 5; i++ {
		nonce := fmt.Sprintf("nonce-%d", i)
		req := httptest.NewRequest("GET", "/v1/attestation?nonce="+nonce, nil)
		w := httptest.NewRecorder()
		h.GetAttestation(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, w.Code)
		}
	}
}
