package handler

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// maxNonces is the upper limit for the in-memory nonce map to prevent
// unbounded memory growth from rapid attestation requests.
const maxNonces = 10000

// AttestationHandler provides server identity attestation.
type AttestationHandler struct {
	privateKey ed25519.PrivateKey
	serverID   string
	apiVersion string

	mu          sync.Mutex
	usedNonces  map[string]int64 // nonce → timestamp
	nonceWindow time.Duration
}

// AttestationResponse is the signed attestation payload.
type AttestationResponse struct {
	ServerID   string `json:"server_id"`
	Timestamp  int64  `json:"timestamp"`
	APIVersion string `json:"api_version"`
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature"`
}

// NewAttestationHandler creates an attestation handler.
func NewAttestationHandler(privateKey ed25519.PrivateKey, serverID, apiVersion string) *AttestationHandler {
	return &AttestationHandler{
		privateKey:  privateKey,
		serverID:    serverID,
		apiVersion:  apiVersion,
		usedNonces:  make(map[string]int64),
		nonceWindow: 5 * time.Minute,
	}
}

// GetAttestation signs and returns a server attestation.
func (h *AttestationHandler) GetAttestation(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	if nonce == "" || len(nonce) > 128 {
		respondError(w, http.StatusBadRequest, "nonce required (max 128 chars)")
		return
	}

	// Replay protection
	h.mu.Lock()
	if _, used := h.usedNonces[nonce]; used {
		h.mu.Unlock()
		respondError(w, http.StatusConflict, "nonce already used")
		return
	}
	now := time.Now()

	// Enforce size cap: clean expired nonces first, then reject if still full
	if len(h.usedNonces) >= maxNonces {
		cutoff := now.Add(-h.nonceWindow).Unix()
		for k, ts := range h.usedNonces {
			if ts < cutoff {
				delete(h.usedNonces, k)
			}
		}
		if len(h.usedNonces) >= maxNonces {
			h.mu.Unlock()
			respondError(w, http.StatusServiceUnavailable, "attestation service temporarily at capacity")
			return
		}
	}

	h.usedNonces[nonce] = now.Unix()
	// Clean expired nonces
	cutoff := now.Add(-h.nonceWindow).Unix()
	for k, ts := range h.usedNonces {
		if ts < cutoff {
			delete(h.usedNonces, k)
		}
	}
	h.mu.Unlock()

	timestamp := now.Unix()
	message := fmt.Sprintf("%s|%d|%s|%s", h.serverID, timestamp, h.apiVersion, nonce)
	signature := ed25519.Sign(h.privateKey, []byte(message))

	resp := AttestationResponse{
		ServerID:   h.serverID,
		Timestamp:  timestamp,
		APIVersion: h.apiVersion,
		Nonce:      nonce,
		Signature:  base64.StdEncoding.EncodeToString(signature),
	}

	respondJSON(w, http.StatusOK, resp)
}

// PublicKeyResponse is the response for the public key endpoint.
type PublicKeyResponse struct {
	PublicKey string `json:"public_key"`
}

// GetPublicKey returns the server Ed25519 public key as base64-encoded JSON.
func (h *AttestationHandler) GetPublicKey(w http.ResponseWriter, r *http.Request) {
	pubKey := h.privateKey.Public().(ed25519.PublicKey)
	encoded := base64.StdEncoding.EncodeToString(pubKey)
	respondJSON(w, http.StatusOK, PublicKeyResponse{PublicKey: encoded})
}
