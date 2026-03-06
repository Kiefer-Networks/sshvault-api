package auth

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestJWTManager(t *testing.T) *JWTManager {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	return NewJWTManager(priv, 15*time.Minute, 7*24*time.Hour)
}

func TestGenerateAndValidateTokenPair(t *testing.T) {
	m := newTestJWTManager(t)
	userID := uuid.New()

	pair, refreshHash, err := m.GenerateTokenPair(userID)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("access token is empty")
	}
	if pair.RefreshToken == "" {
		t.Error("refresh token is empty")
	}
	if refreshHash == "" {
		t.Error("refresh hash is empty")
	}
	if pair.ExpiresAt == 0 {
		t.Error("expires_at is zero")
	}

	// Validate access token
	claims, err := m.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.Subject != userID.String() {
		t.Errorf("subject = %q, want %q", claims.Subject, userID.String())
	}
	if claims.Issuer != "sshvault" {
		t.Errorf("issuer = %q, want %q", claims.Issuer, "sshvault")
	}
}

func TestRefreshTokenHashDiffers(t *testing.T) {
	m := newTestJWTManager(t)
	userID := uuid.New()

	pair, refreshHash, err := m.GenerateTokenPair(userID)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	// The hash of the raw refresh token should match
	if got := HashToken(pair.RefreshToken); got != refreshHash {
		t.Errorf("HashToken(refreshToken) = %q, want %q", got, refreshHash)
	}
}

func TestValidateExpiredToken(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	m := NewJWTManager(priv, -1*time.Second, 7*24*time.Hour) // Already expired

	pair, _, err := m.GenerateTokenPair(uuid.New())
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	_, err = m.ValidateAccessToken(pair.AccessToken)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestValidateTokenWrongKey(t *testing.T) {
	m1 := newTestJWTManager(t)
	m2 := newTestJWTManager(t)

	pair, _, err := m1.GenerateTokenPair(uuid.New())
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	_, err = m2.ValidateAccessToken(pair.AccessToken)
	if err == nil {
		t.Error("expected error validating with wrong key, got nil")
	}
}

func TestValidateGarbageToken(t *testing.T) {
	m := newTestJWTManager(t)
	_, err := m.ValidateAccessToken("not.a.valid.token")
	if err == nil {
		t.Error("expected error for garbage token, got nil")
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	input := "test-token-value"
	h1 := HashToken(input)
	h2 := HashToken(input)
	if h1 != h2 {
		t.Errorf("HashToken not deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 64 { // SHA256 = 32 bytes = 64 hex chars
		t.Errorf("HashToken length = %d, want 64", len(h1))
	}
}

func TestHashTokenDifferentInputs(t *testing.T) {
	h1 := HashToken("token-a")
	h2 := HashToken("token-b")
	if h1 == h2 {
		t.Error("different inputs produced same hash")
	}
}

func TestRefreshTTL(t *testing.T) {
	m := newTestJWTManager(t)
	if m.RefreshTTL() != 7*24*time.Hour {
		t.Errorf("RefreshTTL = %v, want %v", m.RefreshTTL(), 7*24*time.Hour)
	}
}

func TestMultipleTokenPairsUniqueRefresh(t *testing.T) {
	m := newTestJWTManager(t)
	userID := uuid.New()

	pair1, hash1, _ := m.GenerateTokenPair(userID)
	pair2, hash2, _ := m.GenerateTokenPair(userID)

	// Refresh tokens use uuid.New() so they must always differ
	if pair1.RefreshToken == pair2.RefreshToken {
		t.Error("two refresh tokens should differ")
	}
	if hash1 == hash2 {
		t.Error("two refresh hashes should differ")
	}
}
