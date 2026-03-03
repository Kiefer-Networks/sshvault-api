package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// legacyHash generates a hash with v1 parameters (64 MiB, p=4) for backward-compat testing.
func legacyHash(password string, salt []byte) string {
	const (
		v1Memory      uint32 = 64 * 1024
		v1Iterations  uint32 = 3
		v1Parallelism uint8  = 4
		v1KeyLen      uint32 = 32
	)
	hash := argon2.IDKey([]byte(password), salt, v1Iterations, v1Memory, v1Parallelism, v1KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		v1Memory,
		v1Iterations,
		v1Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func TestHashPasswordFormat(t *testing.T) {
	hash, err := HashPassword("testpassword123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash should start with $argon2id$, got %q", hash[:20])
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("hash parts = %d, want 6", len(parts))
	}
}

func TestHashPasswordUniqueSalts(t *testing.T) {
	h1, err := HashPassword("samepassword")
	if err != nil {
		t.Fatalf("HashPassword 1: %v", err)
	}
	h2, err := HashPassword("samepassword")
	if err != nil {
		t.Fatalf("HashPassword 2: %v", err)
	}

	if h1 == h2 {
		t.Error("same password should produce different hashes (random salt)")
	}
}

func TestVerifyPasswordCorrect(t *testing.T) {
	password := "correct-horse-battery-staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("correct password should verify")
	}
}

func TestVerifyPasswordWrong(t *testing.T) {
	hash, err := HashPassword("original")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword("wrong", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Error("wrong password should not verify")
	}
}

func TestVerifyPasswordInvalidFormat(t *testing.T) {
	_, err := VerifyPassword("any", "not-a-valid-hash")
	if err == nil {
		t.Error("expected error for invalid hash format")
	}
}

func TestHashPasswordUsesV2Params(t *testing.T) {
	hash, err := HashPassword("test")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// New hashes must use 256 MiB (m=262144), t=3, p=1
	if !strings.Contains(hash, "m=262144,t=3,p=1") {
		t.Errorf("expected v2 params m=262144,t=3,p=1 in hash, got %s", hash)
	}
}

func TestVerifyPasswordBackwardCompatV1(t *testing.T) {
	// Hash generated with old v1 params: m=65536, t=3, p=4
	// Password: "legacy-password"
	v1Hash := "$argon2id$v=19$m=65536,t=3,p=4$dGVzdHNhbHQxMjM0NTY$invalid"

	// We can't test a real v1 hash without generating one, so verify the
	// parser extracts parameters correctly by testing with a fresh hash
	// using legacy constants
	password := "legacy-test"
	salt := make([]byte, 16)
	copy(salt, []byte("fixedsalt1234567"))

	hash := legacyHash(password, salt)
	ok, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword v1: %v", err)
	}
	if !ok {
		t.Error("v1 legacy hash should still verify correctly")
	}

	// Suppress unused variable warning
	_ = v1Hash
}

func TestVerifyPasswordEmptyInputs(t *testing.T) {
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword empty: %v", err)
	}

	ok, err := VerifyPassword("", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("empty password should verify against its own hash")
	}

	ok, err = VerifyPassword("notempty", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Error("non-empty password should not match empty hash")
	}
}
