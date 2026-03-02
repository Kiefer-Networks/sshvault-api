package auth

import (
	"strings"
	"testing"
)

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
