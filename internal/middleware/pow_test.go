package middleware

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPowGenerateAndVerify(t *testing.T) {
	g := NewPowGuard(4) // 4 leading zero bits (easy for tests)

	challenge, err := g.GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	// Solve the challenge
	nonce := solveChallenge(challenge.Challenge, challenge.Difficulty)
	if nonce == "" {
		t.Fatal("failed to solve challenge")
	}

	if !g.Verify(PowSolution{Challenge: challenge.Challenge, Nonce: nonce}) {
		t.Error("valid solution should verify")
	}
}

func TestPowReplayRejected(t *testing.T) {
	g := NewPowGuard(4)

	challenge, _ := g.GenerateChallenge()
	nonce := solveChallenge(challenge.Challenge, challenge.Difficulty)

	// First use should work
	g.Verify(PowSolution{Challenge: challenge.Challenge, Nonce: nonce})

	// Replay should fail (challenge consumed)
	if g.Verify(PowSolution{Challenge: challenge.Challenge, Nonce: nonce}) {
		t.Error("replayed solution should not verify")
	}
}

func TestPowInvalidNonce(t *testing.T) {
	g := NewPowGuard(16)

	challenge, _ := g.GenerateChallenge()
	if g.Verify(PowSolution{Challenge: challenge.Challenge, Nonce: "wrong"}) {
		t.Error("invalid nonce should not verify")
	}
}

func TestPowUnknownChallenge(t *testing.T) {
	g := NewPowGuard(4)
	if g.Verify(PowSolution{Challenge: "unknown", Nonce: "any"}) {
		t.Error("unknown challenge should not verify")
	}
}

func TestPowMiddleware(t *testing.T) {
	g := NewPowGuard(4)

	handler := g.RequirePoW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Without headers → 428
	req := httptest.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusPreconditionRequired {
		t.Errorf("expected 428, got %d", w.Code)
	}

	// With valid PoW → 200
	challenge, _ := g.GenerateChallenge()
	nonce := solveChallenge(challenge.Challenge, challenge.Difficulty)

	req = httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-PoW-Challenge", challenge.Challenge)
	req.Header.Set("X-PoW-Nonce", nonce)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestPowHandleChallenge(t *testing.T) {
	g := NewPowGuard(8)

	req := httptest.NewRequest("GET", "/challenge", nil)
	w := httptest.NewRecorder()
	g.HandleChallenge(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var c PowChallenge
	if err := json.NewDecoder(w.Body).Decode(&c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if c.Challenge == "" {
		t.Error("challenge should not be empty")
	}
	if c.Difficulty < 8 {
		t.Errorf("difficulty should be >= 8, got %d", c.Difficulty)
	}
}

func TestPowCleanup(t *testing.T) {
	g := NewPowGuard(4)
	g.GenerateChallenge()
	g.GenerateChallenge()

	// Manually expire all
	g.mu.Lock()
	for k, v := range g.pending {
		v.ExpiresAt = 0
		g.pending[k] = v
	}
	g.mu.Unlock()

	g.Cleanup()

	g.mu.Lock()
	remaining := len(g.pending)
	g.mu.Unlock()
	if remaining != 0 {
		t.Errorf("expected 0 pending after cleanup, got %d", remaining)
	}
}

func TestCountLeadingZeroBits(t *testing.T) {
	tests := []struct {
		input    []byte
		expected int
	}{
		{[]byte{0xFF}, 0},
		{[]byte{0x00, 0xFF}, 8},
		{[]byte{0x00, 0x00, 0x01}, 23},
		{[]byte{0x0F}, 4},
		{[]byte{0x00, 0x00}, 16},
	}
	for _, tt := range tests {
		got := countLeadingZeroBits(tt.input)
		if got != tt.expected {
			t.Errorf("countLeadingZeroBits(%v) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

// solveChallenge brute-forces a nonce for testing.
func solveChallenge(challenge string, difficulty int) string {
	for i := 0; i < 10_000_000; i++ {
		nonce := fmt.Sprintf("%d", i)
		h := sha256.Sum256([]byte(challenge + nonce))
		if countLeadingZeroBits(h[:]) >= difficulty {
			return nonce
		}
	}
	return ""
}
