package middleware

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"net/http"
	"sync"
	"time"
)

// PowChallenge represents a proof-of-work challenge.
type PowChallenge struct {
	Challenge  string `json:"challenge"`
	Difficulty int    `json:"difficulty"`
	ExpiresAt  int64  `json:"expires_at"`
}

// PowSolution is submitted by the client to prove work.
type PowSolution struct {
	Challenge string `json:"challenge"`
	Nonce     string `json:"nonce"`
}

// PowGuard validates proof-of-work solutions before allowing requests.
type PowGuard struct {
	mu            sync.Mutex
	pending       map[string]PowChallenge // challenge → metadata
	baseDifficulty int
	maxDifficulty  int
	challengeTTL   time.Duration

	// Request counter for adaptive difficulty
	reqCount int
	reqReset time.Time
}

// NewPowGuard creates a PoW guard with base difficulty (leading zero bits).
func NewPowGuard(baseDifficulty int) *PowGuard {
	return &PowGuard{
		pending:        make(map[string]PowChallenge),
		baseDifficulty: baseDifficulty,
		maxDifficulty:  24,
		challengeTTL:   2 * time.Minute,
		reqReset:       time.Now(),
	}
}

// maxPendingChallenges is the maximum number of outstanding PoW challenges.
const maxPendingChallenges = 10000

// GenerateChallenge creates a new PoW challenge with adaptive difficulty.
func (g *PowGuard) GenerateChallenge() (PowChallenge, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return PowChallenge{}, fmt.Errorf("generating challenge: %w", err)
	}

	g.mu.Lock()
	if len(g.pending) >= maxPendingChallenges {
		g.mu.Unlock()
		return PowChallenge{}, errPowCapacity
	}
	difficulty := g.currentDifficulty()
	challenge := PowChallenge{
		Challenge:  hex.EncodeToString(b),
		Difficulty: difficulty,
		ExpiresAt:  time.Now().Add(g.challengeTTL).Unix(),
	}
	g.pending[challenge.Challenge] = challenge
	g.mu.Unlock()

	return challenge, nil
}

// errPowCapacity is returned when the pending challenge map is full.
var errPowCapacity = fmt.Errorf("challenge capacity exceeded")

// Verify checks a PoW solution. Returns true if valid, consumes the challenge.
func (g *PowGuard) Verify(sol PowSolution) bool {
	g.mu.Lock()
	challenge, ok := g.pending[sol.Challenge]
	if ok {
		delete(g.pending, sol.Challenge)
	}
	g.recordRequest()
	g.mu.Unlock()

	if !ok {
		return false
	}
	if time.Now().Unix() > challenge.ExpiresAt {
		return false
	}

	return verifyLeadingZeros(sol.Challenge, sol.Nonce, challenge.Difficulty)
}

// Cleanup removes expired challenges. Should be called periodically.
func (g *PowGuard) Cleanup() {
	now := time.Now().Unix()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, v := range g.pending {
		if now > v.ExpiresAt {
			delete(g.pending, k)
		}
	}
}

// RequirePoW returns middleware that validates PoW before passing requests.
func (g *PowGuard) RequirePoW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := r.Header.Get("X-PoW-Challenge")
		nonce := r.Header.Get("X-PoW-Nonce")

		if challenge == "" || nonce == "" {
			respondJSONError(w, http.StatusPreconditionRequired, "proof of work required")
			return
		}

		if !g.Verify(PowSolution{Challenge: challenge, Nonce: nonce}) {
			respondJSONError(w, http.StatusForbidden, "invalid proof of work")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// HandleChallenge returns an http.HandlerFunc that serves new challenges.
func (g *PowGuard) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	challenge, err := g.GenerateChallenge()
	if err != nil {
		if err == errPowCapacity {
			respondJSONError(w, http.StatusServiceUnavailable, "server busy, try again later")
			return
		}
		respondJSONError(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(challenge)
}

func (g *PowGuard) currentDifficulty() int {
	now := time.Now()
	if now.Sub(g.reqReset) > time.Minute {
		g.reqCount = 0
		g.reqReset = now
	}

	// Scale difficulty: base + 1 per 50 requests/min
	extra := g.reqCount / 50
	d := g.baseDifficulty + extra
	if d > g.maxDifficulty {
		d = g.maxDifficulty
	}
	return d
}

func (g *PowGuard) recordRequest() {
	now := time.Now()
	if now.Sub(g.reqReset) > time.Minute {
		g.reqCount = 0
		g.reqReset = now
	}
	g.reqCount++
}

// verifyLeadingZeros checks if SHA-256(challenge + nonce) has at least
// `difficulty` leading zero bits.
func verifyLeadingZeros(challenge, nonce string, difficulty int) bool {
	h := sha256.Sum256([]byte(challenge + nonce))
	return countLeadingZeroBits(h[:]) >= difficulty
}

func countLeadingZeroBits(b []byte) int {
	total := 0
	for _, v := range b {
		if v == 0 {
			total += 8
		} else {
			total += bits.LeadingZeros8(v)
			break
		}
	}
	return total
}
