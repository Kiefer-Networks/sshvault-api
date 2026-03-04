package middleware

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.Mutex
	rps      rate.Limit
	burst    int
	stop     chan struct{}
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewRateLimiter(rps float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rps:      rate.Limit(rps),
		burst:    burst,
		stop:     make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Stop signals the background cleanup goroutine to exit.
func (rl *RateLimiter) Stop() {
	close(rl.stop)
}

func (rl *RateLimiter) getVisitor(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[key]
	if !exists {
		limiter := rate.NewLimiter(rl.rps, rl.burst)
		rl.visitors[key] = &visitor{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case <-ticker.C:
			rl.mu.Lock()
			for key, v := range rl.visitors {
				if time.Since(v.lastSeen) > 3*time.Minute {
					delete(rl.visitors, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *RateLimiter) setRateLimitHeaders(w http.ResponseWriter, limiter *rate.Limiter) {
	limit := limiter.Burst()
	remaining := int(math.Max(0, math.Floor(limiter.Tokens())))
	// Seconds until one new token is available (1 / rate).
	resetSecs := 1
	if limiter.Limit() > 0 {
		resetSecs = int(math.Ceil(float64(time.Second) / float64(limiter.Limit()) / float64(time.Second)))
	}
	w.Header().Set("RateLimit-Limit", fmt.Sprintf("%d", limit))
	w.Header().Set("RateLimit-Remaining", fmt.Sprintf("%d", remaining))
	w.Header().Set("RateLimit-Reset", fmt.Sprintf("%d", resetSecs))
}

func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use RemoteAddr which is already set correctly by chi's RealIP middleware.
		// Never read X-Forwarded-For directly — that allows IP spoofing.
		// Strip port to rate-limit by IP only, not IP:port.
		key := r.RemoteAddr
		if host, _, err := net.SplitHostPort(key); err == nil {
			key = host
		}

		limiter := rl.getVisitor(key)
		if !limiter.Allow() {
			rl.setRateLimitHeaders(w, limiter)
			w.Header().Set("Retry-After", "60")
			respondJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		rl.setRateLimitHeaders(w, limiter)
		next.ServeHTTP(w, r)
	})
}

// StrictLimit creates a stricter rate limiter for auth endpoints (5 req/min).
func StrictAuthLimit() *RateLimiter {
	return NewRateLimiter(5.0/60.0, 5)
}
