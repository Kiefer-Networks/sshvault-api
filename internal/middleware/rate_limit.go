package middleware

import (
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

func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use RemoteAddr which is already set correctly by chi's RealIP middleware.
		// Never read X-Forwarded-For directly — that allows IP spoofing.
		key := r.RemoteAddr

		limiter := rl.getVisitor(key)
		if !limiter.Allow() {
			w.Header().Set("Retry-After", "60")
			respondJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// StrictLimit creates a stricter rate limiter for auth endpoints (5 req/min).
func StrictAuthLimit() *RateLimiter {
	return NewRateLimiter(5.0/60.0, 5)
}
