package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiterAllowsWithinBurst(t *testing.T) {
	rl := NewRateLimiter(1, 3) // 1 rps, burst 3
	defer rl.Stop()

	handler := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First 3 requests should pass (within burst)
	for i := range 3 {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, rec.Code, http.StatusOK)
		}
	}
}

func TestRateLimiterBlocksExcess(t *testing.T) {
	rl := NewRateLimiter(0.001, 2) // Very low rate, burst 2
	defer rl.Stop()

	handler := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust burst
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// Next request should be blocked
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}

func TestRateLimiterRetryAfterHeader(t *testing.T) {
	rl := NewRateLimiter(0.001, 1) // Very low rate, burst 1
	defer rl.Stop()

	handler := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust burst
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "172.16.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Trigger rate limit
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "172.16.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter != "60" {
		t.Errorf("Retry-After = %q, want %q", retryAfter, "60")
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(0.001, 1) // Very low rate, burst 1
	defer rl.Stop()

	handler := rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First IP exhausts burst
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Second IP should still work
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "2.2.2.2:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("different IP status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestStrictAuthLimit(t *testing.T) {
	rl := StrictAuthLimit()
	defer rl.Stop()

	if rl.burst != 5 {
		t.Errorf("burst = %d, want 5", rl.burst)
	}
}
