package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTimingEqualizationMinDuration(t *testing.T) {
	minDur := 200 * time.Millisecond

	handler := TimingEqualization(minDur)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fast handler (nearly instant)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/login", nil)
	w := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if elapsed < minDur {
		t.Errorf("response took %v, expected at least %v", elapsed, minDur)
	}
}

func TestTimingEqualizationSlowHandler(t *testing.T) {
	minDur := 100 * time.Millisecond

	handler := TimingEqualization(minDur)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond) // Slower than minimum
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/login", nil)
	w := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(w, req)
	elapsed := time.Since(start)

	// Should not add extra sleep when handler is already slow
	if elapsed > 250*time.Millisecond {
		t.Errorf("slow handler response took %v, should not add significant overhead", elapsed)
	}
}

func TestTimingEqualizationStatusPreserved(t *testing.T) {
	handler := TimingEqualization(50 * time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	req := httptest.NewRequest("POST", "/login", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
