package middleware

import (
	"net/http"
	"time"
)

// TimingEqualization ensures handler responses take at least `minDuration`
// to prevent timing side-channel attacks on authentication endpoints.
func TimingEqualization(minDuration time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			elapsed := time.Since(start)
			if remaining := minDuration - elapsed; remaining > 0 {
				time.Sleep(remaining)
			}
		})
	}
}
