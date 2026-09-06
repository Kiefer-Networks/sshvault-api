package middleware

import (
	"context"
	"net/http"
	"time"
)

// RequestTimeout propagates a cancellation deadline to database and service work.
// Socket read/write timeouts remain the server's responsibility.
func RequestTimeout(timeout time.Duration) func(http.Handler) http.Handler {
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
