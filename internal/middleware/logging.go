package middleware

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// RequestLogger logs each HTTP request with method, URL, status, duration, and request ID.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		reqID, _ := r.Context().Value(RequestIDKey).(string)

		log.Info().
			Str("method", r.Method).
			Str("url", r.URL.RequestURI()).
			Int("status", wrapped.status).
			Dur("duration", time.Since(start)).
			Str("request_id", reqID).
			Str("remote_addr", r.RemoteAddr).
			Msg("request")
	})
}
