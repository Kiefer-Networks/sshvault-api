package middleware

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

// RecoverPanic recovers from panics and returns a generic 500 JSON error.
// Unlike chi's default Recoverer, this does not include a stack trace in the
// response to prevent information leakage in a zero-knowledge architecture;
// the panic is still logged server-side so it remains visible to monitoring.
func RecoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				log.Error().Interface("panic", rvr).Str("method", r.Method).Str("path", r.URL.Path).Msg("recovered from panic in handler")
				if r.Header.Get("Connection") == "Upgrade" {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal server error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
