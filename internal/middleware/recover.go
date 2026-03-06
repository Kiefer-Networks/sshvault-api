package middleware

import "net/http"

// RecoverPanic recovers from panics and returns a generic 500 JSON error.
// Unlike chi's default Recoverer, this does not log stack traces to prevent
// information leakage in a zero-knowledge architecture.
func RecoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
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
