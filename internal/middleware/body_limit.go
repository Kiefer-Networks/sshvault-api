package middleware

import "net/http"

// APIBodyLimit applies the API request size policy.
func APIBodyLimit(vaultSizeBytes int64) func(http.Handler) http.Handler {
	// Base64 expands three bytes to four; reserve 64 KiB for the JSON envelope.
	vaultWireBytes := ((vaultSizeBytes+2)/3)*4 + 64*1024
	return func(next http.Handler) http.Handler {
		ordinary := BodyLimit(10 * 1024 * 1024)(next)
		vault := BodyLimit(vaultWireBytes)(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && r.URL.Path == "/v1/vault" {
				vault.ServeHTTP(w, r)
				return
			}
			ordinary.ServeHTTP(w, r)
		})
	}
}

// BodyLimit restricts the maximum request body size.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes {
				respondJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
