package middleware

import (
	"encoding/json"
	"net/http"
)

// respondJSONError writes a JSON error response with the given status code and message.
// This is intentionally a minimal duplicate of handler.respondError. A shared
// httputil package was considered but the middleware package must not import
// handler (to avoid circular dependencies), and extracting a three-line helper
// into its own package adds more complexity than the duplication warrants.
func respondJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
