package middleware

import (
	"fmt"
	"net/http"
)

// respondJSONError writes a JSON error response with the given status code and message.
func respondJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
