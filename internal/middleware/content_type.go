package middleware

import (
	"mime"
	"net/http"
)

// RequireJSONContentType rejects requests with a non-JSON Content-Type header
// on methods that carry a body (POST, PUT, PATCH). Requests without a
// Content-Type header are allowed through so that the handler can decide
// whether a body is required.
func RequireJSONContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			ct := r.Header.Get("Content-Type")
			if ct != "" {
				mt, _, _ := mime.ParseMediaType(ct)
				if mt != "application/json" {
					respondJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
