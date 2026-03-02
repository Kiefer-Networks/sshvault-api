package middleware

import (
	"strings"

	"github.com/go-chi/cors"
)

// CORSOptions returns CORS configuration. If corsOrigins is non-empty, it is
// split on commas and used as the allowed origins list. Otherwise the built-in
// defaults are used.
func CORSOptions(corsOrigins string) cors.Options {
	var allowedOrigins []string
	if corsOrigins != "" {
		for _, o := range strings.Split(corsOrigins, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				allowedOrigins = append(allowedOrigins, trimmed)
			}
		}
	}
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"https://sshvault.app", "https://app.sshvault.app"}
	}
	return cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}
}
