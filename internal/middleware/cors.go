package middleware

import (
	"github.com/go-chi/cors"
)

func CORSOptions(allowedOrigins []string) cors.Options {
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
