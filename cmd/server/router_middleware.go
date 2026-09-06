package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/kiefernetworks/shellvault-server/internal/config"
	"github.com/kiefernetworks/shellvault-server/internal/handler"
	mw "github.com/kiefernetworks/shellvault-server/internal/middleware"
)

// Shared by server startup and production-stack integration tests.
func productionGlobalMiddleware(r chi.Router, cfg *config.Config, limiter *mw.RateLimiter) {
	r.Use(mw.RequestID)
	r.Use(mw.RequestLogger)
	r.Use(mw.SecurityHeaders)
	r.Use(cors.Handler(mw.CORSOptions(cfg.Server.CORSOrigins)))
	r.Use(mw.ResponsePadding)
	r.Use(mw.RecoverPanic)
	r.Use(mw.RequestTimeout(cfg.Server.RequestTimeout))
	r.Use(mw.TrustedRealIP(cfg.Server.TrustedProxies))
	r.Use(limiter.Limit)
	r.Use(mw.APIBodyLimit(int64(cfg.Vault.MaxSizeMB) * 1024 * 1024))
	r.Use(mw.RequireJSONContentType)
}

func registerEmailChangeRoutes(r chi.Router, h *handler.UserHandler) {
	r.Get("/confirm-email-change", h.PreviewEmailChange)
	r.Post("/confirm-email-change", h.ConfirmEmailChange)
}

func registerVerificationRoutes(r chi.Router, h *handler.AuthHandler) {
	r.Get("/verify-email", h.VerifyEmail)
	r.Post("/verify-email", h.VerifyEmail)
}
