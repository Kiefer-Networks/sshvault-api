package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/billing"
	"github.com/kiefernetworks/shellvault-server/internal/config"
	"github.com/kiefernetworks/shellvault-server/internal/crypto"
	"github.com/kiefernetworks/shellvault-server/internal/handler"
	"github.com/kiefernetworks/shellvault-server/internal/mail"
	mw "github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

func main() {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if cfg.IsDevelopment() {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	}

	log.Info().Str("env", cfg.Env()).Str("addr", cfg.Server.Addr).Msg("starting shellvault-server")

	// Database
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to ping database")
	}
	log.Info().Msg("database connected")

	// Run migrations
	if err := runMigrations(cfg.Database.URL); err != nil {
		log.Fatal().Err(err).Msg("failed to run migrations")
	}

	// Ed25519 key
	privKey, err := crypto.LoadEd25519PrivateKey(cfg.JWT.PrivateKeyPath)
	if err != nil {
		log.Warn().Err(err).Msg("failed to load JWT key, generating new one")
		privKey, err = crypto.GenerateEd25519Key()
		if err != nil {
			log.Fatal().Err(err).Msg("failed to generate JWT key")
		}
		if err := crypto.SaveEd25519PrivateKey(cfg.JWT.PrivateKeyPath, privKey); err != nil {
			log.Warn().Err(err).Msg("failed to save JWT key")
		}
	}

	// JWT manager
	jwtManager := auth.NewJWTManager(privKey, cfg.JWT.AccessTTL, cfg.JWT.RefreshTTL)

	// Repositories
	userRepo := repository.NewUserRepository(pool)
	tokenRepo := repository.NewTokenRepository(pool)
	verifyRepo := repository.NewVerificationRepository(pool)
	vaultRepo := repository.NewVaultRepository(pool)
	deviceRepo := repository.NewDeviceRepository(pool)
	subRepo := repository.NewSubscriptionRepository(pool)

	// Mailer
	var mailer mail.Mailer
	if cfg.SMTP.Host != "" {
		mailer = mail.NewSMTPMailer(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.User, cfg.SMTP.Pass, cfg.SMTP.From)
	} else {
		mailer = mail.NewNoopMailer()
	}
	mailService := service.NewMailService(mailer, cfg.Server.AppBaseURL, cfg.Server.APIBaseURL)

	// Billing provider
	var billingProvider billing.Provider
	billingEnabled := cfg.Billing.Enabled()
	if billingEnabled {
		billingProvider = billing.NewStripeProvider(
			cfg.Billing.StripeSecretKey,
			cfg.Billing.StripeWebhookSecret,
			cfg.Billing.StripePriceID,
			cfg.Server.AppBaseURL,
			subRepo,
		)
	} else {
		billingProvider = billing.NewNoopProvider()
	}

	// Brute force protection (DB-backed, persists across restarts)
	bruteForceGuard := mw.NewBruteForceGuard(pool)

	// Background cleanup of old login attempts (every hour)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			bruteForceGuard.Cleanup(context.Background())
		}
	}()

	// Services
	authService := service.NewAuthService(userRepo, tokenRepo, verifyRepo, jwtManager, mailService, bruteForceGuard)
	vaultService := service.NewVaultService(vaultRepo, cfg.Vault.MaxSizeMB, cfg.Vault.HistoryLimit)
	userService := service.NewUserService(userRepo, tokenRepo)
	billingService := service.NewBillingService(subRepo, billingProvider, billingEnabled)

	// OAuth providers
	var appleOAuth auth.OAuthProvider
	var googleOAuth auth.OAuthProvider
	if cfg.OAuth.AppleClientID != "" {
		appleOAuth = auth.NewAppleOAuth(cfg.OAuth.AppleTeamID, cfg.OAuth.AppleClientID)
	}
	if cfg.OAuth.GoogleClientID != "" {
		googleOAuth = auth.NewGoogleOAuth(cfg.OAuth.GoogleClientID)
	}

	// Handlers
	healthHandler := handler.NewHealthHandler(pool)
	authHandler := handler.NewAuthHandler(authService, appleOAuth, googleOAuth)
	vaultHandler := handler.NewVaultHandler(vaultService, billingService)
	userHandler := handler.NewUserHandler(userService)
	deviceHandler := handler.NewDeviceHandler(deviceRepo, tokenRepo)
	billingHandler := handler.NewBillingHandler(billingService, userService)

	// Middleware
	authMiddleware := mw.NewAuthMiddleware(jwtManager)
	rateLimiter := mw.NewRateLimiter(cfg.Rate.RPS, cfg.Rate.Burst)
	authRateLimiter := mw.StrictAuthLimit()

	// Router
	r := chi.NewRouter()

	// Global middleware
	r.Use(mw.TrustedRealIP(cfg.Server.TrustedProxies))
	r.Use(mw.RequestID)
	r.Use(mw.SecurityHeaders)
	r.Use(chimiddleware.Recoverer)
	r.Use(rateLimiter.Limit)
	r.Use(mw.BodyLimit(10 * 1024 * 1024)) // 10 MB global limit
	r.Use(cors.Handler(mw.CORSOptions(nil)))
	r.Use(chimiddleware.Compress(5))

	// System routes
	r.Get("/health", healthHandler.Health)
	r.Get("/ready", healthHandler.Ready)

	// Swagger UI (serve static OpenAPI file)
	r.Get("/docs", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "api/openapi.yaml")
	})

	// API v1
	r.Route("/v1", func(r chi.Router) {
		// Auth routes (public, with strict rate limiting)
		r.Route("/auth", func(r chi.Router) {
			r.Use(authRateLimiter.Limit)
			r.Post("/register", authHandler.Register)
			r.Post("/login", authHandler.Login)
			r.Post("/refresh", authHandler.Refresh)
			r.Post("/logout", authHandler.Logout)
			r.Post("/oauth/{provider}", authHandler.OAuth)
			r.Get("/verify-email", authHandler.VerifyEmail)
			r.Post("/forgot-password", authHandler.ForgotPassword)
			r.Post("/reset-password", authHandler.ResetPassword)
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Authenticate)

			// Vault
			r.Get("/vault", vaultHandler.GetVault)
			r.Put("/vault", vaultHandler.PutVault)
			r.Get("/vault/history", vaultHandler.GetHistory)
			r.Get("/vault/history/{version}", vaultHandler.GetHistoryVersion)

			// User
			r.Get("/user", userHandler.GetProfile)
			r.Put("/user", userHandler.UpdateProfile)
			r.Delete("/user", userHandler.DeleteAccount)
			r.Put("/user/password", userHandler.ChangePassword)

			// Devices
			r.Get("/devices", deviceHandler.ListDevices)
			r.Delete("/devices/{id}", deviceHandler.DeleteDevice)

			// Billing (only if enabled)
			r.Get("/billing/status", billingHandler.GetStatus)
			r.Post("/billing/checkout", billingHandler.CreateCheckout)
			r.Post("/billing/portal", billingHandler.CreatePortal)
		})

		// Webhooks (public, signature-verified)
		r.Post("/webhooks/stripe", billingHandler.StripeWebhook)
		r.Post("/webhooks/apple", billingHandler.AppleWebhook)
		r.Post("/webhooks/google", billingHandler.GoogleWebhook)
	})

	// Server
	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           r,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// Graceful shutdown
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		sig := <-quit
		log.Info().Str("signal", sig.String()).Msg("shutting down server")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Fatal().Err(err).Msg("server shutdown failed")
		}
	}()

	log.Info().Str("addr", cfg.Server.Addr).Msg("server listening")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("server failed")
	}

	log.Info().Msg("server stopped")
}

func runMigrations(databaseURL string) error {
	m, err := migrate.New("file://migrations", databaseURL)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("running migrations: %w", err)
	}

	log.Info().Msg("migrations complete")
	return nil
}
