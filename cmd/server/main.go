package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
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
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/kiefernetworks/shellvault-server/internal/audit"
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

	// Setup logging — ISO 8601 for legal compliance
	zerolog.TimeFieldFormat = time.RFC3339

	var writers []io.Writer
	if cfg.IsDevelopment() {
		writers = append(writers, zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
	} else {
		writers = append(writers, os.Stdout)
	}

	// Optional JSON log file with rotation
	if cfg.Log.FilePath != "" {
		fileWriter := &lumberjack.Logger{
			Filename:   cfg.Log.FilePath,
			MaxSize:    cfg.Log.MaxSizeMB,
			MaxAge:     cfg.Log.MaxAgeDays,
			MaxBackups: cfg.Log.MaxBackups,
			Compress:   cfg.Log.Compress,
		}
		writers = append(writers, fileWriter)
	}

	log.Logger = zerolog.New(io.MultiWriter(writers...)).With().Timestamp().Logger()

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
	transactor := repository.NewTransactor(pool)

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
			cfg.Server.APIBaseURL,
			subRepo,
			mailer,
		)
	} else {
		billingProvider = billing.NewNoopProvider()
	}

	// Audit logger (async, buffered)
	auditRepo := audit.NewRepository(pool)
	auditLogger := audit.NewLogger(auditRepo, cfg.Audit.BufferSize)

	// Brute force protection (DB-backed, persists across restarts)
	bruteForceGuard := mw.NewBruteForceGuard(pool)

	// Cancellable context for background goroutines
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	var bgWg sync.WaitGroup

	// Background cleanup of old login attempts (every hour)
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-bgCtx.Done():
				return
			case <-ticker.C:
				bruteForceGuard.Cleanup(bgCtx)
			}
		}
	}()

	// Background cleanup of expired tokens (every 6 hours)
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-bgCtx.Done():
				return
			case <-ticker.C:
				n, err := tokenRepo.DeleteExpired(bgCtx)
				if err != nil {
					log.Error().Err(err).Msg("failed to clean expired refresh tokens")
				} else if n > 0 {
					log.Info().Int64("count", n).Msg("cleaned expired refresh tokens")
				}

				m, err := verifyRepo.DeleteExpired(bgCtx)
				if err != nil {
					log.Error().Err(err).Msg("failed to clean expired verification tokens")
				} else if m > 0 {
					log.Info().Int64("count", m).Msg("cleaned expired verification tokens")
				}
			}
		}
	}()

	// Background purge of soft-deleted users after 30 days (every 24 hours)
	// Also anonymizes audit logs for purged users (GDPR compliance)
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-bgCtx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-30 * 24 * time.Hour)

				// Get user IDs before purge for audit anonymization
				purgableIDs, err := userRepo.GetPurgableUserIDs(bgCtx, cutoff)
				if err != nil {
					log.Error().Err(err).Msg("failed to get purgable user ids")
				}

				n, err := userRepo.PurgeDeleted(bgCtx, cutoff)
				if err != nil {
					log.Error().Err(err).Msg("failed to purge deleted users")
				} else if n > 0 {
					log.Info().Int64("count", n).Msg("purged soft-deleted users")
				}

				// Anonymize audit logs for purged users
				for _, uid := range purgableIDs {
					affected, err := auditRepo.AnonymizeUser(bgCtx, uid)
					if err != nil {
						log.Error().Err(err).Str("user_id", uid.String()).Msg("failed to anonymize audit logs")
					} else if affected > 0 {
						log.Info().Int("count", affected).Str("user_id", uid.String()).Msg("anonymized audit logs for purged user")
					}
				}
			}
		}
	}()

	// Weekly audit log retention cleanup
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		ticker := time.NewTicker(7 * 24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-bgCtx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().AddDate(0, 0, -cfg.Audit.RetentionDays)
				n, err := auditRepo.PurgeOld(bgCtx, cutoff)
				if err != nil {
					log.Error().Err(err).Msg("failed to purge old audit logs")
				} else if n > 0 {
					log.Info().Int("count", n).Msg("purged old audit logs")
				}
			}
		}
	}()

	// Services
	authService := service.NewAuthService(userRepo, tokenRepo, verifyRepo, transactor, jwtManager, mailService, bruteForceGuard)
	vaultService := service.NewVaultService(vaultRepo, transactor, cfg.Vault.MaxSizeMB, cfg.Vault.HistoryLimit)
	userService := service.NewUserService(userRepo, tokenRepo, transactor)
	billingService := service.NewBillingService(subRepo, billingProvider, billingEnabled)

	// OAuth providers
	var appleOAuth auth.OAuthProvider
	var googleOAuth auth.OAuthProvider
	if cfg.OAuth.AppleClientID != "" {
		appleOAuth = auth.NewAppleOAuth(cfg.OAuth.AppleClientID)
	}
	if cfg.OAuth.GoogleClientID != "" {
		googleOAuth = auth.NewGoogleOAuth(cfg.OAuth.GoogleClientID)
	}

	// Handlers
	healthHandler := handler.NewHealthHandler(pool)
	authHandler := handler.NewAuthHandler(authService, appleOAuth, googleOAuth, auditLogger)
	vaultHandler := handler.NewVaultHandler(vaultService, billingService, auditLogger)
	userHandler := handler.NewUserHandler(userService, auditLogger)
	deviceHandler := handler.NewDeviceHandler(deviceRepo, auditLogger)
	billingHandler := handler.NewBillingHandler(billingService, userService, auditLogger)
	auditHandler := handler.NewAuditHandler(auditRepo)

	// Middleware
	authMiddleware := mw.NewAuthMiddleware(jwtManager)
	rateLimiter := mw.NewRateLimiter(cfg.Rate.RPS, cfg.Rate.Burst)
	authRateLimiter := mw.StrictAuthLimit()

	// Router
	r := chi.NewRouter()

	// Global middleware
	r.Use(mw.TrustedRealIP(cfg.Server.TrustedProxies))
	r.Use(mw.RequestID)
	r.Use(mw.RequestLogger)
	r.Use(mw.SecurityHeaders)
	r.Use(chimiddleware.Recoverer)
	r.Use(rateLimiter.Limit)
	r.Use(mw.BodyLimit(10 * 1024 * 1024)) // 10 MB global limit
	r.Use(cors.Handler(mw.CORSOptions(cfg.Server.CORSOrigins)))
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

			// Auth (protected)
			r.Post("/auth/logout-all", authHandler.LogoutAll)

			// Devices
			r.Post("/devices", deviceHandler.RegisterDevice)
			r.Get("/devices", deviceHandler.ListDevices)
			r.Delete("/devices/{id}", deviceHandler.DeleteDevice)

			// Audit
			r.Get("/audit", auditHandler.GetAuditLogs)

			// Billing (only if enabled)
			r.Get("/billing/status", billingHandler.GetStatus)
			r.Post("/billing/checkout", billingHandler.CreateCheckout)
			r.Post("/billing/portal", billingHandler.CreatePortal)
		})

		// Billing pages (public, shown after Stripe redirect)
		r.Get("/billing/success", billingHandler.SuccessPage)
		r.Get("/billing/cancel", billingHandler.CancelPage)

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

		// Stop background goroutines and wait for them to finish
		bgCancel()
		bgWg.Wait()
		rateLimiter.Stop()
		authRateLimiter.Stop()

		// Flush audit logs
		auditLogger.Log(&audit.Entry{Category: audit.CatSystem, Action: audit.ActShutdown})
		auditLogger.Stop()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Fatal().Err(err).Msg("server shutdown failed")
		}
	}()

	auditLogger.Log(&audit.Entry{Category: audit.CatSystem, Action: audit.ActStartup, Details: map[string]any{"addr": cfg.Server.Addr}})
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
