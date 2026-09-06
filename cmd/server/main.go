package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/config"
	"github.com/kiefernetworks/shellvault-server/internal/crypto"
	"github.com/kiefernetworks/shellvault-server/internal/handler"
	"github.com/kiefernetworks/shellvault-server/internal/mail"
	mw "github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

// safeGo runs fn in a goroutine with panic recovery and WaitGroup tracking.
func safeGo(wg *sync.WaitGroup, logger zerolog.Logger, name string, fn func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Interface("panic", r).Str("goroutine", name).Msg("recovered from panic in background goroutine")
			}
		}()
		fn()
	}()
}

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

	log.Info().Str("env", cfg.Env()).Str("addr", cfg.Server.Addr).Msg("starting sshvault-server")

	// Database
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}

	if err := pool.Ping(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to ping database")
	}
	log.Info().Msg("database connected")

	// Run migrations
	if err := runMigrations(cfg.Database.URL); err != nil {
		log.Fatal().Err(err).Msg("failed to run migrations")
	}

	// Signing identity is generated only for a missing file; every other failure is fatal.
	privKey, err := crypto.LoadOrCreateEd25519PrivateKey(cfg.JWT.PrivateKeyPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load or persist JWT signing key")
	}

	// JWT manager
	jwtManager := auth.NewJWTManager(privKey, cfg.JWT.AccessTTL, cfg.JWT.RefreshTTL)

	// Repositories
	userRepo := repository.NewUserRepository(pool)
	tokenRepo := repository.NewTokenRepository(pool)
	verifyRepo := repository.NewVerificationRepository(pool)
	vaultRepo := repository.NewVaultRepository(pool)
	deviceRepo := repository.NewDeviceRepository(pool)
	transactor := repository.NewTransactor(pool)

	// Mailer
	var mailer mail.Mailer
	if cfg.SMTP.Host != "" {
		mailer = mail.NewSMTPMailerWithTimeouts(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.User, cfg.SMTP.Pass, cfg.SMTP.From, mail.Timeouts{Connect: cfg.SMTP.ConnectTimeout, Command: cfg.SMTP.CommandTimeout, Overall: cfg.SMTP.DeliveryTimeout})
	} else {
		mailer = mail.NewNoopMailer()
	}
	mailService := service.NewMailDispatcher(service.NewMailService(mailer, cfg.Server.AppBaseURL, cfg.Server.APIBaseURL), 128, 2)

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
	safeGo(&bgWg, log.Logger, "brute-force-cleanup", func() {
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
	})

	// Background cleanup of expired tokens (every 6 hours)
	safeGo(&bgWg, log.Logger, "token-cleanup", func() {
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
	})

	// Background purge of soft-deleted users after 30 days (every 24 hours)
	// Also anonymizes audit logs for purged users (GDPR compliance)
	safeGo(&bgWg, log.Logger, "user-purge", func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-bgCtx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-30 * 24 * time.Hour)

				deleted, err := userRepo.PurgeDeleted(bgCtx, cutoff)
				if err != nil {
					log.Error().Err(err).Msg("failed to purge deleted users")
				} else if len(deleted) > 0 {
					log.Info().Int("count", len(deleted)).Msg("purged soft-deleted users")
				}
			}
		}
	})

	// Weekly audit log retention cleanup
	safeGo(&bgWg, log.Logger, "audit-retention", func() {
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
	})

	// Services
	authService := service.NewAuthService(userRepo, tokenRepo, verifyRepo, transactor, jwtManager, mailService, bruteForceGuard)
	vaultService := service.NewVaultService(vaultRepo, transactor, cfg.Vault.MaxSizeMB, cfg.Vault.HistoryLimit)
	userService := service.NewUserService(userRepo, tokenRepo, transactor, verifyRepo, mailService)

	// Handlers
	healthHandler := handler.NewHealthHandler(pool)
	authHandler := handler.NewAuthHandler(authService, auditLogger)
	vaultHandler := handler.NewVaultHandler(vaultService, deviceRepo, auditLogger)
	userHandler := handler.NewUserHandler(userService, userRepo, auditLogger)
	deviceHandler := handler.NewDeviceHandler(deviceRepo, auditLogger)
	auditHandler := handler.NewAuditHandler(auditRepo)
	attestationHandler := handler.NewAttestationHandler(privKey, cfg.Server.ServerID, "v1")

	// Proof-of-Work guard
	powGuard := mw.NewPowGuard(16) // 16 leading zero bits base difficulty

	// Background PoW challenge cleanup (every 5 minutes)
	safeGo(&bgWg, log.Logger, "pow-cleanup", func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-bgCtx.Done():
				return
			case <-ticker.C:
				powGuard.Cleanup()
			}
		}
	})

	// Middleware
	authMiddleware := mw.NewAuthMiddleware(jwtManager, userRepo)
	rateLimiter := mw.NewRateLimiter(cfg.Rate.RPS, cfg.Rate.Burst)
	authRateLimiter := mw.StrictAuthLimit()

	// Router
	r := chi.NewRouter()

	// Global middleware
	productionGlobalMiddleware(r, cfg, rateLimiter)

	// System routes
	r.Get("/health", healthHandler.Health)
	r.Get("/ready", healthHandler.Ready)

	// Favicon
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "api/favicon.ico")
	})

	// Swagger UI — relaxed CSP for external CDN assets
	r.Route("/docs", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Security-Policy",
					"default-src 'none'; "+
						"script-src 'unsafe-inline' https://unpkg.com; "+
						"style-src 'unsafe-inline' https://unpkg.com; "+
						"img-src 'self' data:; "+
						"font-src https://unpkg.com; "+
						"connect-src 'self' https://unpkg.com")
				next.ServeHTTP(w, r)
			})
		})
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "api/docs.html")
		})
		r.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "api/openapi.yaml")
		})
	})

	// API v1
	r.Route("/v1", func(r chi.Router) {
		// Attestation (public)
		r.Get("/attestation", attestationHandler.GetAttestation)
		r.Get("/attestation/pubkey", attestationHandler.GetPublicKey)

		// Auth routes (public, with strict rate limiting and timing equalization)
		r.Route("/auth", func(r chi.Router) {
			r.Use(authRateLimiter.Limit)
			r.Use(mw.TimingEqualization(1500 * time.Millisecond))

			// PoW challenge endpoint (no PoW required to get a challenge)
			r.Get("/challenge", powGuard.HandleChallenge)

			// PoW-protected auth endpoints
			r.With(powGuard.RequirePoW).Post("/register", authHandler.Register)
			r.With(powGuard.RequirePoW).Post("/login", authHandler.Login)

			r.Post("/refresh", authHandler.Refresh)
			r.Post("/logout", authHandler.Logout)
			registerVerificationRoutes(r, authHandler)
			registerEmailChangeRoutes(r, userHandler)
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
			r.Put("/user/avatar", userHandler.UpdateAvatar)
			r.Delete("/user/avatar", userHandler.DeleteAvatar)

			// Auth (protected)
			r.Post("/auth/logout-all", authHandler.LogoutAll)

			// Devices
			r.Post("/devices", deviceHandler.RegisterDevice)
			r.Get("/devices", deviceHandler.ListDevices)
			r.Delete("/devices/{id}", deviceHandler.DeleteDevice)

			// Audit
			r.Get("/audit", auditHandler.GetAuditLogs)
		})
	})

	// Server
	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           r,
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	shutdownCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	cleanup := func(stopCtx context.Context) error {
		bgCancel()
		rateLimiter.Stop()
		authRateLimiter.Stop()
		auditLogger.Log(&audit.Entry{Category: audit.CatSystem, Action: audit.ActShutdown})
		err := runCleanup(stopCtx,
			func(ctx context.Context) error {
				err := mailService.Stop(ctx)
				if n := mailService.Unconfirmed(); n > 0 {
					log.Warn().Int64("unconfirmed_messages", n).Msg("mail messages not confirmed delivered at shutdown")
				}
				if err != nil {
					log.Warn().Msg("mail delivery stopped at shutdown deadline")
					return err
				}
				return nil
			},
			func(ctx context.Context) error {
				n, err := auditLogger.Stop(ctx)
				if n > 0 {
					log.Error().Int64("unconfirmed_entries", n).Msg("audit entries not confirmed written at shutdown")
				}
				return err
			},
			func(context.Context) error { bgWg.Wait(); return nil },
			rateLimiter.Wait, authRateLimiter.Wait,
		)
		// Pool.Close waits for acquired connections. Give it only the remaining
		// process budget, even when an uncooperative request still owns one.
		poolErr := runCleanup(stopCtx, func(context.Context) error { pool.Close(); return nil })
		return errors.Join(err, poolErr)
	}

	listener, err := net.Listen("tcp", cfg.Server.Addr)
	if err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		_ = cleanup(stopCtx)
		cancel()
		log.Fatal().Err(err).Msg("failed to listen")
	}

	auditLogger.Log(&audit.Entry{Category: audit.CatSystem, Action: audit.ActStartup, Details: map[string]any{"addr": cfg.Server.Addr}})
	log.Info().Str("addr", cfg.Server.Addr).Msg("server listening")
	if err := serveHTTPWithTimeout(shutdownCtx, srv, listener, cleanup, cfg.Server.ShutdownTimeout); err != nil {
		log.Fatal().Err(err).Msg("server stopped with error")
	}

	log.Info().Msg("server stopped")
}

func runMigrations(databaseURL string) error {
	m, err := migrate.New("file://migrations", databaseURL)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("running migrations: %w", err)
	}

	log.Info().Msg("migrations complete")
	return nil
}
