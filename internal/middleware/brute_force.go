package middleware

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	// MaxFailedAttempts before account lockout.
	MaxFailedAttempts = 5
	// LockoutWindow defines how far back to count failures.
	LockoutWindow = 15 * time.Minute
	// IPBlockThreshold — block IP after this many failed attempts across all accounts.
	IPBlockThreshold = 20
)

// BruteForceGuard tracks login attempts in PostgreSQL for persistence across restarts.
type BruteForceGuard struct {
	pool *pgxpool.Pool
}

func NewBruteForceGuard(pool *pgxpool.Pool) *BruteForceGuard {
	return &BruteForceGuard{pool: pool}
}

// RecordAttempt logs a login attempt (success or failure).
func (g *BruteForceGuard) RecordAttempt(ctx context.Context, email, ip string, success bool) {
	query := `INSERT INTO login_attempts (email, ip_address, success, created_at) VALUES ($1, $2, $3, $4)`
	if _, err := g.pool.Exec(ctx, query, email, ip, success, time.Now()); err != nil {
		log.Error().Err(err).Str("email", email).Msg("failed to record login attempt")
	}
}

// IsAccountLocked checks if the account has exceeded MaxFailedAttempts within the LockoutWindow.
func (g *BruteForceGuard) IsAccountLocked(ctx context.Context, email string) (bool, time.Duration) {
	query := `
		SELECT COUNT(*) FROM login_attempts
		WHERE email = $1 AND NOT success AND created_at > $2`

	cutoff := time.Now().Add(-LockoutWindow)
	var count int
	if err := g.pool.QueryRow(ctx, query, email, cutoff).Scan(&count); err != nil {
		log.Error().Err(err).Msg("failed to check account lockout")
		return true, LockoutWindow // Fail-closed: assume locked on DB error
	}

	if count >= MaxFailedAttempts {
		// Find when the oldest relevant attempt was, calculate remaining lockout
		var oldestAttempt time.Time
		oldest := `
			SELECT MIN(created_at) FROM login_attempts
			WHERE email = $1 AND NOT success AND created_at > $2`
		if err := g.pool.QueryRow(ctx, oldest, email, cutoff).Scan(&oldestAttempt); err == nil {
			remaining := LockoutWindow - time.Since(oldestAttempt)
			if remaining > 0 {
				return true, remaining
			}
		}
		return true, LockoutWindow
	}

	return false, 0
}

// IsIPBlocked checks if an IP has too many failed attempts across all accounts.
func (g *BruteForceGuard) IsIPBlocked(ctx context.Context, ip string) bool {
	query := `
		SELECT COUNT(*) FROM login_attempts
		WHERE ip_address = $1 AND NOT success AND created_at > $2`

	cutoff := time.Now().Add(-LockoutWindow)
	var count int
	if err := g.pool.QueryRow(ctx, query, ip, cutoff).Scan(&count); err != nil {
		log.Error().Err(err).Msg("failed to check IP block")
		return true // Fail-closed: assume blocked on DB error
	}

	return count >= IPBlockThreshold
}

// ClearAttempts removes failed attempts for an email after successful login.
func (g *BruteForceGuard) ClearAttempts(ctx context.Context, email string) {
	query := `DELETE FROM login_attempts WHERE email = $1 AND NOT success`
	if _, err := g.pool.Exec(ctx, query, email); err != nil {
		log.Error().Err(err).Msg("failed to clear login attempts")
	}
}

// Cleanup removes old login attempts (call periodically via background goroutine).
func (g *BruteForceGuard) Cleanup(ctx context.Context) {
	query := `DELETE FROM login_attempts WHERE created_at < $1`
	cutoff := time.Now().Add(-24 * time.Hour)
	if result, err := g.pool.Exec(ctx, query, cutoff); err != nil {
		log.Error().Err(err).Msg("failed to cleanup login attempts")
	} else {
		if result.RowsAffected() > 0 {
			log.Info().Int64("deleted", result.RowsAffected()).Msg("cleaned up old login attempts")
		}
	}
}
