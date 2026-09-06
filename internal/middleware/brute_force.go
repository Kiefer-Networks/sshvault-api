package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"strings"
	"time"
)

// hashIP returns a SHA-256 hash of the IP address.
// IPs are never stored in plaintext — only hashes for brute-force comparison.
func hashIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(h[:])
}

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

// ReserveAttempt serializes admission by normalized identity and IP before any
// password work. A crashed/cancelled request remains charged until the window ends.
func (g *BruteForceGuard) ReserveAttempt(ctx context.Context, email, ip string) (uuid.UUID, time.Duration, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if ip != "" {
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "login-ip:"+hashIP(ip)); err != nil {
			return uuid.Nil, 0, err
		}
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "login-account:"+email); err != nil {
		return uuid.Nil, 0, err
	}
	var count int
	cutoff := time.Now().Add(-LockoutWindow)
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM login_attempts WHERE email=$1 AND NOT success AND created_at>$2`, email, cutoff).Scan(&count); err != nil {
		return uuid.Nil, 0, err
	}
	if count >= MaxFailedAttempts {
		return uuid.Nil, LockoutWindow, nil
	}
	if ip != "" {
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM login_attempts WHERE ip_address=$1 AND NOT success AND created_at>$2`, hashIP(ip), cutoff).Scan(&count); err != nil {
			return uuid.Nil, 0, err
		}
		if count >= IPBlockThreshold {
			return uuid.Nil, LockoutWindow, nil
		}
	}
	id := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO login_attempts(id,email,ip_address,success) VALUES($1,$2,$3,FALSE)`, id, email, hashIP(ip)); err != nil {
		return uuid.Nil, 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return uuid.Nil, 0, err
	}
	return id, 0, nil
}

// CompleteAttempt clears only completed older failures on success. In-flight
// reservations and newer guesses retain their charge, regardless of finish order.
func (g *BruteForceGuard) CompleteAttempt(ctx context.Context, email string, id uuid.UUID, success bool) error {
	email = strings.ToLower(strings.TrimSpace(email))
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "login-account:"+email); err != nil {
		return err
	}
	var sequence int64
	if err = tx.QueryRow(ctx, `UPDATE login_attempts SET success=$3, completed_at=NOW() WHERE id=$1 AND email=$2 AND completed_at IS NULL RETURNING admission_sequence`, id, email, success).Scan(&sequence); err != nil {
		return fmt.Errorf("completing login admission: %w", err)
	}
	if success {
		if _, err = tx.Exec(ctx, `DELETE FROM login_attempts WHERE email=$1 AND NOT success AND completed_at IS NOT NULL AND admission_sequence<$2`, email, sequence); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
