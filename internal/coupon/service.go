package coupon

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service handles coupon business logic.
type Service struct {
	pool *pgxpool.Pool
	repo *Repository
}

// NewService creates a coupon service.
func NewService(pool *pgxpool.Pool, repo *Repository) *Service {
	return &Service{pool: pool, repo: repo}
}

// Redeem atomically validates and redeems a coupon for a user.
// It creates the subscription as needed within a single transaction.
func (s *Service) Redeem(ctx context.Context, userID uuid.UUID, code string) (*RedeemResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the coupon row for update to prevent race conditions.
	var c Coupon
	err = tx.QueryRow(ctx, `
		SELECT id, code, grant_sync, sync_days, max_uses, used_count, expires_at
		FROM coupons WHERE code = $1 FOR UPDATE`, code).
		Scan(&c.ID, &c.Code, &c.GrantSync, &c.SyncDays, &c.MaxUses, &c.UsedCount, &c.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("coupon not found")
	}

	// Validate expiry.
	if c.ExpiresAt != nil && time.Now().After(*c.ExpiresAt) {
		return nil, fmt.Errorf("coupon expired")
	}

	// Validate usage limit.
	if c.UsedCount >= c.MaxUses {
		return nil, fmt.Errorf("coupon fully redeemed")
	}

	// Check if user already redeemed this coupon.
	var alreadyRedeemed bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM coupon_redemptions WHERE coupon_id = $1 AND user_id = $2)`,
		c.ID, userID).Scan(&alreadyRedeemed)
	if err != nil {
		return nil, fmt.Errorf("checking redemption: %w", err)
	}
	if alreadyRedeemed {
		return nil, fmt.Errorf("coupon already redeemed by this user")
	}

	// Insert redemption.
	_, err = tx.Exec(ctx, `
		INSERT INTO coupon_redemptions (coupon_id, user_id) VALUES ($1, $2)`,
		c.ID, userID)
	if err != nil {
		return nil, fmt.Errorf("recording redemption: %w", err)
	}

	// Increment used_count.
	_, err = tx.Exec(ctx, `
		UPDATE coupons SET used_count = used_count + 1 WHERE id = $1`, c.ID)
	if err != nil {
		return nil, fmt.Errorf("updating coupon usage: %w", err)
	}

	// Apply sync grant: create or extend subscription.
	if c.GrantSync && c.SyncDays > 0 {
		periodStart := time.Now()
		periodEnd := periodStart.AddDate(0, 0, c.SyncDays)

		// Check for existing subscription.
		var existingCount int
		_ = tx.QueryRow(ctx, `SELECT COUNT(*) FROM subscriptions WHERE user_id = $1`, userID).Scan(&existingCount)

		if existingCount > 0 {
			// Extend existing subscription.
			_, err = tx.Exec(ctx, `
				UPDATE subscriptions SET
					status = 'active',
					current_period_start = $1,
					current_period_end = GREATEST(current_period_end, $2),
					updated_at = now()
				WHERE user_id = $3`,
				periodStart, periodEnd, userID)
		} else {
			// Create new subscription.
			_, err = tx.Exec(ctx, `
				INSERT INTO subscriptions (user_id, provider, provider_sub_id, status, current_period_start, current_period_end)
				VALUES ($1, 'coupon', $2, 'active', $3, $4)`,
				userID, "coupon:"+c.Code, periodStart, periodEnd)
		}
		if err != nil {
			return nil, fmt.Errorf("granting sync subscription: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing redemption: %w", err)
	}

	return &RedeemResult{
		SyncGranted: c.GrantSync,
		SyncDays:    c.SyncDays,
	}, nil
}
