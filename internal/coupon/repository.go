package coupon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository persists coupons and redemptions.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository creates a coupon repository backed by PostgreSQL.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Create inserts a new coupon.
func (r *Repository) Create(ctx context.Context, c *Coupon) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	c.CreatedAt = time.Now()

	_, err := r.pool.Exec(ctx, `
		INSERT INTO coupons (id, code, grant_sync, sync_days, max_uses, used_count, expires_at, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.ID, c.Code, c.GrantSync, c.SyncDays, c.MaxUses, c.UsedCount, c.ExpiresAt, c.CreatedAt, c.CreatedBy)
	if err != nil {
		return fmt.Errorf("creating coupon: %w", err)
	}
	return nil
}

// GetByCode returns a coupon by its code, or nil if not found.
func (r *Repository) GetByCode(ctx context.Context, code string) (*Coupon, error) {
	var c Coupon
	err := r.pool.QueryRow(ctx, `
		SELECT id, code, grant_sync, sync_days, max_uses, used_count, expires_at, created_at, created_by
		FROM coupons WHERE code = $1`, code).
		Scan(&c.ID, &c.Code, &c.GrantSync, &c.SyncDays, &c.MaxUses, &c.UsedCount, &c.ExpiresAt, &c.CreatedAt, &c.CreatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting coupon by code: %w", err)
	}
	return &c, nil
}

// List returns all coupons ordered by creation date.
func (r *Repository) List(ctx context.Context) ([]Coupon, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, code, grant_sync, sync_days, max_uses, used_count, expires_at, created_at, created_by
		FROM coupons ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing coupons: %w", err)
	}
	defer rows.Close()

	var coupons []Coupon
	for rows.Next() {
		var c Coupon
		if err := rows.Scan(&c.ID, &c.Code, &c.GrantSync, &c.SyncDays, &c.MaxUses, &c.UsedCount, &c.ExpiresAt, &c.CreatedAt, &c.CreatedBy); err != nil {
			return nil, fmt.Errorf("scanning coupon: %w", err)
		}
		coupons = append(coupons, c)
	}
	return coupons, rows.Err()
}

// Delete removes a coupon by its code (revoke).
func (r *Repository) Delete(ctx context.Context, code string) error {
	result, err := r.pool.Exec(ctx, `DELETE FROM coupons WHERE code = $1`, code)
	if err != nil {
		return fmt.Errorf("deleting coupon: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("coupon not found: %s", code)
	}
	return nil
}

// HasRedeemed checks if a user has already redeemed a specific coupon.
func (r *Repository) HasRedeemed(ctx context.Context, couponID, userID uuid.UUID) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM coupon_redemptions WHERE coupon_id = $1 AND user_id = $2)`,
		couponID, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("checking redemption: %w", err)
	}
	return exists, nil
}

// ListRedemptions returns all redemptions for a coupon.
func (r *Repository) ListRedemptions(ctx context.Context, couponID uuid.UUID) ([]Redemption, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, coupon_id, user_id, redeemed_at
		FROM coupon_redemptions WHERE coupon_id = $1 ORDER BY redeemed_at DESC`, couponID)
	if err != nil {
		return nil, fmt.Errorf("listing redemptions: %w", err)
	}
	defer rows.Close()

	var redemptions []Redemption
	for rows.Next() {
		var rd Redemption
		if err := rows.Scan(&rd.ID, &rd.CouponID, &rd.UserID, &rd.RedeemedAt); err != nil {
			return nil, fmt.Errorf("scanning redemption: %w", err)
		}
		redemptions = append(redemptions, rd)
	}
	return redemptions, rows.Err()
}
