package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kiefernetworks/shellvault-server/internal/model"
)

type pgSubscriptionRepo struct {
	pool *pgxpool.Pool
}

func NewSubscriptionRepository(pool *pgxpool.Pool) SubscriptionRepository {
	return &pgSubscriptionRepo{pool: pool}
}

func (r *pgSubscriptionRepo) Create(ctx context.Context, sub *model.Subscription) error {
	query := `
		INSERT INTO subscriptions (id, user_id, provider, provider_sub_id, status,
			current_period_start, current_period_end, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	now := time.Now()
	if sub.ID == uuid.Nil {
		sub.ID = uuid.New()
	}
	sub.CreatedAt = now
	sub.UpdatedAt = now

	_, err := r.pool.Exec(ctx, query,
		sub.ID, sub.UserID, sub.Provider, sub.ProviderSubID, sub.Status,
		sub.CurrentPeriodStart, sub.CurrentPeriodEnd, sub.CreatedAt, sub.UpdatedAt)
	if err != nil {
		return fmt.Errorf("creating subscription: %w", err)
	}
	return nil
}

func (r *pgSubscriptionRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*model.Subscription, error) {
	query := `
		SELECT id, user_id, provider, provider_sub_id, status,
			current_period_start, current_period_end, created_at, updated_at
		FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`

	var sub model.Subscription
	err := r.pool.QueryRow(ctx, query, userID).Scan(
		&sub.ID, &sub.UserID, &sub.Provider, &sub.ProviderSubID, &sub.Status,
		&sub.CurrentPeriodStart, &sub.CurrentPeriodEnd, &sub.CreatedAt, &sub.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("getting subscription: %w", err)
	}
	return &sub, nil
}

func (r *pgSubscriptionRepo) GetByProviderSubID(ctx context.Context, providerSubID string) (*model.Subscription, error) {
	query := `
		SELECT id, user_id, provider, provider_sub_id, status,
			current_period_start, current_period_end, created_at, updated_at
		FROM subscriptions WHERE provider_sub_id = $1`

	var sub model.Subscription
	err := r.pool.QueryRow(ctx, query, providerSubID).Scan(
		&sub.ID, &sub.UserID, &sub.Provider, &sub.ProviderSubID, &sub.Status,
		&sub.CurrentPeriodStart, &sub.CurrentPeriodEnd, &sub.CreatedAt, &sub.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("getting subscription by provider: %w", err)
	}
	return &sub, nil
}

func (r *pgSubscriptionRepo) Update(ctx context.Context, sub *model.Subscription) error {
	query := `
		UPDATE subscriptions SET status = $1, current_period_start = $2,
			current_period_end = $3, updated_at = $4
		WHERE id = $5`

	sub.UpdatedAt = time.Now()
	_, err := r.pool.Exec(ctx, query,
		sub.Status, sub.CurrentPeriodStart, sub.CurrentPeriodEnd,
		sub.UpdatedAt, sub.ID)
	if err != nil {
		return fmt.Errorf("updating subscription: %w", err)
	}
	return nil
}
