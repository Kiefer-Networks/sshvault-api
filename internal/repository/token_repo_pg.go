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

type pgTokenRepo struct {
	pool *pgxpool.Pool
}

func NewTokenRepository(pool *pgxpool.Pool) TokenRepository {
	return &pgTokenRepo{pool: pool}
}

func (r *pgTokenRepo) Create(ctx context.Context, token *model.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, device_name, expires_at, created_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	if token.ID == uuid.Nil {
		token.ID = uuid.New()
	}
	token.CreatedAt = time.Now()

	_, err := r.pool.Exec(ctx, query,
		token.ID, token.UserID, token.TokenHash, token.DeviceName,
		token.ExpiresAt, token.CreatedAt, false)
	if err != nil {
		return fmt.Errorf("creating refresh token: %w", err)
	}
	return nil
}

func (r *pgTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, device_name, expires_at, created_at, revoked
		FROM refresh_tokens WHERE token_hash = $1`

	var token model.RefreshToken
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.DeviceName,
		&token.ExpiresAt, &token.CreatedAt, &token.Revoked)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("getting refresh token: %w", err)
	}
	return &token, nil
}

func (r *pgTokenRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}

func (r *pgTokenRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND NOT revoked`
	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("revoking all tokens for user: %w", err)
	}
	return nil
}

func (r *pgTokenRepo) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at < $1 OR revoked = TRUE`
	result, err := r.pool.Exec(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("deleting expired tokens: %w", err)
	}
	return result.RowsAffected(), nil
}
