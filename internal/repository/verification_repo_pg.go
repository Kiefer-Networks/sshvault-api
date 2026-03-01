package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgVerificationRepo struct {
	pool *pgxpool.Pool
}

func NewVerificationRepository(pool *pgxpool.Pool) VerificationRepository {
	return &pgVerificationRepo{pool: pool}
}

func (r *pgVerificationRepo) Create(ctx context.Context, token *VerificationToken) error {
	query := `
		INSERT INTO verification_tokens (id, user_id, token_hash, kind, expires_at, used, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	if token.ID == uuid.Nil {
		token.ID = uuid.New()
	}
	token.CreatedAt = time.Now()

	_, err := r.pool.Exec(ctx, query,
		token.ID, token.UserID, token.TokenHash, token.Kind,
		token.ExpiresAt, false, token.CreatedAt)
	if err != nil {
		return fmt.Errorf("creating verification token: %w", err)
	}
	return nil
}

func (r *pgVerificationRepo) GetByHash(ctx context.Context, tokenHash, kind string) (*VerificationToken, error) {
	query := `
		SELECT id, user_id, token_hash, kind, expires_at, used, created_at
		FROM verification_tokens
		WHERE token_hash = $1 AND kind = $2 AND NOT used`

	var t VerificationToken
	err := r.pool.QueryRow(ctx, query, tokenHash, kind).Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.Kind,
		&t.ExpiresAt, &t.Used, &t.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("getting verification token: %w", err)
	}
	return &t, nil
}

func (r *pgVerificationRepo) MarkUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE verification_tokens SET used = TRUE WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("marking token as used: %w", err)
	}
	return nil
}

func (r *pgVerificationRepo) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM verification_tokens WHERE expires_at < $1 OR used = TRUE`
	result, err := r.pool.Exec(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("deleting expired tokens: %w", err)
	}
	return result.RowsAffected(), nil
}

func (r *pgVerificationRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID, kind string) error {
	query := `UPDATE verification_tokens SET used = TRUE WHERE user_id = $1 AND kind = $2 AND NOT used`
	_, err := r.pool.Exec(ctx, query, userID, kind)
	if err != nil {
		return fmt.Errorf("revoking tokens for user: %w", err)
	}
	return nil
}
