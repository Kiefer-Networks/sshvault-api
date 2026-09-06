package repository

import (
	"context"
	"errors"
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
		INSERT INTO refresh_tokens (id, user_id, token_hash, device_name, expires_at, created_at, revoked, family_id, parent_id, consumed_at, session_version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	if token.ID == uuid.Nil {
		token.ID = uuid.New()
	}
	if token.FamilyID == uuid.Nil {
		token.FamilyID = uuid.New()
	}
	token.CreatedAt = time.Now()

	_, err := conn(ctx, r.pool).Exec(ctx, query,
		token.ID, token.UserID, token.TokenHash, token.DeviceName,
		token.ExpiresAt, token.CreatedAt, false, token.FamilyID, token.ParentID, token.ConsumedAt, token.SessionVersion)
	if err != nil {
		return fmt.Errorf("creating refresh token: %w", err)
	}
	return nil
}

func (r *pgTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, COALESCE(device_name, ''), expires_at, created_at, revoked, family_id, parent_id, consumed_at, session_version
		FROM refresh_tokens WHERE token_hash = $1`

	var token model.RefreshToken
	err := conn(ctx, r.pool).QueryRow(ctx, query, tokenHash).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.DeviceName,
		&token.ExpiresAt, &token.CreatedAt, &token.Revoked, &token.FamilyID, &token.ParentID, &token.ConsumedAt, &token.SessionVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting refresh token: %w", err)
	}
	return &token, nil
}

func (r *pgTokenRepo) ConsumeRefreshToken(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	query := `
		UPDATE refresh_tokens
		SET revoked = TRUE, consumed_at = NOW()
		WHERE token_hash = $1 AND NOT revoked AND consumed_at IS NULL AND expires_at > NOW()
		RETURNING id, user_id, token_hash, COALESCE(device_name, ''), expires_at, created_at, revoked, family_id, parent_id, consumed_at, session_version`

	var token model.RefreshToken
	err := conn(ctx, r.pool).QueryRow(ctx, query, tokenHash).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.DeviceName,
		&token.ExpiresAt, &token.CreatedAt, &token.Revoked, &token.FamilyID, &token.ParentID, &token.ConsumedAt, &token.SessionVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("consuming refresh token: %w", err)
	}
	return &token, nil
}

func (r *pgTokenRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1`
	_, err := conn(ctx, r.pool).Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}

func (r *pgTokenRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND NOT revoked`
	_, err := conn(ctx, r.pool).Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("revoking all tokens for user: %w", err)
	}
	return nil
}

func (r *pgTokenRepo) DeleteExpired(ctx context.Context) (int64, error) {
	var deleted int64
	cutoff := time.Now()
	err := NewTransactor(r.pool).WithTransaction(ctx, func(txCtx context.Context) error {
		// Match rotation's user-first lock order. A rotation admitted before expiry
		// may commit a live successor while cleanup is waiting; recheck afterward
		// using a fresh READ COMMITTED snapshot before deleting any ancestors.
		rows, err := conn(txCtx, r.pool).Query(txCtx, `
   SELECT id FROM users WHERE id IN (
    SELECT user_id FROM refresh_tokens GROUP BY user_id, family_id HAVING MAX(expires_at) < $1
   ) ORDER BY id FOR UPDATE`, cutoff)
		if err != nil {
			return err
		}
		for rows.Next() {
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		result, err := conn(txCtx, r.pool).Exec(txCtx, `DELETE FROM refresh_tokens WHERE family_id IN (
   SELECT family_id FROM refresh_tokens GROUP BY family_id HAVING MAX(expires_at) < $1
  )`, cutoff)
		if err != nil {
			return err
		}
		deleted = result.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("deleting expired tokens: %w", err)
	}
	return deleted, nil
}
