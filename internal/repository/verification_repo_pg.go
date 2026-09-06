package repository

import (
	"context"
	"errors"
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
		INSERT INTO verification_tokens (id, user_id, token_hash, kind, expires_at, used, created_at, registration_password_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	if token.ID == uuid.Nil {
		token.ID = uuid.New()
	}
	token.CreatedAt = time.Now()

	_, err := conn(ctx, r.pool).Exec(ctx, query,
		token.ID, token.UserID, token.TokenHash, token.Kind,
		token.ExpiresAt, false, token.CreatedAt, token.RegistrationPasswordHash)
	if err != nil {
		return fmt.Errorf("creating verification token: %w", err)
	}
	return nil
}

func (r *pgVerificationRepo) GetByHash(ctx context.Context, tokenHash, kind string) (*VerificationToken, error) {
	query := `
		SELECT id, user_id, token_hash, kind, expires_at, used, created_at, registration_password_hash
		FROM verification_tokens
		WHERE token_hash = $1 AND kind = $2 AND NOT used`

	var t VerificationToken
	err := conn(ctx, r.pool).QueryRow(ctx, query, tokenHash, kind).Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.Kind,
		&t.ExpiresAt, &t.Used, &t.CreatedAt, &t.RegistrationPasswordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting verification token: %w", err)
	}
	return &t, nil
}

func (r *pgVerificationRepo) ConsumeVerificationToken(ctx context.Context, tokenHash, kind string) (*VerificationToken, error) {
	query := `
		UPDATE verification_tokens
		SET used = TRUE
		WHERE token_hash = $1 AND kind = $2 AND NOT used AND expires_at > NOW()
		RETURNING id, user_id, token_hash, kind, expires_at, used, created_at, registration_password_hash`

	var t VerificationToken
	err := conn(ctx, r.pool).QueryRow(ctx, query, tokenHash, kind).Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.Kind,
		&t.ExpiresAt, &t.Used, &t.CreatedAt, &t.RegistrationPasswordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("consuming verification token: %w", err)
	}
	return &t, nil
}

func (r *pgVerificationRepo) MarkUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE verification_tokens SET used = TRUE WHERE id = $1`
	_, err := conn(ctx, r.pool).Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("marking token as used: %w", err)
	}
	return nil
}

func (r *pgVerificationRepo) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM verification_tokens WHERE expires_at < $1 OR used = TRUE`
	result, err := conn(ctx, r.pool).Exec(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("deleting expired tokens: %w", err)
	}
	return result.RowsAffected(), nil
}

func (r *pgVerificationRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID, kind string) error {
	query := `UPDATE verification_tokens SET used = TRUE WHERE user_id = $1 AND kind = $2 AND NOT used`
	_, err := conn(ctx, r.pool).Exec(ctx, query, userID, kind)
	if err != nil {
		return fmt.Errorf("revoking tokens for user: %w", err)
	}
	return nil
}

// MailSendCooldown applies across processes, request IPs, and accounts targeting one mailbox.
const MailSendCooldown = 60 * time.Second

func (r *pgVerificationRepo) ReserveMailSend(ctx context.Context, digest, purpose string) (bool, error) {
	var admitted bool
	err := conn(ctx, r.pool).QueryRow(ctx, `INSERT INTO mail_send_budgets(recipient_digest,purpose,next_send_at)
 VALUES($1,$2,clock_timestamp()+$3::interval)
 ON CONFLICT(recipient_digest,purpose) DO UPDATE SET next_send_at=EXCLUDED.next_send_at
 WHERE mail_send_budgets.next_send_at<=clock_timestamp() RETURNING TRUE`, digest, purpose, MailSendCooldown.String()).Scan(&admitted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return admitted, err
}
func (r *pgVerificationRepo) PendingRegistrationPassword(ctx context.Context, id uuid.UUID) (string, error) {
	var hash string
	err := conn(ctx, r.pool).QueryRow(ctx, `SELECT registration_password_hash FROM verification_tokens
 WHERE user_id=$1 AND kind=$2 AND NOT used AND expires_at>NOW()`, id, TokenKindEmailVerify).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return hash, err
}
