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

type pgUserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) UserRepository {
	return &pgUserRepo{pool: pool}
}

func (r *pgUserRepo) Create(ctx context.Context, user *model.User) error {
	query := `
		INSERT INTO users (id, email, password, verified, avatar, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	now := time.Now()
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := conn(ctx, r.pool).Exec(ctx, query,
		user.ID, user.Email, user.Password, user.Verified, user.Avatar, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return fmt.Errorf("creating user: %w", err)
	}
	return nil
}

func (r *pgUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	query := `
		SELECT id, email, password, verified, avatar, created_at, updated_at, deleted_at, session_version
		FROM users WHERE id = $1 AND deleted_at IS NULL`

	var user model.User
	err := conn(ctx, r.pool).QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.Verified, &user.Avatar,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.SessionVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting user by id: %w", err)
	}
	return &user, nil
}

func (r *pgUserRepo) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `
		SELECT id, email, password, verified, avatar, created_at, updated_at, deleted_at, session_version
		FROM users WHERE email = $1 AND deleted_at IS NULL`

	var user model.User
	err := conn(ctx, r.pool).QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Verified, &user.Avatar,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.SessionVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return &user, nil
}

func (r *pgUserRepo) GetDeletedByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `
		SELECT id, email, password, verified, avatar, created_at, updated_at, deleted_at, session_version
		FROM users WHERE email = $1 AND deleted_at IS NOT NULL`

	var user model.User
	err := conn(ctx, r.pool).QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Verified, &user.Avatar,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.SessionVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting deleted user by email: %w", err)
	}
	return &user, nil
}

// GetByIDForUpdate serializes session issuance with password changes and revocation.
// Callers must hold a transaction until all session changes are complete.
func (r *pgUserRepo) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*model.User, error) {
	var user model.User
	const query = `SELECT id, email, password, verified, avatar, created_at,
  updated_at, deleted_at, session_version
  FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`
	err := conn(ctx, r.pool).QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.Verified, &user.Avatar,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.SessionVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("locking user: %w", err)
	}
	return &user, nil
}

func (r *pgUserRepo) updateFields(ctx context.Context, query string, args ...any) error {
	result, err := conn(ctx, r.pool).Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("updating user: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("user not found or changed")
	}
	return nil
}

// UpdateEmail also invalidates links sent to the previous mailbox atomically.
func (r *pgUserRepo) UpdateEmail(ctx context.Context, id uuid.UUID, email string) error {
	return NewTransactor(r.pool).WithTransaction(ctx, func(txCtx context.Context) error {
		if err := r.updateFields(txCtx, `UPDATE users SET email=$2, verified=FALSE, updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL`, id, email); err != nil {
			return err
		}
		// Use a new statement snapshot after acquiring the user lock so links
		// committed by an issuance transaction we waited for are also revoked.
		_, err := conn(txCtx, r.pool).Exec(txCtx, `UPDATE verification_tokens SET used=TRUE WHERE user_id=$1 AND NOT used`, id)
		if err != nil {
			return fmt.Errorf("revoking mailbox tokens: %w", err)
		}
		return nil
	})
}

func (r *pgUserRepo) UpdateAvatar(ctx context.Context, id uuid.UUID, avatar string) error {
	return r.updateFields(ctx, `UPDATE users SET avatar=$2,updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL`, id, avatar)
}
func (r *pgUserRepo) MarkVerified(ctx context.Context, id uuid.UUID, email string) error {
	return r.updateFields(ctx, `UPDATE users SET verified=TRUE,updated_at=NOW() WHERE id=$1 AND email=$2 AND deleted_at IS NULL`, id, email)
}
func (r *pgUserRepo) UpdatePassword(ctx context.Context, id uuid.UUID, expectedPassword, password string) error {
	return r.updateFields(ctx, `UPDATE users SET password=$3,session_version=session_version+1,updated_at=NOW() WHERE id=$1 AND password=$2 AND deleted_at IS NULL`, id, expectedPassword, password)
}
func (r *pgUserRepo) RevokeSessions(ctx context.Context, id uuid.UUID) error {
	return r.updateFields(ctx, `UPDATE users SET session_version=session_version+1,updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL`, id)
}

func (r *pgUserRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL`
	_, err := conn(ctx, r.pool).Exec(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("soft deleting user: %w", err)
	}
	return nil
}

func (r *pgUserRepo) PurgeDeleted(ctx context.Context, olderThan time.Time) (int64, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("beginning purge transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Delete all related data for soft-deleted users older than the cutoff.
	// Order matters: child tables first, then the user.
	queries := []string{
		`DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL AND deleted_at < $1)`,
		`DELETE FROM verification_tokens WHERE user_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL AND deleted_at < $1)`,
		// vault_history has no user_id — join through vaults
		`DELETE FROM vault_history WHERE vault_id IN (SELECT v.id FROM vaults v JOIN users u ON v.user_id = u.id WHERE u.deleted_at IS NOT NULL AND u.deleted_at < $1)`,
		`DELETE FROM vaults WHERE user_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL AND deleted_at < $1)`,
		`DELETE FROM devices WHERE user_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL AND deleted_at < $1)`,
		// login_attempts has no user_id — match by email
		`DELETE FROM login_attempts WHERE email IN (SELECT email FROM users WHERE deleted_at IS NOT NULL AND deleted_at < $1)`,
	}

	for _, q := range queries {
		if _, err := tx.Exec(ctx, q, olderThan); err != nil {
			return 0, fmt.Errorf("purging related data: %w", err)
		}
	}

	// Finally delete the user rows
	result, err := tx.Exec(ctx, `DELETE FROM users WHERE deleted_at IS NOT NULL AND deleted_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("purging deleted users: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing purge transaction: %w", err)
	}

	return result.RowsAffected(), nil
}

func (r *pgUserRepo) GetPurgableUserIDs(ctx context.Context, olderThan time.Time) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id FROM users WHERE deleted_at IS NOT NULL AND deleted_at < $1`, olderThan)
	if err != nil {
		return nil, fmt.Errorf("getting purgable user ids: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scanning user id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
