package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
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

	return NewTransactor(r.pool).WithTransaction(ctx, func(txCtx context.Context) error {
		_, err := conn(txCtx, r.pool).Exec(txCtx, query,
			user.ID, user.Email, user.Password, user.Verified, user.Avatar, user.CreatedAt, user.UpdatedAt)
		if err != nil {
			return fmt.Errorf("creating user: %w", err)
		}
		return nil
	})
}

func (r *pgUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	query := `
		SELECT id, email, password, verified, avatar, created_at, updated_at, deleted_at, session_version, verification_grandfathered, pending_email
		FROM users WHERE id = $1 AND deleted_at IS NULL`

	var user model.User
	err := conn(ctx, r.pool).QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.Verified, &user.Avatar,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.SessionVersion, &user.VerificationGrandfathered, &user.PendingEmail)
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
		SELECT id, email, password, verified, avatar, created_at, updated_at, deleted_at, session_version, verification_grandfathered, pending_email
		FROM users WHERE email = $1 AND deleted_at IS NULL`

	var user model.User
	err := conn(ctx, r.pool).QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Verified, &user.Avatar,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.SessionVersion, &user.VerificationGrandfathered, &user.PendingEmail)
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
		SELECT id, email, password, verified, avatar, created_at, updated_at, deleted_at, session_version, verification_grandfathered, pending_email
		FROM users WHERE email = $1 AND deleted_at IS NOT NULL`

	var user model.User
	err := conn(ctx, r.pool).QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Verified, &user.Avatar,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.SessionVersion, &user.VerificationGrandfathered, &user.PendingEmail)
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
  updated_at, deleted_at, session_version, verification_grandfathered, pending_email
  FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`
	err := conn(ctx, r.pool).QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.Verified, &user.Avatar,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.SessionVersion, &user.VerificationGrandfathered, &user.PendingEmail)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("locking user: %w", err)
	}
	return &user, nil
}

func (r *pgUserRepo) updateFields(ctx context.Context, query string, args ...any) error {
	// Standalone field updates (including avatar handlers) need maintenance
	// protection too. An existing transaction reuses its lock and connection.
	return NewTransactor(r.pool).WithTransaction(ctx, func(txCtx context.Context) error {
		result, err := conn(txCtx, r.pool).Exec(txCtx, query, args...)
		if err != nil {
			return fmt.Errorf("updating user: %w", err)
		}
		if result.RowsAffected() != 1 {
			return fmt.Errorf("user not found or changed")
		}
		return nil
	})
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
	return NewTransactor(r.pool).WithTransaction(ctx, func(txCtx context.Context) error {
		if err := r.updateFields(txCtx, `UPDATE users SET password=$3,pending_email='',session_version=session_version+1,updated_at=NOW() WHERE id=$1 AND password=$2 AND deleted_at IS NULL`, id, expectedPassword, password); err != nil {
			return err
		}
		_, err := conn(txCtx, r.pool).Exec(txCtx, `UPDATE verification_tokens SET used=TRUE WHERE user_id=$1 AND kind IN ($2,$3,$4) AND NOT used`, id, TokenKindEmailChange, TokenKindEmailVerify, TokenKindPasswordReset)
		return err
	})
}
func (r *pgUserRepo) RevokeSessions(ctx context.Context, id uuid.UUID) error {
	return r.updateFields(ctx, `UPDATE users SET session_version=session_version+1,updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL`, id)
}

func (r *pgUserRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return NewTransactor(r.pool).WithTransaction(ctx, func(txCtx context.Context) error {
		_, err := conn(txCtx, r.pool).Exec(txCtx, `UPDATE users SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL`, time.Now(), id)
		if err != nil {
			return fmt.Errorf("soft deleting user: %w", err)
		}
		return nil
	})
}

// PurgeDeleted returns only IDs whose anonymization and deletion committed.
func (r *pgUserRepo) PurgeDeleted(ctx context.Context, olderThan time.Time) ([]uuid.UUID, error) {
	return r.deleteUsers(ctx, `SELECT id, email FROM users WHERE deleted_at IS NOT NULL AND deleted_at < $1 ORDER BY id FOR UPDATE`, olderThan)
}

// HardDelete explicitly deletes an account in any state, using the same atomic
// anonymization and deletion path as scheduled retention.
func (r *pgUserRepo) HardDelete(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	return r.deleteUsers(ctx, `SELECT id, email FROM users WHERE id = $1 ORDER BY id FOR UPDATE`, id)
}

func (r *pgUserRepo) deleteUsers(ctx context.Context, selection string, arg any) ([]uuid.UUID, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning purge transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := LockAccountMutation(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, selection, arg)
	if err != nil {
		return nil, fmt.Errorf("locking purge candidates: %w", err)
	}
	var ids []uuid.UUID
	var emails []string
	for rows.Next() {
		var id uuid.UUID
		var email string
		if err := rows.Scan(&id, &email); err != nil {
			rows.Close()
			return nil, fmt.Errorf("reading purge candidates: %w", err)
		}
		ids = append(ids, id)
		emails = append(emails, email)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading purge candidates: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	// Complete candidate discovery before any audit or child mutation. The locks
	// prevent activation or new FK-linked children until the transaction ends.
	for _, id := range ids {
		if _, err := audit.AnonymizeUserTx(ctx, tx, id); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM login_attempts WHERE email = ANY($1::text[])`, emails); err != nil {
		return nil, fmt.Errorf("purging login attempts: %w", err)
	}
	// All other children have ON DELETE CASCADE foreign keys, including history
	// through vaults. Delete only the stable, locked IDs; never reselect candidates.
	rows, err = tx.Query(ctx, `DELETE FROM users WHERE id = ANY($1::uuid[]) RETURNING id`, ids)
	if err != nil {
		return nil, fmt.Errorf("purging users: %w", err)
	}
	var deleted []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		deleted = append(deleted, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing purge: %w", err)
	}
	return deleted, nil
}

func (r *pgUserRepo) SetPendingEmail(ctx context.Context, id uuid.UUID, email string) error {
	return r.updateFields(ctx, `UPDATE users SET pending_email=$2,updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL`, id, email)
}
func (r *pgUserRepo) ConfirmPendingEmail(ctx context.Context, id uuid.UUID, email string) error {
	return r.updateFields(ctx, `UPDATE users SET email=$2,pending_email='',verified=TRUE,session_version=session_version+1,updated_at=NOW() WHERE id=$1 AND pending_email=$2 AND pending_email<>'' AND deleted_at IS NULL`, id, email)
}

func (r *pgUserRepo) ActivateRegistration(ctx context.Context, id uuid.UUID, email, passwordHash string) error {
	return r.updateFields(ctx, `UPDATE users SET password=$3,verified=TRUE,session_version=session_version+1,updated_at=NOW()
 WHERE id=$1 AND email=$2 AND NOT verified AND NOT verification_grandfathered AND deleted_at IS NULL`, id, email, passwordHash)
}
