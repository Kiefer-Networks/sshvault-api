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
		INSERT INTO users (id, email, password, verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	now := time.Now()
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := r.pool.Exec(ctx, query,
		user.ID, user.Email, user.Password, user.Verified, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return fmt.Errorf("creating user: %w", err)
	}
	return nil
}

func (r *pgUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	query := `
		SELECT id, email, password, verified, created_at, updated_at, deleted_at
		FROM users WHERE id = $1 AND deleted_at IS NULL`

	var user model.User
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.Verified,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
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
		SELECT id, email, password, verified, created_at, updated_at, deleted_at
		FROM users WHERE email = $1 AND deleted_at IS NULL`

	var user model.User
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Verified,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return &user, nil
}

func (r *pgUserRepo) Update(ctx context.Context, user *model.User) error {
	query := `
		UPDATE users SET email = $1, password = $2, verified = $3, updated_at = $4
		WHERE id = $5 AND deleted_at IS NULL`

	user.UpdatedAt = time.Now()
	_, err := r.pool.Exec(ctx, query,
		user.Email, user.Password, user.Verified, user.UpdatedAt, user.ID)
	if err != nil {
		return fmt.Errorf("updating user: %w", err)
	}
	return nil
}

func (r *pgUserRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL`
	_, err := r.pool.Exec(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("soft deleting user: %w", err)
	}
	return nil
}

func (r *pgUserRepo) CreateOAuthAccount(ctx context.Context, account *model.OAuthAccount) error {
	query := `
		INSERT INTO oauth_accounts (id, user_id, provider, provider_id, email, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	if account.ID == uuid.Nil {
		account.ID = uuid.New()
	}
	account.CreatedAt = time.Now()

	_, err := r.pool.Exec(ctx, query,
		account.ID, account.UserID, account.Provider, account.ProviderID,
		account.Email, account.CreatedAt)
	if err != nil {
		return fmt.Errorf("creating oauth account: %w", err)
	}
	return nil
}

func (r *pgUserRepo) GetOAuthAccount(ctx context.Context, provider, providerID string) (*model.OAuthAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_id, email, created_at
		FROM oauth_accounts WHERE provider = $1 AND provider_id = $2`

	var account model.OAuthAccount
	err := r.pool.QueryRow(ctx, query, provider, providerID).Scan(
		&account.ID, &account.UserID, &account.Provider,
		&account.ProviderID, &account.Email, &account.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting oauth account: %w", err)
	}
	return &account, nil
}

func (r *pgUserRepo) GetOAuthAccountsByUser(ctx context.Context, userID uuid.UUID) ([]model.OAuthAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_id, email, created_at
		FROM oauth_accounts WHERE user_id = $1`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("getting oauth accounts: %w", err)
	}
	defer rows.Close()

	var accounts []model.OAuthAccount
	for rows.Next() {
		var a model.OAuthAccount
		if err := rows.Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderID, &a.Email, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning oauth account: %w", err)
		}
		accounts = append(accounts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}
	return accounts, nil
}
