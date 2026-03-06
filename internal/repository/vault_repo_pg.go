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

type pgVaultRepo struct {
	pool *pgxpool.Pool
}

func NewVaultRepository(pool *pgxpool.Pool) VaultRepository {
	return &pgVaultRepo{pool: pool}
}

func (r *pgVaultRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*model.Vault, error) {
	query := `
		SELECT id, user_id, version, blob, checksum, updated_at
		FROM vaults WHERE user_id = $1`

	var vault model.Vault
	err := r.pool.QueryRow(ctx, query, userID).Scan(
		&vault.ID, &vault.UserID, &vault.Version, &vault.Blob,
		&vault.Checksum, &vault.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting vault: %w", err)
	}
	return &vault, nil
}

func (r *pgVaultRepo) Upsert(ctx context.Context, vault *model.Vault) error {
	query := `
		INSERT INTO vaults (id, user_id, version, blob, checksum, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id) DO UPDATE
		SET version = $3, blob = $4, checksum = $5, updated_at = $6`

	if vault.ID == uuid.Nil {
		vault.ID = uuid.New()
	}
	vault.UpdatedAt = time.Now()

	_, err := r.pool.Exec(ctx, query,
		vault.ID, vault.UserID, vault.Version, vault.Blob,
		vault.Checksum, vault.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upserting vault: %w", err)
	}
	return nil
}

func (r *pgVaultRepo) UpdateBlob(ctx context.Context, userID uuid.UUID, expectedVersion int, blob []byte, checksum string) (*model.Vault, error) {
	query := `
		UPDATE vaults
		SET version = version + 1, blob = $1, checksum = $2, updated_at = $3
		WHERE user_id = $4 AND version = $5
		RETURNING id, user_id, version, blob, checksum, updated_at`

	now := time.Now()
	var vault model.Vault
	err := conn(ctx, r.pool).QueryRow(ctx, query, blob, checksum, now, userID, expectedVersion).Scan(
		&vault.ID, &vault.UserID, &vault.Version, &vault.Blob,
		&vault.Checksum, &vault.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // version conflict
		}
		return nil, fmt.Errorf("updating vault blob: %w", err)
	}
	return &vault, nil
}

func (r *pgVaultRepo) CreateHistory(ctx context.Context, entry *model.VaultHistory) error {
	query := `
		INSERT INTO vault_history (id, vault_id, version, blob, checksum, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	entry.CreatedAt = time.Now()

	_, err := conn(ctx, r.pool).Exec(ctx, query,
		entry.ID, entry.VaultID, entry.Version, entry.Blob,
		entry.Checksum, entry.CreatedAt)
	if err != nil {
		return fmt.Errorf("creating vault history: %w", err)
	}
	return nil
}

func (r *pgVaultRepo) GetHistory(ctx context.Context, vaultID uuid.UUID, userID uuid.UUID, limit int) ([]model.VaultHistory, error) {
	query := `
		SELECT vh.id, vh.vault_id, vh.version, vh.checksum, vh.created_at
		FROM vault_history vh
		JOIN vaults v ON vh.vault_id = v.id
		WHERE vh.vault_id = $1 AND v.user_id = $2
		ORDER BY vh.version DESC LIMIT $3`

	rows, err := r.pool.Query(ctx, query, vaultID, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("getting vault history: %w", err)
	}
	defer rows.Close()

	var entries []model.VaultHistory
	for rows.Next() {
		var e model.VaultHistory
		if err := rows.Scan(&e.ID, &e.VaultID, &e.Version, &e.Checksum, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning vault history: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}
	return entries, nil
}

func (r *pgVaultRepo) GetHistoryVersion(ctx context.Context, vaultID uuid.UUID, userID uuid.UUID, version int) (*model.VaultHistory, error) {
	query := `
		SELECT vh.id, vh.vault_id, vh.version, vh.blob, vh.checksum, vh.created_at
		FROM vault_history vh
		JOIN vaults v ON vh.vault_id = v.id
		WHERE vh.vault_id = $1 AND v.user_id = $2 AND vh.version = $3`

	var entry model.VaultHistory
	err := r.pool.QueryRow(ctx, query, vaultID, userID, version).Scan(
		&entry.ID, &entry.VaultID, &entry.Version, &entry.Blob,
		&entry.Checksum, &entry.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting vault history version: %w", err)
	}
	return &entry, nil
}

func (r *pgVaultRepo) PruneHistory(ctx context.Context, vaultID uuid.UUID, keepCount int) error {
	query := `
		DELETE FROM vault_history
		WHERE vault_id = $1 AND id NOT IN (
			SELECT id FROM vault_history
			WHERE vault_id = $1
			ORDER BY version DESC LIMIT $2
		)`

	_, err := r.pool.Exec(ctx, query, vaultID, keepCount)
	if err != nil {
		return fmt.Errorf("pruning vault history: %w", err)
	}
	return nil
}
