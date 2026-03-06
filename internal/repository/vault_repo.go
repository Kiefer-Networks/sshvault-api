package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
)

type VaultRepository interface {
	GetByUserID(ctx context.Context, userID uuid.UUID) (*model.Vault, error)
	Upsert(ctx context.Context, vault *model.Vault) error
	UpdateBlob(ctx context.Context, userID uuid.UUID, expectedVersion int, blob []byte, checksum string) (*model.Vault, error)

	// History
	CreateHistory(ctx context.Context, entry *model.VaultHistory) error
	GetHistory(ctx context.Context, vaultID uuid.UUID, userID uuid.UUID, limit int) ([]model.VaultHistory, error)
	GetHistoryVersion(ctx context.Context, vaultID uuid.UUID, userID uuid.UUID, version int) (*model.VaultHistory, error)
	PruneHistory(ctx context.Context, vaultID uuid.UUID, keepCount int) error
}
