package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

type VaultService struct {
	vaultRepo    repository.VaultRepository
	maxSizeBytes int
	historyLimit int
}

func NewVaultService(vaultRepo repository.VaultRepository, maxSizeMB, historyLimit int) *VaultService {
	return &VaultService{
		vaultRepo:    vaultRepo,
		maxSizeBytes: maxSizeMB * 1024 * 1024,
		historyLimit: historyLimit,
	}
}

type PutVaultRequest struct {
	Version  int    `json:"version"`
	Blob     []byte `json:"blob"`
	Checksum string `json:"checksum"`
}

type VaultResponse struct {
	Version   int    `json:"version"`
	Blob      []byte `json:"blob,omitempty"`
	Checksum  string `json:"checksum,omitempty"`
	UpdatedAt int64  `json:"updated_at"`
}

type VaultHistoryEntry struct {
	Version   int    `json:"version"`
	Checksum  string `json:"checksum"`
	CreatedAt int64  `json:"created_at"`
}

func (s *VaultService) GetVault(ctx context.Context, userID uuid.UUID) (*VaultResponse, error) {
	vault, err := s.vaultRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("getting vault: %w", err)
	}
	if vault == nil {
		return &VaultResponse{Version: 0}, nil
	}

	return &VaultResponse{
		Version:   vault.Version,
		Blob:      vault.Blob,
		Checksum:  vault.Checksum,
		UpdatedAt: vault.UpdatedAt.Unix(),
	}, nil
}

func (s *VaultService) PutVault(ctx context.Context, userID uuid.UUID, req *PutVaultRequest) (*VaultResponse, error) {
	if len(req.Blob) > s.maxSizeBytes {
		return nil, fmt.Errorf("blob exceeds maximum size of %d MB", s.maxSizeBytes/(1024*1024))
	}

	// Verify checksum
	hash := sha256.Sum256(req.Blob)
	computed := hex.EncodeToString(hash[:])
	if req.Checksum != computed {
		return nil, fmt.Errorf("checksum mismatch: expected %s, got %s", req.Checksum, computed)
	}

	// Get or create vault
	vault, err := s.vaultRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("getting vault: %w", err)
	}

	if vault == nil {
		// First sync — create vault with version 1
		if req.Version != 1 {
			return nil, fmt.Errorf("first sync must use version 1")
		}
		vault = &model.Vault{
			UserID:   userID,
			Version:  1,
			Blob:     req.Blob,
			Checksum: req.Checksum,
		}
		if err := s.vaultRepo.Upsert(ctx, vault); err != nil {
			return nil, fmt.Errorf("creating vault: %w", err)
		}
	} else {
		// Optimistic locking: expected version must match current
		expectedVersion := vault.Version
		if req.Version != expectedVersion+1 {
			return nil, &ConflictError{
				CurrentVersion: vault.Version,
				Message:        fmt.Sprintf("version conflict: expected %d, got %d", expectedVersion+1, req.Version),
			}
		}

		// Save current version to history before overwriting
		history := &model.VaultHistory{
			VaultID:  vault.ID,
			Version:  vault.Version,
			Blob:     vault.Blob,
			Checksum: vault.Checksum,
		}
		if err := s.vaultRepo.CreateHistory(ctx, history); err != nil {
			return nil, fmt.Errorf("saving vault history: %w", err)
		}

		// Update vault
		updated, err := s.vaultRepo.UpdateBlob(ctx, userID, expectedVersion, req.Blob, req.Checksum)
		if err != nil {
			return nil, fmt.Errorf("updating vault: %w", err)
		}
		if updated == nil {
			return nil, &ConflictError{
				CurrentVersion: vault.Version,
				Message:        "concurrent modification detected",
			}
		}
		vault = updated

		// Prune old history
		if err := s.vaultRepo.PruneHistory(ctx, vault.ID, s.historyLimit); err != nil {
			// Non-fatal: log but don't fail the request
			_ = err
		}
	}

	return &VaultResponse{
		Version:   vault.Version,
		Checksum:  vault.Checksum,
		UpdatedAt: vault.UpdatedAt.Unix(),
	}, nil
}

func (s *VaultService) GetHistory(ctx context.Context, userID uuid.UUID) ([]VaultHistoryEntry, error) {
	vault, err := s.vaultRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("getting vault: %w", err)
	}
	if vault == nil {
		return nil, nil
	}

	entries, err := s.vaultRepo.GetHistory(ctx, vault.ID, s.historyLimit)
	if err != nil {
		return nil, fmt.Errorf("getting history: %w", err)
	}

	result := make([]VaultHistoryEntry, len(entries))
	for i, e := range entries {
		result[i] = VaultHistoryEntry{
			Version:   e.Version,
			Checksum:  e.Checksum,
			CreatedAt: e.CreatedAt.Unix(),
		}
	}
	return result, nil
}

func (s *VaultService) GetHistoryVersion(ctx context.Context, userID uuid.UUID, version int) (*VaultResponse, error) {
	vault, err := s.vaultRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("getting vault: %w", err)
	}
	if vault == nil {
		return nil, fmt.Errorf("vault not found")
	}

	entry, err := s.vaultRepo.GetHistoryVersion(ctx, vault.ID, version)
	if err != nil {
		return nil, fmt.Errorf("getting history version: %w", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("version %d not found", version)
	}

	return &VaultResponse{
		Version:   entry.Version,
		Blob:      entry.Blob,
		Checksum:  entry.Checksum,
		UpdatedAt: entry.CreatedAt.Unix(),
	}, nil
}

// ConflictError represents a version conflict during vault sync.
type ConflictError struct {
	CurrentVersion int    `json:"current_version"`
	Message        string `json:"message"`
}

func (e *ConflictError) Error() string {
	return e.Message
}
