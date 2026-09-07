package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kiefernetworks/shellvault-server/internal/model"
)

// --- Mock Vault Repository ---

type mockVaultRepo struct {
	vaults         map[uuid.UUID]*model.Vault // key: userID
	histories      map[uuid.UUID][]model.VaultHistory
	rejectBlobRead bool
}

func newMockVaultRepo() *mockVaultRepo {
	return &mockVaultRepo{
		vaults:    make(map[uuid.UUID]*model.Vault),
		histories: make(map[uuid.UUID][]model.VaultHistory),
	}
}

func (m *mockVaultRepo) GetByUserID(_ context.Context, userID uuid.UUID) (*model.Vault, error) {
	if m.rejectBlobRead {
		return nil, errors.New("full vault read attempted")
	}
	v := m.vaults[userID]
	return v, nil
}

func (m *mockVaultRepo) GetMetadataByUserID(_ context.Context, userID uuid.UUID) (*model.Vault, error) {
	return m.vaults[userID], nil
}

func (m *mockVaultRepo) Create(_ context.Context, vault *model.Vault) error {
	vault.ID = uuid.New()
	vault.UpdatedAt = time.Now()
	m.vaults[vault.UserID] = vault
	return nil
}

func (m *mockVaultRepo) UpdateBlob(_ context.Context, userID uuid.UUID, expectedVersion int, blob []byte, checksum string) (*model.Vault, error) {
	v := m.vaults[userID]
	if v == nil || v.Version != expectedVersion {
		return nil, nil
	}
	v.Version++
	v.Blob = blob
	v.Checksum = checksum
	v.UpdatedAt = time.Now()
	return v, nil
}

func (m *mockVaultRepo) CreateHistory(_ context.Context, entry *model.VaultHistory) error {
	entry.ID = uuid.New()
	entry.CreatedAt = time.Now()
	m.histories[entry.VaultID] = append(m.histories[entry.VaultID], *entry)
	return nil
}

func (m *mockVaultRepo) GetHistory(_ context.Context, vaultID uuid.UUID, _ uuid.UUID, limit int) ([]model.VaultHistory, error) {
	h := m.histories[vaultID]
	if len(h) > limit {
		h = h[len(h)-limit:]
	}
	return h, nil
}

func (m *mockVaultRepo) GetHistoryVersion(_ context.Context, vaultID uuid.UUID, _ uuid.UUID, version int) (*model.VaultHistory, error) {
	for _, e := range m.histories[vaultID] {
		if e.Version == version {
			return &e, nil
		}
	}
	return nil, nil
}

func (m *mockVaultRepo) PruneHistory(_ context.Context, _ uuid.UUID, _ int) error {
	return nil
}

// --- Helper ---

func blobChecksum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// --- Tests ---

func TestGetVaultEmpty(t *testing.T) {
	repo := newMockVaultRepo()
	svc := NewVaultService(repo, nil, 10, 20)

	resp, err := svc.GetVault(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("GetVault: %v", err)
	}
	if resp.Version != 0 {
		t.Errorf("version = %d, want 0", resp.Version)
	}
}

func TestGetVaultExisting(t *testing.T) {
	repo := newMockVaultRepo()
	svc := NewVaultService(repo, nil, 10, 20)
	userID := uuid.New()

	blob := []byte(`{"encrypted":"data"}`)
	repo.vaults[userID] = &model.Vault{
		ID:        uuid.New(),
		UserID:    userID,
		Version:   3,
		Blob:      blob,
		Checksum:  blobChecksum(blob),
		UpdatedAt: time.Now(),
	}

	resp, err := svc.GetVault(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetVault: %v", err)
	}
	if resp.Version != 3 {
		t.Errorf("version = %d, want 3", resp.Version)
	}
	if string(resp.Blob) != `{"encrypted":"data"}` {
		t.Errorf("blob = %q, want encrypted data", string(resp.Blob))
	}
}

func TestPutVaultFirstSync(t *testing.T) {
	repo := newMockVaultRepo()
	svc := NewVaultService(repo, nil, 10, 20)
	userID := uuid.New()
	blob := []byte(`{"servers":[]}`)

	resp, err := svc.PutVault(context.Background(), userID, &PutVaultRequest{
		Version:  1,
		Blob:     blob,
		Checksum: blobChecksum(blob),
	})
	if err != nil {
		t.Fatalf("PutVault: %v", err)
	}
	if resp.Version != 1 {
		t.Errorf("version = %d, want 1", resp.Version)
	}
}

func TestPutVaultFirstSyncWrongVersion(t *testing.T) {
	repo := newMockVaultRepo()
	svc := NewVaultService(repo, nil, 10, 20)
	blob := []byte(`test`)

	_, err := svc.PutVault(context.Background(), uuid.New(), &PutVaultRequest{
		Version:  5,
		Blob:     blob,
		Checksum: blobChecksum(blob),
	})
	if err == nil {
		t.Fatal("expected error for wrong initial version")
	}
	if !strings.Contains(err.Error(), "first sync must use version 1") {
		t.Errorf("error = %q, want 'first sync must use version 1'", err.Error())
	}
}

func TestPutVaultChecksumMismatch(t *testing.T) {
	repo := newMockVaultRepo()
	svc := NewVaultService(repo, nil, 10, 20)

	_, err := svc.PutVault(context.Background(), uuid.New(), &PutVaultRequest{
		Version:  1,
		Blob:     []byte(`data`),
		Checksum: "wrong-checksum",
	})
	if err == nil {
		t.Fatal("expected error for checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("error = %q, want 'checksum mismatch'", err.Error())
	}
}

func TestPutVaultSizeLimit(t *testing.T) {
	repo := newMockVaultRepo()
	svc := NewVaultService(repo, nil, 1, 20) // 1 MB limit

	bigBlob := make([]byte, 2*1024*1024) // 2 MB

	_, err := svc.PutVault(context.Background(), uuid.New(), &PutVaultRequest{
		Version:  1,
		Blob:     bigBlob,
		Checksum: blobChecksum(bigBlob),
	})
	if err == nil {
		t.Fatal("expected error for oversized blob")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("error = %q, want 'exceeds maximum size'", err.Error())
	}
}

func TestVault15MiBBoundary(t *testing.T) {
	repo := newMockVaultRepo()
	svc := NewVaultService(repo, nil, 15, 10)
	blob := make([]byte, 15*1024*1024+1)
	accepted := blob[:15*1024*1024]
	if _, err := svc.PutVault(context.Background(), uuid.New(), &PutVaultRequest{
		Version: 1, Blob: accepted, Checksum: blobChecksum(accepted),
	}); err != nil {
		t.Fatalf("15 MiB vault rejected: %v", err)
	}
	if _, err := svc.PutVault(context.Background(), uuid.New(), &PutVaultRequest{
		Version: 1, Blob: blob, Checksum: "not evaluated for oversized data",
	}); err == nil {
		t.Fatal("vault exceeding 15 MiB accepted")
	}
}

func TestGetHistoryEmpty(t *testing.T) {
	repo := newMockVaultRepo()
	svc := NewVaultService(repo, nil, 10, 20)

	entries, err := svc.GetHistory(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	// Must be a non-nil empty slice, not nil: the handler serializes this
	// directly to JSON, and nil would encode as "history": null instead of [].
	if entries == nil {
		t.Error("expected non-nil empty slice for non-existent vault, got nil")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for non-existent vault, got %d", len(entries))
	}
}

func TestGetHistoryVersionNotFound(t *testing.T) {
	repo := newMockVaultRepo()
	svc := NewVaultService(repo, nil, 10, 20)
	userID := uuid.New()

	repo.vaults[userID] = &model.Vault{
		ID:        uuid.New(),
		UserID:    userID,
		Version:   1,
		UpdatedAt: time.Now(),
	}

	_, err := svc.GetHistoryVersion(context.Background(), userID, 99)
	if err == nil {
		t.Fatal("expected error for non-existent version")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want 'not found'", err.Error())
	}
}

func TestHistoryEndpointsDoNotReadCurrentBlob(t *testing.T) {
	repo := newMockVaultRepo()
	userID := uuid.New()
	vaultID := uuid.New()
	repo.vaults[userID] = &model.Vault{ID: vaultID, UserID: userID, Version: 2, Blob: make([]byte, MaxVaultSizeBytes)}
	repo.histories[vaultID] = []model.VaultHistory{{VaultID: vaultID, Version: 1, Blob: []byte("old")}}
	repo.rejectBlobRead = true
	svc := NewVaultService(repo, nil, 15, 20)

	if _, err := svc.GetHistory(context.Background(), userID); err != nil {
		t.Fatalf("history metadata read current blob: %v", err)
	}
	if _, err := svc.GetHistoryVersion(context.Background(), userID, 1); err != nil {
		t.Fatalf("history version read current blob: %v", err)
	}
}
