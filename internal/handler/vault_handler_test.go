package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

// --- mock vault repository ---

type mockVaultRepo struct {
	vault   *model.Vault
	history []model.VaultHistory
	err     error
}

func (m *mockVaultRepo) GetByUserID(_ context.Context, _ uuid.UUID) (*model.Vault, error) {
	return m.vault, m.err
}

func (m *mockVaultRepo) Upsert(_ context.Context, v *model.Vault) error {
	m.vault = v
	return m.err
}

func (m *mockVaultRepo) UpdateBlob(_ context.Context, _ uuid.UUID, _ int, blob []byte, checksum string) (*model.Vault, error) {
	if m.vault == nil {
		return nil, m.err
	}
	m.vault.Version++
	m.vault.Blob = blob
	m.vault.Checksum = checksum
	m.vault.UpdatedAt = time.Now()
	return m.vault, m.err
}

func (m *mockVaultRepo) CreateHistory(_ context.Context, _ *model.VaultHistory) error {
	return m.err
}

func (m *mockVaultRepo) GetHistory(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ int) ([]model.VaultHistory, error) {
	return m.history, m.err
}

func (m *mockVaultRepo) GetHistoryVersion(_ context.Context, _ uuid.UUID, _ uuid.UUID, version int) (*model.VaultHistory, error) {
	for _, h := range m.history {
		if h.Version == version {
			return &h, nil
		}
	}
	return nil, m.err
}

func (m *mockVaultRepo) PruneHistory(_ context.Context, _ uuid.UUID, _ int) error {
	return nil
}

// --- helpers ---

func newTestAuditLogger() *audit.Logger {
	return audit.NewNopLogger()
}

func authedRequest(r *http.Request, userID uuid.UUID) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.UserIDKey, userID)
	return r.WithContext(ctx)
}

type mockDeviceRepoForVault struct{}

func (m *mockDeviceRepoForVault) Create(_ context.Context, _ *model.Device) error { return nil }
func (m *mockDeviceRepoForVault) GetByUserID(_ context.Context, _ uuid.UUID) ([]model.Device, error) {
	return nil, nil
}
func (m *mockDeviceRepoForVault) Delete(_ context.Context, _, _ uuid.UUID) error { return nil }
func (m *mockDeviceRepoForVault) UpdateLastSync(_ context.Context, _, _ uuid.UUID, _ string) error {
	return nil
}

func newVaultHandler(vaultRepo repository.VaultRepository) *VaultHandler {
	vs := service.NewVaultService(vaultRepo, nil, 10, 10)
	al := newTestAuditLogger()
	return NewVaultHandler(vs, &mockDeviceRepoForVault{}, al)
}

func blobChecksum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// --- GetVault tests ---

func TestGetVault_NoUserID(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})

	req := httptest.NewRequest(http.MethodGet, "/vault", nil)
	rec := httptest.NewRecorder()

	h.GetVault(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestGetVault_EmptyVault(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/vault", nil)
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetVault(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp service.VaultResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Version != 0 {
		t.Errorf("version = %d, want 0", resp.Version)
	}
}

func TestGetVault_ExistingVault(t *testing.T) {
	blob := []byte("encrypted-vault-data")
	checksum := blobChecksum(blob)
	vaultRepo := &mockVaultRepo{
		vault: &model.Vault{
			ID:        uuid.New(),
			Version:   3,
			Blob:      blob,
			Checksum:  checksum,
			UpdatedAt: time.Now(),
		},
	}
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/vault", nil)
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetVault(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp service.VaultResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Version != 3 {
		t.Errorf("version = %d, want 3", resp.Version)
	}
	if resp.Checksum != checksum {
		t.Errorf("checksum = %q, want %q", resp.Checksum, checksum)
	}
}

func TestGetVault_ServiceError(t *testing.T) {
	vaultRepo := &mockVaultRepo{
		err: fmt.Errorf("database error"),
	}
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/vault", nil)
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetVault(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// --- PutVault tests ---

func TestPutVault_NoUserID(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})

	req := httptest.NewRequest(http.MethodPut, "/vault", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	h.PutVault(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestPutVault_InvalidJSON(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodPut, "/vault", strings.NewReader(`not json`))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.PutVault(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestPutVault_VersionZero(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})
	userID := uuid.New()

	body := `{"version":0,"blob":"AQID","checksum":"abc"}`
	req := httptest.NewRequest(http.MethodPut, "/vault", strings.NewReader(body))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.PutVault(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "version must be >= 1") {
		t.Errorf("error = %q, want version error", msg)
	}
}

func TestPutVault_EmptyBlob(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})
	userID := uuid.New()

	body := `{"version":1,"blob":"","checksum":"abc"}`
	req := httptest.NewRequest(http.MethodPut, "/vault", strings.NewReader(body))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.PutVault(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "blob is required") {
		t.Errorf("error = %q, want blob error", msg)
	}
}

func TestPutVault_EmptyChecksum(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})
	userID := uuid.New()

	body := `{"version":1,"blob":"AQID","checksum":""}`
	req := httptest.NewRequest(http.MethodPut, "/vault", strings.NewReader(body))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.PutVault(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "checksum is required") {
		t.Errorf("error = %q, want checksum error", msg)
	}
}

func TestPutVault_FirstSync_Success(t *testing.T) {
	vaultRepo := &mockVaultRepo{}
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	blob := []byte{1, 2, 3}
	checksum := blobChecksum(blob)
	// blob is base64 encoded in JSON: [1,2,3] -> "AQID"
	body := fmt.Sprintf(`{"version":1,"blob":"AQID","checksum":"%s"}`, checksum)

	req := httptest.NewRequest(http.MethodPut, "/vault", strings.NewReader(body))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.PutVault(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestPutVault_ChecksumMismatch(t *testing.T) {
	vaultRepo := &mockVaultRepo{}
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	body := `{"version":1,"blob":"AQID","checksum":"wrong-checksum"}`
	req := httptest.NewRequest(http.MethodPut, "/vault", strings.NewReader(body))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.PutVault(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if msg != "failed to update vault" {
		t.Errorf("error = %q, want %q", msg, "failed to update vault")
	}
}

func TestPutVault_FirstSync_WrongVersion(t *testing.T) {
	vaultRepo := &mockVaultRepo{} // nil vault = first sync
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	blob := []byte{1, 2, 3}
	checksum := blobChecksum(blob)
	body := fmt.Sprintf(`{"version":2,"blob":"AQID","checksum":"%s"}`, checksum)

	req := httptest.NewRequest(http.MethodPut, "/vault", strings.NewReader(body))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.PutVault(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if msg != "failed to update vault" {
		t.Errorf("error = %q, want %q", msg, "failed to update vault")
	}
}

func TestPutVault_VersionConflict(t *testing.T) {
	vaultRepo := &mockVaultRepo{
		vault: &model.Vault{
			ID:        uuid.New(),
			Version:   3,
			Blob:      []byte{4, 5, 6},
			Checksum:  blobChecksum([]byte{4, 5, 6}),
			UpdatedAt: time.Now(),
		},
	}
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	blob := []byte{1, 2, 3}
	checksum := blobChecksum(blob)
	// Send version 2 when current is 3 (expected would be 4)
	body := fmt.Sprintf(`{"version":2,"blob":"AQID","checksum":"%s"}`, checksum)

	req := httptest.NewRequest(http.MethodPut, "/vault", strings.NewReader(body))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.PutVault(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

// --- GetHistory tests ---

func TestGetHistory_NoUserID(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})

	req := httptest.NewRequest(http.MethodGet, "/vault/history", nil)
	rec := httptest.NewRecorder()

	h.GetHistory(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestGetHistory_EmptyHistory(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/vault/history", nil)
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetHistory(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestGetHistory_WithEntries(t *testing.T) {
	vaultID := uuid.New()
	vaultRepo := &mockVaultRepo{
		vault: &model.Vault{
			ID:        vaultID,
			Version:   3,
			UpdatedAt: time.Now(),
		},
		history: []model.VaultHistory{
			{Version: 1, Checksum: "abc", CreatedAt: time.Now()},
			{Version: 2, Checksum: "def", CreatedAt: time.Now()},
		},
	}
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/vault/history", nil)
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetHistory(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if _, ok := resp["history"]; !ok {
		t.Error("response missing 'history' key")
	}
}

func TestGetHistory_ServiceError(t *testing.T) {
	vaultRepo := &mockVaultRepo{
		err: fmt.Errorf("database error"),
	}
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/vault/history", nil)
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetHistory(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// --- GetHistoryVersion tests ---

func TestGetHistoryVersion_NoUserID(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})

	req := httptest.NewRequest(http.MethodGet, "/vault/history/1", nil)
	rec := httptest.NewRecorder()

	h.GetHistoryVersion(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestGetHistoryVersion_InvalidVersion(t *testing.T) {
	h := newVaultHandler(&mockVaultRepo{})
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/vault/history/abc", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("version", "abc")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetHistoryVersion(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if msg != "invalid version" {
		t.Errorf("error = %q, want %q", msg, "invalid version")
	}
}

func TestGetHistoryVersion_NotFound(t *testing.T) {
	vaultRepo := &mockVaultRepo{
		vault: &model.Vault{
			ID:        uuid.New(),
			Version:   3,
			UpdatedAt: time.Now(),
		},
		history: []model.VaultHistory{}, // no history entries
	}
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/vault/history/1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("version", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetHistoryVersion(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGetHistoryVersion_Success(t *testing.T) {
	vaultID := uuid.New()
	vaultRepo := &mockVaultRepo{
		vault: &model.Vault{
			ID:        vaultID,
			Version:   3,
			UpdatedAt: time.Now(),
		},
		history: []model.VaultHistory{
			{Version: 1, Blob: []byte{1}, Checksum: "abc", CreatedAt: time.Now()},
			{Version: 2, Blob: []byte{2}, Checksum: "def", CreatedAt: time.Now()},
		},
	}
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/vault/history/2", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("version", "2")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetHistoryVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp service.VaultResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Version != 2 {
		t.Errorf("version = %d, want 2", resp.Version)
	}
	if resp.Checksum != "def" {
		t.Errorf("checksum = %q, want %q", resp.Checksum, "def")
	}
}

func TestGetHistoryVersion_NoVault(t *testing.T) {
	vaultRepo := &mockVaultRepo{} // nil vault
	h := newVaultHandler(vaultRepo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/vault/history/1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("version", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = authedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetHistoryVersion(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
