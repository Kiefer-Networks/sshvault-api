package handler

import (
	"context"
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
)

// --- mock device repository ---

type mockDeviceRepo struct {
	devices   []model.Device
	createErr error
	getErr    error
	deleteErr error
	created   *model.Device
	deletedID uuid.UUID
}

func (m *mockDeviceRepo) Create(_ context.Context, device *model.Device) error {
	if m.createErr != nil {
		return m.createErr
	}
	device.ID = uuid.New()
	device.CreatedAt = time.Now()
	m.created = device
	return nil
}

func (m *mockDeviceRepo) GetByUserID(_ context.Context, _ uuid.UUID) ([]model.Device, error) {
	return m.devices, m.getErr
}

func (m *mockDeviceRepo) Delete(_ context.Context, id, _ uuid.UUID) error {
	m.deletedID = id
	return m.deleteErr
}

func (m *mockDeviceRepo) UpdateLastSync(_ context.Context, _, _ uuid.UUID, _ string) error {
	return nil
}

// --- helpers ---

func newDeviceHandler(repo *mockDeviceRepo) *DeviceHandler {
	al := audit.NewNopLogger()
	return NewDeviceHandler(repo, al)
}

func deviceAuthedRequest(r *http.Request, userID uuid.UUID) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.UserIDKey, userID)
	return r.WithContext(ctx)
}

// --- RegisterDevice tests ---

func TestRegisterDevice_NoUserID(t *testing.T) {
	h := newDeviceHandler(&mockDeviceRepo{})

	req := httptest.NewRequest(http.MethodPost, "/devices", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRegisterDevice_InvalidJSON(t *testing.T) {
	h := newDeviceHandler(&mockDeviceRepo{})
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodPost, "/devices", strings.NewReader(`not json`))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRegisterDevice_MissingName(t *testing.T) {
	h := newDeviceHandler(&mockDeviceRepo{})
	userID := uuid.New()

	body := `{"name":"","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/devices", strings.NewReader(body))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if msg != "name is required" {
		t.Errorf("error = %q, want %q", msg, "name is required")
	}
}

func TestRegisterDevice_NameTooLong(t *testing.T) {
	h := newDeviceHandler(&mockDeviceRepo{})
	userID := uuid.New()

	longName := strings.Repeat("a", 256)
	body := fmt.Sprintf(`{"name":"%s","platform":"ios"}`, longName)
	req := httptest.NewRequest(http.MethodPost, "/devices", strings.NewReader(body))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "255") {
		t.Errorf("error = %q, want name length error", msg)
	}
}

func TestRegisterDevice_PlatformTooLong(t *testing.T) {
	h := newDeviceHandler(&mockDeviceRepo{})
	userID := uuid.New()

	longPlatform := strings.Repeat("a", 51)
	body := fmt.Sprintf(`{"name":"My Device","platform":"%s"}`, longPlatform)
	req := httptest.NewRequest(http.MethodPost, "/devices", strings.NewReader(body))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "50") {
		t.Errorf("error = %q, want platform length error", msg)
	}
}

func TestRegisterDevice_DefaultPlatform(t *testing.T) {
	repo := &mockDeviceRepo{}
	h := newDeviceHandler(repo)
	userID := uuid.New()

	body := `{"name":"My Device"}`
	req := httptest.NewRequest(http.MethodPost, "/devices", strings.NewReader(body))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	if repo.created == nil {
		t.Fatal("device not created")
	}
	if repo.created.Platform != "unknown" {
		t.Errorf("platform = %q, want %q", repo.created.Platform, "unknown")
	}
}

func TestRegisterDevice_Success(t *testing.T) {
	repo := &mockDeviceRepo{}
	h := newDeviceHandler(repo)
	userID := uuid.New()

	body := `{"name":"iPhone 15","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/devices", strings.NewReader(body))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if resp["name"] != "iPhone 15" {
		t.Errorf("name = %q, want %q", resp["name"], "iPhone 15")
	}
	if resp["platform"] != "ios" {
		t.Errorf("platform = %q, want %q", resp["platform"], "ios")
	}
	if resp["id"] == nil || resp["id"] == "" {
		t.Error("expected non-empty device id")
	}
}

func TestRegisterDevice_NameExactly255(t *testing.T) {
	repo := &mockDeviceRepo{}
	h := newDeviceHandler(repo)
	userID := uuid.New()

	exactName := strings.Repeat("a", 255)
	body := fmt.Sprintf(`{"name":"%s","platform":"ios"}`, exactName)
	req := httptest.NewRequest(http.MethodPost, "/devices", strings.NewReader(body))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
}

func TestRegisterDevice_PlatformExactly50(t *testing.T) {
	repo := &mockDeviceRepo{}
	h := newDeviceHandler(repo)
	userID := uuid.New()

	exactPlatform := strings.Repeat("a", 50)
	body := fmt.Sprintf(`{"name":"device","platform":"%s"}`, exactPlatform)
	req := httptest.NewRequest(http.MethodPost, "/devices", strings.NewReader(body))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
}

func TestRegisterDevice_RepoError(t *testing.T) {
	repo := &mockDeviceRepo{createErr: fmt.Errorf("database error")}
	h := newDeviceHandler(repo)
	userID := uuid.New()

	body := `{"name":"device","platform":"ios"}`
	req := httptest.NewRequest(http.MethodPost, "/devices", strings.NewReader(body))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// --- ListDevices tests ---

func TestListDevices_NoUserID(t *testing.T) {
	h := newDeviceHandler(&mockDeviceRepo{})

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	rec := httptest.NewRecorder()

	h.ListDevices(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestListDevices_Empty(t *testing.T) {
	repo := &mockDeviceRepo{devices: nil}
	h := newDeviceHandler(repo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.ListDevices(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	var devices []any
	if err := json.Unmarshal(resp["devices"], &devices); err != nil {
		t.Fatalf("decoding devices: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("devices length = %d, want 0", len(devices))
	}
}

func TestListDevices_WithDevices(t *testing.T) {
	repo := &mockDeviceRepo{
		devices: []model.Device{
			{ID: uuid.New(), Name: "Device 1", Platform: "ios", CreatedAt: time.Now()},
			{ID: uuid.New(), Name: "Device 2", Platform: "android", CreatedAt: time.Now()},
		},
	}
	h := newDeviceHandler(repo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.ListDevices(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	var devices []model.Device
	if err := json.Unmarshal(resp["devices"], &devices); err != nil {
		t.Fatalf("decoding devices: %v", err)
	}
	if len(devices) != 2 {
		t.Errorf("devices length = %d, want 2", len(devices))
	}
}

func TestListDevices_RepoError(t *testing.T) {
	repo := &mockDeviceRepo{getErr: fmt.Errorf("database error")}
	h := newDeviceHandler(repo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.ListDevices(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// --- DeleteDevice tests ---

func TestDeleteDevice_NoUserID(t *testing.T) {
	h := newDeviceHandler(&mockDeviceRepo{})

	req := httptest.NewRequest(http.MethodDelete, "/devices/"+uuid.New().String(), nil)
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDeleteDevice_InvalidID(t *testing.T) {
	h := newDeviceHandler(&mockDeviceRepo{})
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodDelete, "/devices/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "invalid device id") {
		t.Errorf("error = %q, want 'invalid device id'", msg)
	}
}

func TestDeleteDevice_Success(t *testing.T) {
	repo := &mockDeviceRepo{}
	h := newDeviceHandler(repo)
	userID := uuid.New()
	deviceID := uuid.New()

	req := httptest.NewRequest(http.MethodDelete, "/devices/"+deviceID.String(), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", deviceID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	if repo.deletedID != deviceID {
		t.Errorf("deleted device ID = %s, want %s", repo.deletedID, deviceID)
	}
}

func TestDeleteDevice_RepoError(t *testing.T) {
	repo := &mockDeviceRepo{deleteErr: fmt.Errorf("database error")}
	h := newDeviceHandler(repo)
	userID := uuid.New()
	deviceID := uuid.New()

	req := httptest.NewRequest(http.MethodDelete, "/devices/"+deviceID.String(), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", deviceID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestDeleteDevice_EmptyID(t *testing.T) {
	h := newDeviceHandler(&mockDeviceRepo{})
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodDelete, "/devices/", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = deviceAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
