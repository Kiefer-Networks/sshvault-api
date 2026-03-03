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

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

// --- mock user repository ---

type mockUserRepo struct {
	user     *model.User
	getErr   error
	updateFn func(ctx context.Context, user *model.User) error
}

func (m *mockUserRepo) Create(_ context.Context, _ *model.User) error {
	return nil
}

func (m *mockUserRepo) GetByID(_ context.Context, _ uuid.UUID) (*model.User, error) {
	return m.user, m.getErr
}

func (m *mockUserRepo) GetByEmail(_ context.Context, email string) (*model.User, error) {
	if m.user != nil && m.user.Email == email {
		return m.user, nil
	}
	return nil, nil
}

func (m *mockUserRepo) Update(ctx context.Context, user *model.User) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, user)
	}
	return nil
}

func (m *mockUserRepo) SoftDelete(_ context.Context, _ uuid.UUID) error {
	return nil
}

func (m *mockUserRepo) PurgeDeleted(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockUserRepo) GetPurgableUserIDs(_ context.Context, _ time.Time) ([]uuid.UUID, error) {
	return nil, nil
}

func (m *mockUserRepo) CreateOAuthAccount(_ context.Context, _ *model.OAuthAccount) error {
	return nil
}

func (m *mockUserRepo) GetOAuthAccount(_ context.Context, _, _ string) (*model.OAuthAccount, error) {
	return nil, nil
}

func (m *mockUserRepo) GetOAuthAccountsByUser(_ context.Context, _ uuid.UUID) ([]model.OAuthAccount, error) {
	return nil, nil
}

// --- mock token repository ---

type mockTokenRepo struct{}

func (m *mockTokenRepo) Create(_ context.Context, _ *model.RefreshToken) error {
	return nil
}

func (m *mockTokenRepo) GetByHash(_ context.Context, _ string) (*model.RefreshToken, error) {
	return nil, nil
}

func (m *mockTokenRepo) Revoke(_ context.Context, _ uuid.UUID) error {
	return nil
}

func (m *mockTokenRepo) RevokeAllForUser(_ context.Context, _ uuid.UUID) error {
	return nil
}

func (m *mockTokenRepo) DeleteExpired(_ context.Context) (int64, error) {
	return 0, nil
}

// --- helpers ---

func newUserHandler(userRepo repository.UserRepository) *UserHandler {
	us := service.NewUserService(userRepo, &mockTokenRepo{}, nil)
	al := audit.NewNopLogger()
	return NewUserHandler(us, al)
}

func userAuthedRequest(r *http.Request, userID uuid.UUID) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.UserIDKey, userID)
	return r.WithContext(ctx)
}

// --- GetProfile tests ---

func TestGetProfile_NoUserID(t *testing.T) {
	h := newUserHandler(&mockUserRepo{})

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	rec := httptest.NewRecorder()

	h.GetProfile(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestGetProfile_UserNotFound(t *testing.T) {
	h := newUserHandler(&mockUserRepo{}) // nil user
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetProfile(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "not found") {
		t.Errorf("error = %q, want 'not found'", msg)
	}
}

func TestGetProfile_Success(t *testing.T) {
	userID := uuid.New()
	userRepo := &mockUserRepo{
		user: &model.User{
			ID:        userID,
			Email:     "test@example.com",
			Verified:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	h := newUserHandler(userRepo)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp model.User
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Email != "test@example.com" {
		t.Errorf("email = %q, want %q", resp.Email, "test@example.com")
	}
	if resp.ID != userID {
		t.Errorf("id = %s, want %s", resp.ID, userID)
	}
}

func TestGetProfile_RepoError(t *testing.T) {
	userRepo := &mockUserRepo{getErr: fmt.Errorf("database error")}
	h := newUserHandler(userRepo)
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetProfile(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// --- UpdateProfile tests ---

func TestUpdateProfile_NoUserID(t *testing.T) {
	h := newUserHandler(&mockUserRepo{})

	req := httptest.NewRequest(http.MethodPut, "/me", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestUpdateProfile_InvalidJSON(t *testing.T) {
	h := newUserHandler(&mockUserRepo{})
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodPut, "/me", strings.NewReader(`not json`))
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestUpdateProfile_EmailTooLong(t *testing.T) {
	h := newUserHandler(&mockUserRepo{})
	userID := uuid.New()

	longEmail := strings.Repeat("a", 255) + "@example.com"
	body := fmt.Sprintf(`{"email":"%s"}`, longEmail)

	req := httptest.NewRequest(http.MethodPut, "/me", strings.NewReader(body))
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "254") {
		t.Errorf("error = %q, want message about 254 characters", msg)
	}
}

func TestUpdateProfile_Success(t *testing.T) {
	userID := uuid.New()
	userRepo := &mockUserRepo{
		user: &model.User{
			ID:        userID,
			Email:     "old@example.com",
			Verified:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	h := newUserHandler(userRepo)

	body := `{"email":"new@example.com"}`
	req := httptest.NewRequest(http.MethodPut, "/me", strings.NewReader(body))
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestUpdateProfile_NoChanges(t *testing.T) {
	userID := uuid.New()
	userRepo := &mockUserRepo{
		user: &model.User{
			ID:        userID,
			Email:     "same@example.com",
			Verified:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	h := newUserHandler(userRepo)

	body := `{}`
	req := httptest.NewRequest(http.MethodPut, "/me", strings.NewReader(body))
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestUpdateProfile_ServiceError(t *testing.T) {
	userRepo := &mockUserRepo{getErr: fmt.Errorf("db error")}
	h := newUserHandler(userRepo)
	userID := uuid.New()

	body := `{"email":"new@example.com"}`
	req := httptest.NewRequest(http.MethodPut, "/me", strings.NewReader(body))
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.UpdateProfile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- DeleteAccount tests ---

func TestDeleteAccount_NoUserID(t *testing.T) {
	h := newUserHandler(&mockUserRepo{})

	req := httptest.NewRequest(http.MethodDelete, "/me", nil)
	rec := httptest.NewRecorder()

	h.DeleteAccount(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// Note: TestDeleteAccount_ServiceError is not included because DeleteAccount
// calls Transactor.WithTransaction, and the nil Transactor cannot be safely
// tested without a real or mock database pool.

// --- ChangePassword tests ---

func TestChangePassword_NoUserID(t *testing.T) {
	h := newUserHandler(&mockUserRepo{})

	req := httptest.NewRequest(http.MethodPost, "/me/password", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestChangePassword_InvalidJSON(t *testing.T) {
	h := newUserHandler(&mockUserRepo{})
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodPost, "/me/password", strings.NewReader(`not json`))
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestChangePassword_MissingCurrentPassword(t *testing.T) {
	h := newUserHandler(&mockUserRepo{})
	userID := uuid.New()

	body := `{"current_password":"","new_password":"newpass123"}`
	req := httptest.NewRequest(http.MethodPost, "/me/password", strings.NewReader(body))
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "current_password is required") {
		t.Errorf("error = %q, want current_password error", msg)
	}
}

func TestChangePassword_ShortNewPassword(t *testing.T) {
	h := newUserHandler(&mockUserRepo{})
	userID := uuid.New()

	body := `{"current_password":"oldpass123","new_password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/me/password", strings.NewReader(body))
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "at least 8") {
		t.Errorf("error = %q, want 'at least 8 characters'", msg)
	}
}

func TestChangePassword_ExactlyMinLength(t *testing.T) {
	h := newUserHandler(&mockUserRepo{})
	userID := uuid.New()

	// Exactly 8 characters should pass handler validation, but will fail at service
	// level because user not found (nil user repo).
	body := `{"current_password":"oldpass1","new_password":"12345678"}`
	req := httptest.NewRequest(http.MethodPost, "/me/password", strings.NewReader(body))
	req = userAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	// Service should return error (user not found), handler returns 400
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
