package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/model"
)

// --- Mock Repositories for UserService Tests ---

type userSvcMockUserRepo struct {
	users      map[uuid.UUID]*model.User
	emailIndex map[string]*model.User
	getByIDErr    error
	getByEmailErr error
	updateErr     error
	softDeleteErr error
}

func newUserSvcMockUserRepo() *userSvcMockUserRepo {
	return &userSvcMockUserRepo{
		users:      make(map[uuid.UUID]*model.User),
		emailIndex: make(map[string]*model.User),
	}
}

func (m *userSvcMockUserRepo) Create(_ context.Context, user *model.User) error {
	user.ID = uuid.New()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	m.emailIndex[user.Email] = user
	return nil
}

func (m *userSvcMockUserRepo) GetByID(_ context.Context, id uuid.UUID) (*model.User, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	return m.users[id], nil
}

func (m *userSvcMockUserRepo) GetByEmail(_ context.Context, email string) (*model.User, error) {
	if m.getByEmailErr != nil {
		return nil, m.getByEmailErr
	}
	return m.emailIndex[email], nil
}

func (m *userSvcMockUserRepo) Update(_ context.Context, user *model.User) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.users[user.ID] = user
	m.emailIndex[user.Email] = user
	return nil
}

func (m *userSvcMockUserRepo) SoftDelete(_ context.Context, id uuid.UUID) error {
	if m.softDeleteErr != nil {
		return m.softDeleteErr
	}
	if u, ok := m.users[id]; ok {
		now := time.Now()
		u.DeletedAt = &now
	}
	return nil
}

func (m *userSvcMockUserRepo) PurgeDeleted(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *userSvcMockUserRepo) GetPurgableUserIDs(_ context.Context, _ time.Time) ([]uuid.UUID, error) {
	return nil, nil
}

type userSvcMockTokenRepo struct {
	tokens     map[uuid.UUID]*model.RefreshToken
	revokeErr  error
	revokedAll bool
}

func newUserSvcMockTokenRepo() *userSvcMockTokenRepo {
	return &userSvcMockTokenRepo{
		tokens: make(map[uuid.UUID]*model.RefreshToken),
	}
}

func (m *userSvcMockTokenRepo) Create(_ context.Context, token *model.RefreshToken) error {
	token.ID = uuid.New()
	token.CreatedAt = time.Now()
	m.tokens[token.ID] = token
	return nil
}

func (m *userSvcMockTokenRepo) GetByHash(_ context.Context, _ string) (*model.RefreshToken, error) {
	return nil, nil
}

func (m *userSvcMockTokenRepo) Revoke(_ context.Context, id uuid.UUID) error {
	if t, ok := m.tokens[id]; ok {
		t.Revoked = true
	}
	return nil
}

func (m *userSvcMockTokenRepo) RevokeAllForUser(_ context.Context, userID uuid.UUID) error {
	if m.revokeErr != nil {
		return m.revokeErr
	}
	m.revokedAll = true
	for _, t := range m.tokens {
		if t.UserID == userID {
			t.Revoked = true
		}
	}
	return nil
}

func (m *userSvcMockTokenRepo) DeleteExpired(_ context.Context) (int64, error) { return 0, nil }

// --- Helpers ---

func seedUser(repo *userSvcMockUserRepo, email, password string) *model.User {
	id := uuid.New()
	var hash string
	if password != "" {
		var err error
		hash, err = auth.HashPassword(password)
		if err != nil {
			panic(err)
		}
	}
	user := &model.User{
		ID:        id,
		Email:     email,
		Password:  hash,
		Verified:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	repo.users[id] = user
	repo.emailIndex[email] = user
	return user
}

func newUserService(repo *userSvcMockUserRepo, tokenRepo *userSvcMockTokenRepo) *UserService {
	return &UserService{
		userRepo:  repo,
		tokenRepo: tokenRepo,
		tx:        nil, // Transaction-dependent methods tested separately
	}
}

// --- GetProfile Tests ---

func TestGetProfileSuccess(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	user := seedUser(repo, "profile@example.com", "password123")

	result, err := svc.GetProfile(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if result.ID != user.ID {
		t.Errorf("ID = %v, want %v", result.ID, user.ID)
	}
	if result.Email != "profile@example.com" {
		t.Errorf("Email = %q, want %q", result.Email, "profile@example.com")
	}
}

func TestGetProfileNotFound(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())

	_, err := svc.GetProfile(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error for non-existent user")
	}
	if !strings.Contains(err.Error(), "user not found") {
		t.Errorf("error = %q, want 'user not found'", err.Error())
	}
}

func TestGetProfileRepoError(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	repo.getByIDErr = fmt.Errorf("database connection lost")
	svc := newUserService(repo, newUserSvcMockTokenRepo())

	_, err := svc.GetProfile(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
	if !strings.Contains(err.Error(), "getting user") {
		t.Errorf("error = %q, want 'getting user'", err.Error())
	}
}

// --- UpdateProfile Tests ---

func TestUpdateProfileEmailChange(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	user := seedUser(repo, "old@example.com", "password123")

	result, err := svc.UpdateProfile(context.Background(), user.ID, &UpdateProfileRequest{
		Email: "new@example.com",
	})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if result.Email != "new@example.com" {
		t.Errorf("Email = %q, want %q", result.Email, "new@example.com")
	}
	if result.Verified {
		t.Error("user should be unverified after email change")
	}
}

func TestUpdateProfileSameEmail(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	user := seedUser(repo, "same@example.com", "password123")

	result, err := svc.UpdateProfile(context.Background(), user.ID, &UpdateProfileRequest{
		Email: "same@example.com",
	})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if !result.Verified {
		t.Error("verified should not change when email stays the same")
	}
}

func TestUpdateProfileEmptyEmail(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	user := seedUser(repo, "keep@example.com", "password123")

	result, err := svc.UpdateProfile(context.Background(), user.ID, &UpdateProfileRequest{
		Email: "",
	})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if result.Email != "keep@example.com" {
		t.Errorf("Email = %q, want %q (unchanged)", result.Email, "keep@example.com")
	}
}

func TestUpdateProfileInvalidEmail(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	user := seedUser(repo, "valid@example.com", "password123")

	_, err := svc.UpdateProfile(context.Background(), user.ID, &UpdateProfileRequest{
		Email: "not-an-email",
	})
	if err == nil {
		t.Fatal("expected error for invalid email")
	}
	if !strings.Contains(err.Error(), "invalid email format") {
		t.Errorf("error = %q, want 'invalid email format'", err.Error())
	}
}

func TestUpdateProfileEmailAlreadyInUse(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	seedUser(repo, "taken@example.com", "password123")
	user := seedUser(repo, "original@example.com", "password123")

	_, err := svc.UpdateProfile(context.Background(), user.ID, &UpdateProfileRequest{
		Email: "taken@example.com",
	})
	if err == nil {
		t.Fatal("expected error for email already in use")
	}
	if !strings.Contains(err.Error(), "email already in use") {
		t.Errorf("error = %q, want 'email already in use'", err.Error())
	}
}

func TestUpdateProfileNormalizesEmail(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	user := seedUser(repo, "old@example.com", "password123")

	result, err := svc.UpdateProfile(context.Background(), user.ID, &UpdateProfileRequest{
		Email: "  NEW@EXAMPLE.COM  ",
	})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if result.Email != "new@example.com" {
		t.Errorf("Email = %q, want %q", result.Email, "new@example.com")
	}
}

func TestUpdateProfileUserNotFound(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())

	_, err := svc.UpdateProfile(context.Background(), uuid.New(), &UpdateProfileRequest{
		Email: "new@example.com",
	})
	if err == nil {
		t.Fatal("expected error for non-existent user")
	}
	if !strings.Contains(err.Error(), "user not found") {
		t.Errorf("error = %q, want 'user not found'", err.Error())
	}
}

func TestUpdateProfileRepoGetError(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	repo.getByIDErr = fmt.Errorf("db error")
	svc := newUserService(repo, newUserSvcMockTokenRepo())

	_, err := svc.UpdateProfile(context.Background(), uuid.New(), &UpdateProfileRequest{
		Email: "new@example.com",
	})
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
	if !strings.Contains(err.Error(), "getting user") {
		t.Errorf("error = %q, want 'getting user'", err.Error())
	}
}

func TestUpdateProfileEmailCheckError(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	user := seedUser(repo, "current@example.com", "password123")

	repo.getByEmailErr = fmt.Errorf("db lookup error")

	_, err := svc.UpdateProfile(context.Background(), user.ID, &UpdateProfileRequest{
		Email: "different@example.com",
	})
	if err == nil {
		t.Fatal("expected error when email check fails")
	}
	if !strings.Contains(err.Error(), "checking email") {
		t.Errorf("error = %q, want 'checking email'", err.Error())
	}
}

func TestUpdateProfileUpdateError(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	user := seedUser(repo, "update@example.com", "password123")

	repo.updateErr = fmt.Errorf("write failed")

	_, err := svc.UpdateProfile(context.Background(), user.ID, &UpdateProfileRequest{})
	if err == nil {
		t.Fatal("expected error when update fails")
	}
	if !strings.Contains(err.Error(), "updating user") {
		t.Errorf("error = %q, want 'updating user'", err.Error())
	}
}

// --- ChangePassword Tests ---

func TestChangePasswordUserNotFound(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())

	err := svc.ChangePassword(context.Background(), uuid.New(), &ChangePasswordRequest{
		CurrentPassword: "old",
		NewPassword:     "new",
	})
	if err == nil {
		t.Fatal("expected error for non-existent user")
	}
	if !strings.Contains(err.Error(), "user not found") {
		t.Errorf("error = %q, want 'user not found'", err.Error())
	}
}

func TestChangePasswordRepoError(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	repo.getByIDErr = fmt.Errorf("db failure")
	svc := newUserService(repo, newUserSvcMockTokenRepo())

	err := svc.ChangePassword(context.Background(), uuid.New(), &ChangePasswordRequest{
		CurrentPassword: "old",
		NewPassword:     "new",
	})
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
	if !strings.Contains(err.Error(), "getting user") {
		t.Errorf("error = %q, want 'getting user'", err.Error())
	}
}

func TestChangePasswordInvalidCurrent(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	user := seedUser(repo, "pw@example.com", "correctpassword")

	err := svc.ChangePassword(context.Background(), user.ID, &ChangePasswordRequest{
		CurrentPassword: "wrongpassword",
		NewPassword:     "newpassword123",
	})
	if err == nil {
		t.Fatal("expected error for invalid current password")
	}
	if !strings.Contains(err.Error(), "invalid current password") {
		t.Errorf("error = %q, want 'invalid current password'", err.Error())
	}
}

func TestChangePasswordEmptyPasswordUser(t *testing.T) {
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())
	// Users with an empty password field; changing password should skip
	// the current password check. This test verifies the code path up to the
	// transaction call. Because the Transactor requires a real DB, we expect
	// a nil-pointer panic. We recover from it to confirm we got past the
	// password check.
	user := seedUser(repo, "emptypass@example.com", "")

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic from nil Transactor (proves we passed the password check)")
			}
			// Recovered successfully — the code path reached WithTransaction.
		}()
		_ = svc.ChangePassword(context.Background(), user.ID, &ChangePasswordRequest{
			CurrentPassword: "",
			NewPassword:     "newpassword123",
		})
	}()
}

// --- DeleteAccount Tests ---

func TestDeleteAccountUserNotExistNoError(t *testing.T) {
	// DeleteAccount calls tx.WithTransaction directly (no user lookup first),
	// so even for non-existent users it would try the transaction. With nil tx
	// we expect a panic proving the code reached the transaction call.
	repo := newUserSvcMockUserRepo()
	svc := newUserService(repo, newUserSvcMockTokenRepo())

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic from nil Transactor")
			}
		}()
		_ = svc.DeleteAccount(context.Background(), uuid.New())
	}()
}
