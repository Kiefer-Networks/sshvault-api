package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

// --- Mock Repositories ---

type mockUserRepo struct {
	users      map[uuid.UUID]*model.User
	emailIndex map[string]*model.User
	createErr  error
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users:      make(map[uuid.UUID]*model.User),
		emailIndex: make(map[string]*model.User),
	}
}

func (m *mockUserRepo) Create(_ context.Context, user *model.User) error {
	if m.createErr != nil {
		return m.createErr
	}
	user.ID = uuid.New()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	m.emailIndex[user.Email] = user
	return nil
}

func (m *mockUserRepo) GetByID(_ context.Context, id uuid.UUID) (*model.User, error) {
	u := m.users[id]
	return u, nil
}

func (m *mockUserRepo) GetByEmail(_ context.Context, email string) (*model.User, error) {
	u := m.emailIndex[email]
	return u, nil
}

func (m *mockUserRepo) Update(_ context.Context, user *model.User) error {
	m.users[user.ID] = user
	m.emailIndex[user.Email] = user
	return nil
}

func (m *mockUserRepo) GetDeletedByEmail(_ context.Context, _ string) (*model.User, error) {
	return nil, nil
}

func (m *mockUserRepo) SoftDelete(_ context.Context, _ uuid.UUID) error { return nil }

func (m *mockUserRepo) PurgeDeleted(_ context.Context, _ time.Time) ([]uuid.UUID, error) {
	return nil, nil
}

func (m *mockUserRepo) HardDelete(_ context.Context, _ uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

type mockTokenRepo struct {
	tokens    map[uuid.UUID]*model.RefreshToken
	hashIndex map[string]*model.RefreshToken
}

func newMockTokenRepo() *mockTokenRepo {
	return &mockTokenRepo{
		tokens:    make(map[uuid.UUID]*model.RefreshToken),
		hashIndex: make(map[string]*model.RefreshToken),
	}
}

func (m *mockTokenRepo) Create(_ context.Context, token *model.RefreshToken) error {
	token.ID = uuid.New()
	token.CreatedAt = time.Now()
	m.tokens[token.ID] = token
	m.hashIndex[token.TokenHash] = token
	return nil
}

func (m *mockTokenRepo) GetByHash(_ context.Context, tokenHash string) (*model.RefreshToken, error) {
	return m.hashIndex[tokenHash], nil
}

func (m *mockTokenRepo) Revoke(_ context.Context, id uuid.UUID) error {
	if t, ok := m.tokens[id]; ok {
		t.Revoked = true
	}
	return nil
}

func (m *mockTokenRepo) RevokeAllForUser(_ context.Context, userID uuid.UUID) error {
	for _, t := range m.tokens {
		if t.UserID == userID {
			t.Revoked = true
		}
	}
	return nil
}

func (m *mockTokenRepo) ConsumeRefreshToken(_ context.Context, tokenHash string) (*model.RefreshToken, error) {
	t, ok := m.hashIndex[tokenHash]
	if !ok || t.Revoked || t.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}
	t.Revoked = true
	return t, nil
}

func (m *mockTokenRepo) DeleteExpired(_ context.Context) (int64, error) { return 0, nil }

type mockVerifyRepo struct {
	tokens map[uuid.UUID]*repository.VerificationToken
}

func newMockVerifyRepo() *mockVerifyRepo {
	return &mockVerifyRepo{
		tokens: make(map[uuid.UUID]*repository.VerificationToken),
	}
}

func (m *mockVerifyRepo) Create(_ context.Context, token *repository.VerificationToken) error {
	token.ID = uuid.New()
	token.CreatedAt = time.Now()
	m.tokens[token.ID] = token
	return nil
}

func (m *mockVerifyRepo) GetByHash(_ context.Context, tokenHash, kind string) (*repository.VerificationToken, error) {
	for _, t := range m.tokens {
		if t.TokenHash == tokenHash && t.Kind == kind && !t.Used {
			return t, nil
		}
	}
	return nil, nil
}

func (m *mockVerifyRepo) ConsumeVerificationToken(_ context.Context, tokenHash, kind string) (*repository.VerificationToken, error) {
	for _, t := range m.tokens {
		if t.TokenHash == tokenHash && t.Kind == kind && !t.Used && t.ExpiresAt.After(time.Now()) {
			t.Used = true
			return t, nil
		}
	}
	return nil, nil
}

func (m *mockVerifyRepo) MarkUsed(_ context.Context, id uuid.UUID) error {
	if t, ok := m.tokens[id]; ok {
		t.Used = true
	}
	return nil
}

func (m *mockVerifyRepo) DeleteExpired(_ context.Context) (int64, error) { return 0, nil }

func (m *mockVerifyRepo) RevokeAllForUser(_ context.Context, userID uuid.UUID, kind string) error {
	for _, t := range m.tokens {
		if t.UserID == userID && t.Kind == kind {
			t.Used = true
		}
	}
	return nil
}

type mockMailer struct {
	sentVerification int
	sentReset        int
}

func (m *mockMailer) SendVerificationEmail(_ context.Context, _, _ string) error {
	m.sentVerification++
	return nil
}

func (m *mockMailer) SendPasswordResetEmail(_ context.Context, _, _ string) error {
	m.sentReset++
	return nil
}

// --- Helper ---

func newTestJWT(t *testing.T) *auth.JWTManager {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	return auth.NewJWTManager(priv, 15*time.Minute, 7*24*time.Hour)
}

func newTestAuthService(t *testing.T) (*AuthService, *mockUserRepo, *mockTokenRepo, *mockVerifyRepo, *mockMailer) {
	t.Helper()
	userRepo := newMockUserRepo()
	tokenRepo := newMockTokenRepo()
	verifyRepo := newMockVerifyRepo()
	mailer := &mockMailer{}
	jwt := newTestJWT(t)

	svc := NewAuthService(userRepo, tokenRepo, verifyRepo, testTransactionRunner{}, jwt, mailer, nil)
	return svc, userRepo, tokenRepo, verifyRepo, mailer
}

// --- Register Tests ---

func TestRegisterSuccess(t *testing.T) {
	svc, users, tokens, _, mailer := newTestAuthService(t)
	res, err := svc.Register(context.Background(), &RegisterRequest{Email: "  TEST@EXAMPLE.COM  ", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status == "" || users.emailIndex["test@example.com"] == nil || len(tokens.tokens) != 0 || mailer.sentVerification != 1 {
		t.Fatal("registration must normalize email, send verification and issue no sessions")
	}
}
func TestRegisterDuplicateEmail(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)
	a, err := svc.Register(context.Background(), &RegisterRequest{Email: "test@example.com", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.Register(context.Background(), &RegisterRequest{Email: "test@example.com", Password: "password123"})
	if err != nil || *a != *b {
		t.Fatal("registration must be indistinguishable")
	}
}
func TestRegisterInvalidEmail(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)
	if _, err := svc.Register(context.Background(), &RegisterRequest{Email: "invalid", Password: "password123"}); err == nil {
		t.Fatal("invalid email accepted")
	}
}

func registerVerified(t *testing.T, svc *AuthService, ctx context.Context, req *RegisterRequest) (*AuthResponse, error) {
	t.Helper()
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	user := &model.User{Email: NormalizeEmail(req.Email), Password: hash, Verified: true}
	if err = svc.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	return svc.Login(ctx, &LoginRequest{Email: req.Email, Password: req.Password})
}

// --- Login Tests ---

func TestLoginSuccess(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	_, err := registerVerified(t, svc, ctx, &RegisterRequest{
		Email:    "login@example.com",
		Password: "mypassword123",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	resp, err := svc.Login(ctx, &LoginRequest{
		Email:    "login@example.com",
		Password: "mypassword123",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected access token")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	_, err := registerVerified(t, svc, ctx, &RegisterRequest{
		Email:    "wrong@example.com",
		Password: "correctpassword",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, err = svc.Login(ctx, &LoginRequest{
		Email:    "wrong@example.com",
		Password: "wrongpassword",
	})
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("error = %q, want 'invalid credentials'", err.Error())
	}
}

func TestLoginNonExistentUser(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)

	_, err := svc.Login(context.Background(), &LoginRequest{
		Email:    "nonexistent@example.com",
		Password: "anypassword",
	})
	if err == nil {
		t.Fatal("expected error for non-existent user")
	}
	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("error = %q, want 'invalid credentials'", err.Error())
	}
}

// --- Refresh Tests ---

func TestRefreshSuccess(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	regResp, err := registerVerified(t, svc, ctx, &RegisterRequest{
		Email:    "refresh@example.com",
		Password: "mypassword123",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	refreshResp, err := svc.Refresh(ctx, &RefreshRequest{
		RefreshToken: regResp.RefreshToken,
	})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshResp.AccessToken == "" {
		t.Error("expected new access token")
	}
	if refreshResp.RefreshToken == regResp.RefreshToken {
		t.Error("refresh token should be rotated")
	}
}

func TestRefreshRevokedToken(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	regResp, err := registerVerified(t, svc, ctx, &RegisterRequest{
		Email:    "revoke@example.com",
		Password: "mypassword123",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Use the refresh token once (revokes it)
	_, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: regResp.RefreshToken})
	if err != nil {
		t.Fatalf("first Refresh: %v", err)
	}

	// Try to use the same token again — should fail
	_, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: regResp.RefreshToken})
	if err == nil {
		t.Fatal("expected error for revoked refresh token")
	}
}

func TestRefreshInvalidToken(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)

	_, err := svc.Refresh(context.Background(), &RefreshRequest{
		RefreshToken: "totally-invalid-token",
	})
	if err == nil {
		t.Fatal("expected error for invalid refresh token")
	}
}

// --- Logout Tests ---

func TestLogoutSuccess(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	regResp, err := registerVerified(t, svc, ctx, &RegisterRequest{
		Email:    "logout@example.com",
		Password: "mypassword123",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := svc.Logout(ctx, regResp.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	// Refresh should now fail
	_, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: regResp.RefreshToken})
	if err == nil {
		t.Fatal("expected error after logout")
	}
}

func TestLogoutNonExistentToken(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)
	// Should not error — graceful no-op
	if err := svc.Logout(context.Background(), "nonexistent-token"); err != nil {
		t.Fatalf("Logout with nonexistent token: %v", err)
	}
}

// --- VerifyEmail Tests ---

func TestVerifyEmailSuccess(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService(t)
	mail := &lifecycleMailbox{}
	svc.mailer = mail
	ctx := context.Background()
	if _, err := svc.Register(ctx, &RegisterRequest{Email: "verify@example.com", Password: "password123"}); err != nil {
		t.Fatal(err)
	}
	user := users.emailIndex["verify@example.com"]
	if user.Verified {
		t.Fatal("new account already verified")
	}
	if err := svc.VerifyEmail(ctx, mail.verification, "password123"); err != nil {
		t.Fatal(err)
	}
	if !user.Verified {
		t.Fatal("verification did not authorize account")
	}
}

func TestVerifyEmailInvalidToken(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)

	err := svc.VerifyEmail(context.Background(), "invalid-token", "password123")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

// --- ForgotPassword Tests ---

func TestForgotPasswordExistingUser(t *testing.T) {
	svc, _, _, _, mailer := newTestAuthService(t)
	ctx := context.Background()

	_, err := registerVerified(t, svc, ctx, &RegisterRequest{
		Email:    "forgot@example.com",
		Password: "mypassword123",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	mailer.sentReset = 0
	if err := svc.ForgotPassword(ctx, "forgot@example.com"); err != nil {
		t.Fatalf("ForgotPassword: %v", err)
	}
	if mailer.sentReset != 1 {
		t.Errorf("reset emails = %d, want 1", mailer.sentReset)
	}
}

func TestForgotPasswordNonExistentUser(t *testing.T) {
	svc, _, _, _, mailer := newTestAuthService(t)

	// Should not reveal user existence
	if err := svc.ForgotPassword(context.Background(), "nobody@example.com"); err != nil {
		t.Fatalf("ForgotPassword: %v", err)
	}
	if mailer.sentReset != 0 {
		t.Errorf("reset emails = %d, want 0", mailer.sentReset)
	}
}

// --- LogoutAll Tests ---

func TestLogoutAllRevokesAllTokens(t *testing.T) {
	svc, _, tokenRepo, _, _ := newTestAuthService(t)
	ctx := context.Background()

	regResp, err := registerVerified(t, svc, ctx, &RegisterRequest{
		Email:    "logoutall@example.com",
		Password: "mypassword123",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Login a second time to create another token
	_, err = svc.Login(ctx, &LoginRequest{
		Email:    "logoutall@example.com",
		Password: "mypassword123",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := svc.LogoutAll(ctx, regResp.User.ID); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}

	// All tokens should be revoked
	for _, tok := range tokenRepo.tokens {
		if tok.UserID == regResp.User.ID && !tok.Revoked {
			t.Error("expected all tokens to be revoked")
		}
	}
}

func (m *mockUserRepo) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*model.User, error) {
	return m.GetByID(ctx, id)
}
func (m *mockUserRepo) UpdateEmail(ctx context.Context, id uuid.UUID, email string) error {
	u, err := m.GetByID(ctx, id)
	if err != nil {
		return err
	}
	u.Email = email
	u.Verified = false
	return m.Update(ctx, u)
}
func (m *mockUserRepo) UpdateAvatar(ctx context.Context, id uuid.UUID, avatar string) error {
	u, err := m.GetByID(ctx, id)
	if err != nil {
		return err
	}
	u.Avatar = avatar
	return m.Update(ctx, u)
}
func (m *mockUserRepo) MarkVerified(ctx context.Context, id uuid.UUID, email string) error {
	u, err := m.GetByID(ctx, id)
	if err != nil {
		return err
	}
	u.Verified = true
	return m.Update(ctx, u)
}
func (m *mockUserRepo) UpdatePassword(ctx context.Context, id uuid.UUID, expected, password string) error {
	u, err := m.GetByID(ctx, id)
	if err != nil {
		return err
	}
	u.Password = password
	u.SessionVersion++
	return m.Update(ctx, u)
}
func (m *mockUserRepo) RevokeSessions(ctx context.Context, id uuid.UUID) error {
	u, err := m.GetByID(ctx, id)
	if err != nil {
		return err
	}
	u.SessionVersion++
	return m.Update(ctx, u)
}

type testTransactionRunner struct{}

func (testTransactionRunner) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (m *mockUserRepo) SetPendingEmail(ctx context.Context, id uuid.UUID, email string) error {
	u, err := m.GetByID(ctx, id)
	if err != nil {
		return err
	}
	u.PendingEmail = email
	return nil
}
func (m *mockUserRepo) ConfirmPendingEmail(ctx context.Context, id uuid.UUID, email string) error {
	u, err := m.GetByID(ctx, id)
	if err != nil {
		return err
	}
	u.Email = email
	u.PendingEmail = ""
	u.Verified = true
	u.SessionVersion++
	return nil
}

func (m *mockMailer) SendEmailChangeEmail(context.Context, string, string) error { return nil }

func (m *mockUserRepo) ActivateRegistration(ctx context.Context, id uuid.UUID, email, passwordHash string) error {
	u, err := m.GetByID(ctx, id)
	if err != nil {
		return err
	}
	u.Password = passwordHash
	u.Verified = true
	u.SessionVersion++
	return nil
}

func (m *mockVerifyRepo) ReserveMailSend(context.Context, string, string) (bool, error) {
	return true, nil
}
