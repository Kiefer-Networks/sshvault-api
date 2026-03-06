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

func (m *mockUserRepo) PurgeDeleted(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

func (m *mockUserRepo) GetPurgableUserIDs(_ context.Context, _ time.Time) ([]uuid.UUID, error) {
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

	svc := NewAuthService(userRepo, tokenRepo, verifyRepo, nil, jwt, mailer, nil)
	return svc, userRepo, tokenRepo, verifyRepo, mailer
}

// --- Register Tests ---

func TestRegisterSuccess(t *testing.T) {
	svc, userRepo, _, _, mailer := newTestAuthService(t)

	resp, err := svc.Register(context.Background(), &RegisterRequest{
		Email:    "test@example.com",
		Password: "strongpassword123",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.User == nil {
		t.Fatal("expected user in response")
	}
	if resp.User.Email != "test@example.com" {
		t.Errorf("email = %q, want %q", resp.User.Email, "test@example.com")
	}
	if resp.AccessToken == "" {
		t.Error("expected access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh token")
	}
	if len(userRepo.users) != 1 {
		t.Errorf("users count = %d, want 1", len(userRepo.users))
	}
	if mailer.sentVerification != 1 {
		t.Errorf("verification emails = %d, want 1", mailer.sentVerification)
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	_, err := svc.Register(ctx, &RegisterRequest{
		Email:    "dup@example.com",
		Password: "strongpassword123",
	})
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}

	_, err = svc.Register(ctx, &RegisterRequest{
		Email:    "dup@example.com",
		Password: "anotherpassword123",
	})
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("error = %q, want 'already registered'", err.Error())
	}
}

func TestRegisterInvalidEmail(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)

	_, err := svc.Register(context.Background(), &RegisterRequest{
		Email:    "not-an-email",
		Password: "strongpassword123",
	})
	if err == nil {
		t.Fatal("expected error for invalid email")
	}
	if !strings.Contains(err.Error(), "invalid email") {
		t.Errorf("error = %q, want 'invalid email'", err.Error())
	}
}

func TestRegisterNormalizesEmail(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)

	resp, err := svc.Register(context.Background(), &RegisterRequest{
		Email:    "  TEST@EXAMPLE.COM  ",
		Password: "strongpassword123",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.User.Email != "test@example.com" {
		t.Errorf("email = %q, want %q", resp.User.Email, "test@example.com")
	}
}

// --- Login Tests ---

func TestLoginSuccess(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)
	ctx := context.Background()

	_, err := svc.Register(ctx, &RegisterRequest{
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

	_, err := svc.Register(ctx, &RegisterRequest{
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

	regResp, err := svc.Register(ctx, &RegisterRequest{
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

	regResp, err := svc.Register(ctx, &RegisterRequest{
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

	regResp, err := svc.Register(ctx, &RegisterRequest{
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
	svc, userRepo, _, verifyRepo, _ := newTestAuthService(t)
	ctx := context.Background()

	// Register creates a verification token
	regResp, err := svc.Register(ctx, &RegisterRequest{
		Email:    "verify@example.com",
		Password: "mypassword123",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if regResp.User.Verified {
		t.Fatal("user should not be verified initially")
	}

	// Find the token that was created
	var rawToken string
	for _, vt := range verifyRepo.tokens {
		if vt.UserID == regResp.User.ID && vt.Kind == repository.TokenKindEmailVerify {
			// We can't recover the raw token from the hash, so we test the flow differently:
			// Store a known token and verify it
			rawToken = uuid.New().String()
			vt.TokenHash = auth.HashToken(rawToken)
			break
		}
	}

	if rawToken == "" {
		t.Fatal("no verification token found")
	}

	if err := svc.VerifyEmail(ctx, rawToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	user := userRepo.users[regResp.User.ID]
	if !user.Verified {
		t.Error("user should be verified after VerifyEmail")
	}
}

func TestVerifyEmailInvalidToken(t *testing.T) {
	svc, _, _, _, _ := newTestAuthService(t)

	err := svc.VerifyEmail(context.Background(), "invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

// --- ForgotPassword Tests ---

func TestForgotPasswordExistingUser(t *testing.T) {
	svc, _, _, _, mailer := newTestAuthService(t)
	ctx := context.Background()

	_, err := svc.Register(ctx, &RegisterRequest{
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

	regResp, err := svc.Register(ctx, &RegisterRequest{
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
