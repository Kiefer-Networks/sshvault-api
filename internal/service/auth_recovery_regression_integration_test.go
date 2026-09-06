package service

import (
	"context"
	"testing"
	"time"

	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

func TestPasswordChangeInvalidatesOutstandingReset(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	tokens := repository.NewTokenRepository(p)
	verify := repository.NewVerificationRepository(p)
	tx := repository.NewTransactor(p)
	authService := NewAuthService(users, tokens, verify, tx, newTestJWT(t), nil, nil)
	userService := NewUserService(users, tokens, tx, verify, nil)

	initial, err := registerVerified(t, authService, ctx, &RegisterRequest{Email: "recovery@example.com", Password: "old-password"})
	if err != nil {
		t.Fatal(err)
	}
	if err = verify.Create(ctx, &repository.VerificationToken{
		UserID: initial.User.ID, TokenHash: auth.HashToken("stolen-reset"),
		Kind: repository.TokenKindPasswordReset, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err = userService.ChangePassword(ctx, initial.User.ID, &ChangePasswordRequest{CurrentPassword: "old-password", NewPassword: "owner-new-password"}); err != nil {
		t.Fatal(err)
	}
	if err = authService.ResetPassword(ctx, "stolen-reset", "attacker-password"); err == nil {
		t.Fatal("reset issued before password change remained valid")
	}
}

func TestPriorSessionReplayDoesNotRevokeRecoveredSession(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	tokens := repository.NewTokenRepository(p)
	verify := repository.NewVerificationRepository(p)
	tx := repository.NewTransactor(p)
	authService := NewAuthService(users, tokens, verify, tx, newTestJWT(t), nil, nil)

	initial, err := registerVerified(t, authService, ctx, &RegisterRequest{Email: "replay@example.com", Password: "old-password"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authService.Refresh(ctx, &RefreshRequest{RefreshToken: initial.RefreshToken}); err != nil {
		t.Fatal(err)
	}
	if err = authService.LogoutAll(ctx, initial.User.ID); err != nil {
		t.Fatal(err)
	}
	recovered, err := authService.Login(ctx, &LoginRequest{Email: "replay@example.com", Password: "old-password"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authService.Refresh(ctx, &RefreshRequest{RefreshToken: initial.RefreshToken}); err == nil {
		t.Fatal("replayed token accepted")
	}
	current, err := users.GetByID(ctx, initial.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.SessionVersion != recovered.User.SessionVersion {
		t.Fatalf("prior-session replay revoked recovered session: %d -> %d", recovered.User.SessionVersion, current.SessionVersion)
	}
}
