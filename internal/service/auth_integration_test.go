package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

func authDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is required for PostgreSQL integration tests")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	schema := "auth_" + uuid.New().String()
	schema = "\"" + schema + "\""
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); admin.Close() })
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	paths, err := filepath.Glob("../../migrations/*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	for _, p := range paths {
		sql, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	return pool
}

func TestIntegrationAccessRevocation(t *testing.T) {
	for _, action := range []string{"delete", "logout_all", "reset", "change_password"} {
		t.Run(action, func(t *testing.T) {
			pool := authDatabase(t)
			ctx := context.Background()
			users := repository.NewUserRepository(pool)
			tokens := repository.NewTokenRepository(pool)
			verify := repository.NewVerificationRepository(pool)
			tx := repository.NewTransactor(pool)
			jwt := newTestJWT(t)
			svc := NewAuthService(users, tokens, verify, tx, jwt, nil, nil)
			us := NewUserService(users, tokens, tx)
			response, err := svc.Register(ctx, &RegisterRequest{Email: "user@example.com", Password: "old-password"})
			if err != nil {
				t.Fatal(err)
			}
			handler := middleware.NewAuthMiddleware(jwt, users).Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			status := func() int {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Set("Authorization", "Bearer "+response.AccessToken)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w.Code
			}
			if got := status(); got != 204 {
				t.Fatalf("active token status %d", got)
			}
			switch action {
			case "delete":
				err = us.DeleteAccount(ctx, response.User.ID)
			case "logout_all":
				err = svc.LogoutAll(ctx, response.User.ID)
			case "change_password":
				err = us.ChangePassword(ctx, response.User.ID, &ChangePasswordRequest{CurrentPassword: "old-password", NewPassword: "new-password"})
			case "reset":
				err = verify.Create(ctx, &repository.VerificationToken{UserID: response.User.ID, TokenHash: auth.HashToken("reset"), Kind: repository.TokenKindPasswordReset, ExpiresAt: time.Now().Add(time.Hour)})
				if err == nil {
					err = svc.ResetPassword(ctx, "reset", "new-password")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := status(); got != 401 {
				t.Errorf("revoked access token accepted: status %d", got)
			}
			if _, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: response.RefreshToken}); err == nil {
				t.Error("revoked refresh token accepted")
			}
		})
	}
}

type failCreateTokens struct{ repository.TokenRepository }

func (r failCreateTokens) Create(context.Context, *model.RefreshToken) error {
	return errors.New("injected insert failure")
}
func TestIntegrationRefreshRollback(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	tokens := repository.NewTokenRepository(pool)
	verify := repository.NewVerificationRepository(pool)
	tx := repository.NewTransactor(pool)
	jwt := newTestJWT(t)
	svc := NewAuthService(users, tokens, verify, tx, jwt, nil, nil)
	response, err := svc.Register(ctx, &RegisterRequest{Email: "refresh@example.com", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	svc.tokenRepo = failCreateTokens{tokens}
	if _, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: response.RefreshToken}); err == nil {
		t.Fatal("expected insertion failure")
	}
	svc.tokenRepo = tokens
	if _, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: response.RefreshToken}); err != nil {
		t.Fatalf("failed rotation consumed token: %v", err)
	}
}

type staleReadUsers struct {
	repository.UserRepository
	afterRead func()
}

func (r staleReadUsers) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	u, err := r.UserRepository.GetByID(ctx, id)
	if err == nil {
		r.afterRead()
	}
	return u, err
}
func TestIntegrationProfilePreservesConcurrentPassword(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	u := &model.User{Email: "profile@example.com", Password: "old-hash"}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	wrapped := staleReadUsers{users, func() {
		if _, err := pool.Exec(ctx, "UPDATE users SET password='new-hash' WHERE id=$1", u.ID); err != nil {
			t.Fatal(err)
		}
	}}
	svc := NewUserService(wrapped, repository.NewTokenRepository(pool), repository.NewTransactor(pool))
	if _, err := svc.UpdateProfile(ctx, u.ID, &UpdateProfileRequest{Email: "new@example.com"}); err != nil {
		t.Fatal(err)
	}
	got, err := users.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "new-hash" {
		t.Fatalf("profile restored stale password: %q", got.Password)
	}
}

func TestIntegrationResetTokenSingleUse(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	tokens := repository.NewTokenRepository(pool)
	verify := repository.NewVerificationRepository(pool)
	tx := repository.NewTransactor(pool)
	u := &model.User{Email: "reset@example.com", Password: "old-hash"}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := verify.Create(ctx, &repository.VerificationToken{UserID: u.ID, TokenHash: auth.HashToken("reset"), Kind: repository.TokenKindPasswordReset, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	svc := NewAuthService(users, tokens, verify, tx, newTestJWT(t), nil, nil)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; results <- svc.ResetPassword(ctx, "reset", "new-password") }()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("reset succeeded %d times; want exactly once", successes)
	}
}

type failRevokeTokens struct{ repository.TokenRepository }

func (r failRevokeTokens) RevokeAllForUser(context.Context, uuid.UUID) error {
	return errors.New("injected revoke failure")
}
func TestIntegrationResetRollback(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	tokens := repository.NewTokenRepository(pool)
	verify := repository.NewVerificationRepository(pool)
	tx := repository.NewTransactor(pool)
	u := &model.User{Email: "rollback@example.com", Password: "old-hash"}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := verify.Create(ctx, &repository.VerificationToken{UserID: u.ID, TokenHash: auth.HashToken("reset"), Kind: repository.TokenKindPasswordReset, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	svc := NewAuthService(users, failRevokeTokens{tokens}, verify, tx, newTestJWT(t), nil, nil)
	if err := svc.ResetPassword(ctx, "reset", "new-password"); err == nil {
		t.Fatal("expected revocation failure")
	}
	got, err := users.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "old-hash" || got.SessionVersion != 0 {
		t.Fatal("failed reset changed credentials")
	}
	svc.tokenRepo = tokens
	if err := svc.ResetPassword(ctx, "reset", "new-password"); err != nil {
		t.Fatalf("failed reset consumed token: %v", err)
	}
}

func TestIntegrationPasswordlessAccountAndMissingDeletion(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	tokens := repository.NewTokenRepository(pool)
	tx := repository.NewTransactor(pool)
	u := &model.User{Email: "empty@example.com"}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	svc := NewUserService(users, tokens, tx)
	if err := svc.ChangePassword(ctx, u.ID, &ChangePasswordRequest{NewPassword: "new-password"}); err != nil {
		t.Fatal(err)
	}
	got, err := users.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := auth.VerifyPassword("new-password", got.Password); err != nil || !valid {
		t.Fatal("new password was not stored")
	}
	if got.SessionVersion != 1 {
		t.Fatal("password change did not revoke sessions")
	}
	if err := svc.DeleteAccount(ctx, uuid.New()); err != nil {
		t.Fatalf("missing deletion must be idempotent: %v", err)
	}
}

type afterEmailReadUsers struct {
	repository.UserRepository
	afterRead func()
}

func (r afterEmailReadUsers) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	u, err := r.UserRepository.GetByEmail(ctx, email)
	if err == nil {
		r.afterRead()
	}
	return u, err
}
func TestIntegrationLoginCannotIssueFromRevokedSnapshot(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	tokens := repository.NewTokenRepository(pool)
	tx := repository.NewTransactor(pool)
	jwt := newTestJWT(t)
	svc := NewAuthService(users, tokens, repository.NewVerificationRepository(pool), tx, jwt, nil, nil)
	response, err := svc.Register(ctx, &RegisterRequest{Email: "race@example.com", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	svc.userRepo = afterEmailReadUsers{users, func() {
		if err := svc.LogoutAll(ctx, response.User.ID); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := svc.Login(ctx, &LoginRequest{Email: "race@example.com", Password: "password"}); err == nil {
		t.Fatal("login issued a session from credentials read before logout-all")
	}
	var active int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM refresh_tokens WHERE user_id=$1 AND NOT revoked", response.User.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("%d sessions escaped revocation", active)
	}
}

func TestIntegrationRefreshWaitsForRevocation(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	tokens := repository.NewTokenRepository(pool)
	tx := repository.NewTransactor(pool)
	jwt := newTestJWT(t)
	svc := NewAuthService(users, tokens, repository.NewVerificationRepository(pool), tx, jwt, nil, nil)
	response, err := svc.Register(ctx, &RegisterRequest{Email: "refresh-race@example.com", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- tx.WithTransaction(ctx, func(txCtx context.Context) error {
			if err := users.RevokeSessions(txCtx, response.User.ID); err != nil {
				return err
			}
			close(locked)
			<-release
			return tokens.RevokeAllForUser(txCtx, response.User.ID)
		})
	}()
	<-locked
	read := make(chan struct{})
	svc.tokenRepo = notifyTokenRead{tokens, read}
	refreshed := make(chan error, 1)
	go func() {
		_, err := svc.Refresh(ctx, &RefreshRequest{RefreshToken: response.RefreshToken})
		refreshed <- err
	}()
	<-read
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-refreshed; err == nil {
		t.Fatal("refresh bypassed revocation transaction")
	}
}

func TestIntegrationFieldUpdatesPreserveCredentials(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	u := &model.User{Email: "fields@example.com", Password: "new-hash"}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := users.UpdateAvatar(ctx, u.ID, "avatar"); err != nil {
		t.Fatal(err)
	}
	if err := users.MarkVerified(ctx, u.ID, u.Email); err != nil {
		t.Fatal(err)
	}
	got, err := users.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "new-hash" || got.Avatar != "avatar" || !got.Verified {
		t.Fatalf("unrelated fields changed: %+v", got)
	}
	if err := users.UpdateEmail(ctx, u.ID, "changed@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := users.MarkVerified(ctx, u.ID, u.Email); err == nil {
		t.Fatal("stale verification verified a changed email")
	}
	if err := users.UpdatePassword(ctx, u.ID, "stale-hash", "overwrite"); err == nil {
		t.Fatal("stale password change succeeded")
	}
}

type notifyTokenRead struct {
	repository.TokenRepository
	read chan struct{}
}

func (r notifyTokenRead) GetByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	token, err := r.TokenRepository.GetByHash(ctx, hash)
	close(r.read)
	return token, err
}

type failVerifyUsers struct{ repository.UserRepository }

func (r failVerifyUsers) MarkVerified(context.Context, uuid.UUID, string) error {
	return errors.New("injected verification failure")
}
func TestIntegrationVerificationRollback(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	tokens := repository.NewTokenRepository(pool)
	verify := repository.NewVerificationRepository(pool)
	tx := repository.NewTransactor(pool)
	u := &model.User{Email: "verify-rollback@example.com", Password: "hash"}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := verify.Create(ctx, &repository.VerificationToken{UserID: u.ID, TokenHash: auth.HashToken("verify"), Kind: repository.TokenKindEmailVerify, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	svc := NewAuthService(failVerifyUsers{users}, tokens, verify, tx, newTestJWT(t), nil, nil)
	if err := svc.VerifyEmail(ctx, "verify"); err == nil {
		t.Fatal("expected verification failure")
	}
	svc.userRepo = users
	if err := svc.VerifyEmail(ctx, "verify"); err != nil {
		t.Fatalf("failed verification consumed token: %v", err)
	}
}
func TestIntegrationEmailChangeRevokesMailboxTokens(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	verify := repository.NewVerificationRepository(pool)
	u := &model.User{Email: "old-mailbox@example.com", Password: "hash"}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{repository.TokenKindEmailVerify, repository.TokenKindPasswordReset} {
		if err := verify.Create(ctx, &repository.VerificationToken{UserID: u.ID, TokenHash: auth.HashToken(kind), Kind: kind, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := users.UpdateEmail(ctx, u.ID, "new-mailbox@example.com"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{repository.TokenKindEmailVerify, repository.TokenKindPasswordReset} {
		token, err := verify.GetByHash(ctx, auth.HashToken(kind), kind)
		if err != nil {
			t.Fatal(err)
		}
		if token != nil {
			t.Errorf("old mailbox %s token remains usable", kind)
		}
	}
}

func TestIntegrationForgotPasswordCannotIssueForChangedEmail(t *testing.T) {
	pool := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(pool)
	verify := repository.NewVerificationRepository(pool)
	u := &model.User{Email: "old-reset@example.com", Password: "hash"}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	wrapped := afterEmailReadUsers{users, func() {
		if err := users.UpdateEmail(ctx, u.ID, "new-reset@example.com"); err != nil {
			t.Fatal(err)
		}
	}}
	svc := NewAuthService(wrapped, repository.NewTokenRepository(pool), verify, repository.NewTransactor(pool), newTestJWT(t), nil, nil)
	if err := svc.ForgotPassword(ctx, u.Email); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM verification_tokens WHERE user_id=$1 AND NOT used", u.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("%d reset links issued for old mailbox after email change", active)
	}
}

func TestIntegrationEmailChangeRevokesTokenCommittedWhileWaiting(t *testing.T) {
	pool := authDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	users := repository.NewUserRepository(pool)
	u := &model.User{Email: "waiting@example.com", Password: "hash"}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var blocker int
	if err = tx.QueryRow(ctx, "SELECT pg_backend_pid() FROM users WHERE id=$1 FOR UPDATE", u.ID).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO verification_tokens(user_id,token_hash,kind,expires_at) VALUES($1,'pending-token','password_reset',NOW()+interval '1 hour')", u.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- users.UpdateEmail(ctx, u.ID, "changed-waiting@example.com") }()
	for {
		var waiting bool
		if err = pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("email update did not wait for issuance")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	var used bool
	if err = pool.QueryRow(ctx, "SELECT used FROM verification_tokens WHERE token_hash='pending-token'").Scan(&used); err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Fatal("email change missed token committed while waiting for user lock")
	}
}
