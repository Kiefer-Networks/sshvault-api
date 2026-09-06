package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

type admissionUsers struct {
	repository.UserRepository
	entered  atomic.Int32
	admitted chan struct{}
	release  <-chan struct{}
}

func (r *admissionUsers) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	r.entered.Add(1)
	r.admitted <- struct{}{}
	<-r.release
	return r.UserRepository.GetByEmail(ctx, email)
}

func TestLoginReservesBeforePasswordWork(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	release := make(chan struct{})
	password, err := auth.HashPassword("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	realUsers := repository.NewUserRepository(p)
	if err = realUsers.Create(ctx, &model.User{Email: "test@example.com", Password: password, Verified: true}); err != nil {
		t.Fatal(err)
	}
	users := &admissionUsers{UserRepository: realUsers, release: release, admitted: make(chan struct{}, 12)}
	svc := NewAuthService(users, repository.NewTokenRepository(p), repository.NewVerificationRepository(p), repository.NewTransactor(p), newTestJWT(t), nil, middleware.NewBruteForceGuard(p))
	// A repository boundary holds admitted requests before expensive verification.
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if result, err := svc.Login(ctx, &LoginRequest{Email: " TEST@example.com ", Password: "incorrect-password", IP: "192.0.2.1"}); err == nil || result != nil {
				t.Error("wrong password authorized")
			}
		}()
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for i := 0; i < middleware.MaxFailedAttempts; i++ {
		select {
		case <-users.admitted:
		case <-deadline.C:
			close(release)
			wg.Wait()
			t.Fatal("admission did not reach expected boundary")
		}
	}
	close(release)
	wg.Wait()
	if n := users.entered.Load(); n != middleware.MaxFailedAttempts {
		t.Fatalf("password-stage admissions=%d, want %d", n, middleware.MaxFailedAttempts)
	}
}

func TestRefreshReplayRevokesCredentialsAfterCleanup(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	tokens := repository.NewTokenRepository(p)
	manager := newTestJWT(t)
	svc := NewAuthService(users, tokens, repository.NewVerificationRepository(p), repository.NewTransactor(p), manager, nil, nil)
	initial, err := registerVerified(t, svc, ctx, &RegisterRequest{Email: "refresh@example.com", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := svc.Refresh(ctx, &RefreshRequest{RefreshToken: initial.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tokens.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: initial.RefreshToken}); err == nil {
		t.Fatal("consumed token accepted")
	}
	current, err := users.GetByID(ctx, initial.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.SessionVersion != initial.User.SessionVersion+1 {
		t.Errorf("replay did not increment session version: %d", current.SessionVersion)
	}
	if _, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: rotated.RefreshToken}); err == nil {
		t.Error("successor remained usable after replay")
	}
	handler := middleware.NewAuthMiddleware(manager, users).Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+rotated.AccessToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("access token remained usable: %d", w.Code)
	}
	stored, err := tokens.GetByHash(ctx, auth.HashToken(initial.RefreshToken))
	if err != nil || stored == nil {
		t.Errorf("cleanup removed replay evidence: %v", err)
	}
}

func TestConcurrentRefreshHasOneSuccessAndRevokesFamily(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	tokens := repository.NewTokenRepository(p)
	svc := NewAuthService(users, tokens, repository.NewVerificationRepository(p), repository.NewTransactor(p), newTestJWT(t), nil, nil)
	initial, err := registerVerified(t, svc, ctx, &RegisterRequest{Email: "concurrent@example.com", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan *AuthResponse, 4)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, _ := svc.Refresh(ctx, &RefreshRequest{RefreshToken: initial.RefreshToken})
			results <- result
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result != nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful rotations=%d, want 1", successes)
	}
	var count, live, families, parents int
	if err = p.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE NOT revoked),count(DISTINCT family_id),count(parent_id) FROM refresh_tokens`).Scan(&count, &live, &families, &parents); err != nil {
		t.Fatal(err)
	}
	if count != 2 || live != 0 || families != 1 || parents != 1 {
		t.Fatalf("rotation state: rows=%d live=%d families=%d parents=%d", count, live, families, parents)
	}
	current, err := users.GetByID(ctx, initial.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.SessionVersion != initial.User.SessionVersion+3 {
		t.Fatalf("replays not committed: version=%d", current.SessionVersion)
	}
}

type failReplayRevocation struct{ repository.TokenRepository }

func (r failReplayRevocation) RevokeAllForUser(context.Context, uuid.UUID) error {
	return errors.New("injected revocation failure")
}

func TestReplayRevocationRollsBackAsOneTransaction(t *testing.T) {
	p := authDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	tokens := repository.NewTokenRepository(p)
	svc := NewAuthService(users, tokens, repository.NewVerificationRepository(p), repository.NewTransactor(p), newTestJWT(t), nil, nil)
	initial, err := registerVerified(t, svc, ctx, &RegisterRequest{Email: "rollback@example.com", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := svc.Refresh(ctx, &RefreshRequest{RefreshToken: initial.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	svc.tokenRepo = failReplayRevocation{tokens}
	if _, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: initial.RefreshToken}); err == nil {
		t.Fatal("injected failure ignored")
	}
	current, err := users.GetByID(ctx, initial.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.SessionVersion != initial.User.SessionVersion {
		t.Fatal("session version committed without revocation")
	}
	svc.tokenRepo = tokens
	if _, err = svc.Refresh(ctx, &RefreshRequest{RefreshToken: rotated.RefreshToken}); err != nil {
		t.Fatalf("rollback damaged successor: %v", err)
	}
}
