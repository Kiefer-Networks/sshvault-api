package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/config"
	"github.com/kiefernetworks/shellvault-server/internal/handler"
	mw "github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/service"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

type slowRegistrationMail struct{}

func (slowRegistrationMail) SendVerificationEmail(ctx context.Context, _, _ string) error {
	select {
	case <-time.After(4 * time.Second):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (slowRegistrationMail) SendPasswordResetEmail(context.Context, string, string) error { return nil }
func (slowRegistrationMail) SendEmailChangeEmail(context.Context, string, string) error   { return nil }

func registrationNonce(ch mw.PowChallenge) string {
	for i := 0; ; i++ {
		nonce := fmt.Sprint(i)
		sum := sha256.Sum256([]byte(ch.Challenge + nonce))
		zeros := 0
		for _, b := range sum {
			if b == 0 {
				zeros += 8
				continue
			}
			zeros += bits.LeadingZeros8(b)
			break
		}
		if zeros >= ch.Difficulty {
			return nonce
		}
	}
}
func TestRegistrationProductionMiddlewareTimingWithSlowSMTP(t *testing.T) {
	p := testutil.Database(t, 0)
	users := repository.NewUserRepository(p)
	testutil.Exec(t, p, "INSERT INTO users(email,password,verified,deleted_at) VALUES('existing@example.com','hash',TRUE,NULL),('deleted@example.com','hash',FALSE,NOW())")
	dispatcher := service.NewMailDispatcher(slowRegistrationMail{}, 128, 2)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dispatcher.Stop(ctx)
	}()
	svc := service.NewAuthService(users, repository.NewTokenRepository(p), repository.NewVerificationRepository(p), repository.NewTransactor(p), nil, dispatcher, nil)
	authHandler := handler.NewAuthHandler(svc, audit.NewNopLogger())
	limiter := mw.NewRateLimiter(100, 100)
	defer limiter.Stop()
	authLimiter := mw.NewRateLimiter(100, 100)
	defer authLimiter.Stop()
	pow := mw.NewPowGuard(16)
	cfg := &config.Config{}
	cfg.Vault.MaxSizeMB = 15
	r := chi.NewRouter()
	productionGlobalMiddleware(r, cfg, limiter)
	r.Route("/v1/auth", func(r chi.Router) {
		r.Use(authLimiter.Limit)
		r.Use(mw.TimingEqualization(1500 * time.Millisecond))
		r.With(pow.RequirePoW).Post("/register", authHandler.Register)
	})
	server := httptest.NewServer(r)
	defer server.Close()
	client := server.Client()
	var durations []time.Duration
	var previous string
	for _, email := range []string{"new@example.com", "existing@example.com", "deleted@example.com", "new@example.com"} {
		challenge, err := pow.GenerateChallenge()
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("POST", server.URL+"/v1/auth/register", strings.NewReader(`{"email":"`+email+`","password":"password123"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-PoW-Challenge", challenge.Challenge)
		req.Header.Set("X-PoW-Nonce", registrationNonce(challenge))
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			t.Fatal(err)
		}
		durations = append(durations, time.Since(start))
		if resp.StatusCode != 202 {
			t.Fatalf("registration %s: %d %s", email, resp.StatusCode, body)
		}
		var parsed map[string]any
		if err = json.Unmarshal(body, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed) != 1 || parsed["status"] == nil {
			t.Fatalf("non-opaque response: %s", body)
		}
		if previous != "" && previous != string(body) {
			t.Fatal("registration response differs by existence")
		}
		previous = string(body)
	}
	min, max := durations[0], durations[0]
	for _, d := range durations {
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	if max-min > 750*time.Millisecond {
		t.Fatalf("SMTP/existence timing leak: %v (spread %v)", durations, max-min)
	}
	if max > 3*time.Second {
		t.Fatalf("registration waited for slow SMTP: %v", durations)
	}
}

type serverEmailChangeMailbox struct{ token string }

func (m *serverEmailChangeMailbox) SendEmailChangeEmail(_ context.Context, _ string, token string) error {
	m.token = token
	return nil
}
func TestEmailChangePreviewAndFormUseProductionMiddleware(t *testing.T) {
	p := testutil.Database(t, 0)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	verify := repository.NewVerificationRepository(p)
	mail := &serverEmailChangeMailbox{}
	hash, err := auth.HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	u := &model.User{Email: "old@example.com", Password: hash, Verified: true}
	if err = users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	svc := service.NewUserService(users, repository.NewTokenRepository(p), repository.NewTransactor(p), verify, mail)
	if _, err = svc.UpdateProfile(ctx, u.ID, &service.UpdateProfileRequest{Email: "new@example.com", CurrentPassword: "password123"}); err != nil {
		t.Fatal(err)
	}
	limiter := mw.NewRateLimiter(100, 100)
	defer limiter.Stop()
	cfg := &config.Config{}
	cfg.Vault.MaxSizeMB = 15
	r := chi.NewRouter()
	productionGlobalMiddleware(r, cfg, limiter)
	h := handler.NewUserHandler(svc, users, audit.NewNopLogger())
	r.Route("/v1/auth", func(r chi.Router) { registerEmailChangeRoutes(r, h) })
	server := httptest.NewServer(r)
	defer server.Close()
	client := server.Client()
	endpoint := server.URL + "/v1/auth/confirm-email-change"
	resp, err := client.Get(endpoint + "?token=" + mail.token)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err = resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || !strings.Contains(string(body), `method="post"`) {
		t.Fatalf("preview was not a confirmation form: %d %s", resp.StatusCode, body)
	}
	current, _ := users.GetByID(ctx, u.ID)
	if current.Email != "old@example.com" || current.SessionVersion != 0 {
		t.Fatal("production GET mutated account")
	}
	stored, err := verify.GetByHash(ctx, auth.HashToken(mail.token), repository.TokenKindEmailChange)
	if err != nil || stored == nil {
		t.Fatal("production GET consumed token")
	}
	resp, err = client.PostForm(endpoint, url.Values{"token": {mail.token}})
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err = resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("explicit confirmation form rejected: %d %s", resp.StatusCode, body)
	}
	current, _ = users.GetByID(ctx, u.ID)
	if current.Email != "new@example.com" || current.SessionVersion != 1 {
		t.Fatal("explicit POST did not confirm email")
	}
	resp, err = client.PostForm(endpoint, url.Values{"token": {mail.token}})
	if err != nil {
		t.Fatal(err)
	}
	if err = resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatal("confirmation form replay accepted")
	}
}

func (m *serverEmailChangeMailbox) SendVerificationEmail(_ context.Context, _ string, token string) error {
	m.token = token
	return nil
}
func (m *serverEmailChangeMailbox) SendPasswordResetEmail(context.Context, string, string) error {
	return nil
}

func TestActivationPreviewAndPasswordFormUseProductionMiddleware(t *testing.T) {
	p := testutil.Database(t, 0)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	verify := repository.NewVerificationRepository(p)
	mail := &serverEmailChangeMailbox{}
	svc := service.NewAuthService(users, repository.NewTokenRepository(p), verify, repository.NewTransactor(p), nil, mail, nil)
	if _, err := svc.Register(ctx, &service.RegisterRequest{Email: "owner@example.com", Password: "attacker-password"}); err != nil {
		t.Fatal(err)
	}
	before, _ := users.GetByEmail(ctx, "owner@example.com")
	limiter := mw.NewRateLimiter(100, 100)
	defer limiter.Stop()
	cfg := &config.Config{}
	cfg.Vault.MaxSizeMB = 15
	r := chi.NewRouter()
	productionGlobalMiddleware(r, cfg, limiter)
	h := handler.NewAuthHandler(svc, audit.NewNopLogger())
	r.Route("/v1/auth", func(r chi.Router) { registerVerificationRoutes(r, h) })
	server := httptest.NewServer(r)
	defer server.Close()
	client := server.Client()
	endpoint := server.URL + "/v1/auth/verify-email"
	resp, err := client.Get(endpoint + "?token=" + mail.token)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err = resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.Contains(string(body), `name="new_password"`) {
		t.Fatalf("password preview missing: %d", resp.StatusCode)
	}
	after, _ := users.GetByID(ctx, before.ID)
	live, _ := verify.GetByHash(ctx, auth.HashToken(mail.token), repository.TokenKindEmailVerify)
	if after.Verified || after.Password != before.Password || after.SessionVersion != before.SessionVersion || live == nil {
		t.Fatal("production scanner GET changed activation state")
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("preview omitted secret-safe response headers")
	}
	resp, err = client.PostForm(endpoint, url.Values{"token": {mail.token}, "new_password": {"owner-password"}})
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err = resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("password form rejected by production middleware: %d %s", resp.StatusCode, body)
	}
	after, _ = users.GetByID(ctx, before.ID)
	if valid, _ := auth.VerifyPassword("owner-password", after.Password); !valid || !after.Verified {
		t.Fatal("explicit form failed to activate owner password")
	}
}
