package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/service"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

type activationMailbox struct {
	token string
	sends int
}

func (m *activationMailbox) SendVerificationEmail(_ context.Context, _, token string) error {
	m.token = token
	m.sends++
	return nil
}
func (m *activationMailbox) SendPasswordResetEmail(context.Context, string, string) error { return nil }

func TestActivationOwnerChoosesPasswordAndScannerCannotConsume(t *testing.T) {
	p := testutil.Database(t, 0)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	verify := repository.NewVerificationRepository(p)
	mailbox := &activationMailbox{}
	svc := service.NewAuthService(users, repository.NewTokenRepository(p), verify, repository.NewTransactor(p), nil, mailbox, nil)
	h := NewAuthHandler(svc, audit.NewNopLogger())
	if _, err := svc.Register(ctx, &service.RegisterRequest{Email: "owner@example.com", Password: "attacker-password"}); err != nil {
		t.Fatal(err)
	}
	firstToken := mailbox.token
	before, _ := users.GetByEmail(ctx, "owner@example.com")
	get := httptest.NewRecorder()
	h.VerifyEmail(get, httptest.NewRequest("GET", "/v1/auth/verify-email?token="+firstToken, nil))
	after, _ := users.GetByEmail(ctx, "owner@example.com")
	live, _ := verify.GetByHash(ctx, auth.HashToken(firstToken), repository.TokenKindEmailVerify)
	if get.Code != 200 || after.Verified || after.Password != before.Password || after.SessionVersion != before.SessionVersion || live == nil {
		t.Fatalf("scanner GET mutated activation state (status %d)", get.Code)
	}
	if !strings.Contains(get.Body.String(), `name="new_password"`) {
		t.Error("preview lacks owner password form")
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.Register(ctx, &service.RegisterRequest{Email: " OWNER@example.com ", Password: "another-attacker-password"}); err != nil {
			t.Fatal(err)
		}
	}
	live, _ = verify.GetByHash(ctx, auth.HashToken(firstToken), repository.TokenKindEmailVerify)
	if mailbox.sends != 1 || live == nil {
		t.Fatal("throttled signup destroyed the only delivered activation link")
	}
	for _, password := range []string{"", "short", strings.Repeat("a", 257)} {
		body, _ := json.Marshal(map[string]string{"token": firstToken, "new_password": password})
		rec := httptest.NewRecorder()
		h.VerifyEmail(rec, httptest.NewRequest("POST", "/v1/auth/verify-email", strings.NewReader(string(body))))
		if rec.Code != 400 {
			t.Fatalf("invalid activation password returned %d", rec.Code)
		}
		live, _ = verify.GetByHash(ctx, auth.HashToken(firstToken), repository.TokenKindEmailVerify)
		if live == nil {
			t.Fatal("invalid password consumed activation token")
		}
	}
	body, _ := json.Marshal(map[string]string{"token": firstToken, "new_password": "owner-chosen-password"})
	rec := httptest.NewRecorder()
	h.VerifyEmail(rec, httptest.NewRequest("POST", "/v1/auth/verify-email", strings.NewReader(string(body))))
	if rec.Code != 200 {
		t.Fatalf("owner activation: %d %s", rec.Code, rec.Body)
	}
	after, _ = users.GetByEmail(ctx, "owner@example.com")
	if valid, _ := auth.VerifyPassword("owner-chosen-password", after.Password); !valid || !after.Verified {
		t.Fatal("owner password not activated")
	}
	if valid, _ := auth.VerifyPassword("attacker-password", after.Password); valid {
		t.Fatal("attacker password became usable")
	}
	replay := httptest.NewRecorder()
	h.VerifyEmail(replay, httptest.NewRequest("POST", "/v1/auth/verify-email", strings.NewReader(string(body))))
	if replay.Code != 400 {
		t.Fatal("activation token was reusable")
	}
}
