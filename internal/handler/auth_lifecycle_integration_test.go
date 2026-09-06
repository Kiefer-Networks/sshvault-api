package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/service"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

type lifecycleMail struct{ token string }

func (m *lifecycleMail) SendEmailChangeEmail(_ context.Context, _, token string) error {
	m.token = token
	return nil
}

func TestLifecycleRegistrationHTTPIdentical(t *testing.T) {
	p := testutil.Database(t, 0)
	users := repository.NewUserRepository(p)
	svc := service.NewAuthService(users, repository.NewTokenRepository(p), repository.NewVerificationRepository(p), repository.NewTransactor(p), nil, nil, nil)
	h := NewAuthHandler(svc, audit.NewNopLogger())
	var body string
	for i := 0; i < 3; i++ {
		if i == 2 {
			testutil.Exec(t, p, "UPDATE users SET deleted_at=NOW()")
		}
		w := httptest.NewRecorder()
		h.Register(w, httptest.NewRequest("POST", "/v1/auth/register", strings.NewReader(`{"email":"account@example.com","password":"password123"}`)))
		if w.Code != 202 {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		if i == 0 {
			body = w.Body.String()
		} else if body != w.Body.String() {
			t.Fatal("existing/deleted registration reveals account existence")
		}
		var data map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		if len(data) != 1 || data["status"] == nil {
			t.Fatalf("registration exposes additional data: %v", data)
		}
	}
}
func TestLifecycleEmailChangeHTTPPendingAndConfirmation(t *testing.T) {
	p := testutil.Database(t, 0)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	mail := &lifecycleMail{}
	hash, _ := auth.HashPassword("password123")
	u := &model.User{Email: "old@example.com", Password: hash, Verified: true}
	if err := users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	svc := service.NewUserService(users, repository.NewTokenRepository(p), repository.NewTransactor(p), repository.NewVerificationRepository(p), mail)
	h := NewUserHandler(svc, users, audit.NewNopLogger())
	w := httptest.NewRecorder()
	h.UpdateProfile(w, userAuthedRequest(httptest.NewRequest("PATCH", "/v1/users/me", strings.NewReader(`{"email":"new@example.com","current_password":"password123"}`)), u.ID))
	if w.Code != 202 || !strings.Contains(w.Body.String(), "pending_confirmation") {
		t.Fatalf("pending response: %d %s", w.Code, w.Body)
	}
	confirmer := h
	w = httptest.NewRecorder()
	confirmer.ConfirmEmailChange(w, httptest.NewRequest("GET", "/v1/auth/confirm-email-change?token="+mail.token, nil))
	if w.Code != 200 {
		t.Fatalf("confirmation: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	confirmer.ConfirmEmailChange(w, httptest.NewRequest("GET", "/v1/auth/confirm-email-change?token="+mail.token, nil))
	if w.Code != 400 {
		t.Fatalf("replay: %d", w.Code)
	}
}

func TestLifecycleUnverifiedLoginHTTP(t *testing.T) {
	p := testutil.Database(t, 0)
	ctx := context.Background()
	users := repository.NewUserRepository(p)
	hash, err := auth.HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	u := &model.User{Email: "unverified@example.com", Password: hash}
	if err = users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	svc := service.NewAuthService(users, repository.NewTokenRepository(p), repository.NewVerificationRepository(p), repository.NewTransactor(p), nil, nil, nil)
	h := NewAuthHandler(svc, audit.NewNopLogger())
	w := httptest.NewRecorder()
	h.Login(w, httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"email":"unverified@example.com","password":"password123"}`)))
	if w.Code != 403 || decodeError(t, w) != "verification_required" {
		t.Fatalf("unverified login status/body: %d %s", w.Code, w.Body)
	}
}
