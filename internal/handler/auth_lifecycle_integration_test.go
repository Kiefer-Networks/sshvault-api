package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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
	confirmer.ConfirmEmailChange(w, httptest.NewRequest("POST", "/v1/auth/confirm-email-change", strings.NewReader(`{"token":"`+mail.token+`"}`)))
	if w.Code != 200 {
		t.Fatalf("confirmation: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	confirmer.ConfirmEmailChange(w, httptest.NewRequest("POST", "/v1/auth/confirm-email-change", strings.NewReader(`{"token":"`+mail.token+`"}`)))
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
	if w.Code != 401 || decodeError(t, w) != "invalid credentials" {
		t.Fatalf("unverified login status/body: %d %s", w.Code, w.Body)
	}
}

func TestEmailChangeScannerGETIsNonMutating(t *testing.T) {
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
	if _, err := svc.UpdateProfile(ctx, u.ID, &service.UpdateProfileRequest{Email: "new@example.com", CurrentPassword: "password123"}); err != nil {
		t.Fatal(err)
	}
	h := NewUserHandler(svc, users, audit.NewNopLogger())
	w := httptest.NewRecorder()
	h.PreviewEmailChange(w, httptest.NewRequest("GET", "/v1/auth/confirm-email-change?token="+mail.token, nil))
	got, _ := users.GetByID(ctx, u.ID)
	if got.Email != "old@example.com" || got.SessionVersion != 0 || got.PendingEmail != "new@example.com" {
		t.Fatal("scanner GET mutated security-sensitive account state")
	}
	var active int
	if err := p.QueryRow(ctx, "SELECT count(*) FROM verification_tokens WHERE NOT used").Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatal("scanner GET consumed confirmation token")
	}
}

type distributedRegistrationMail struct{ sends atomic.Int32 }

func (m *distributedRegistrationMail) SendVerificationEmail(context.Context, string, string) error {
	m.sends.Add(1)
	return nil
}
func (m *distributedRegistrationMail) SendPasswordResetEmail(context.Context, string, string) error {
	return nil
}
func TestRegistrationRecipientCooldownAcrossClientIPs(t *testing.T) {
	p := testutil.Database(t, 0)
	mail := &distributedRegistrationMail{}
	users := repository.NewUserRepository(p)
	svc := service.NewAuthService(users, repository.NewTokenRepository(p), repository.NewVerificationRepository(p), repository.NewTransactor(p), nil, mail, nil)
	h := NewAuthHandler(svc, audit.NewNopLogger())
	attempt := func(ip string) string {
		req := httptest.NewRequest("POST", "/v1/auth/register", strings.NewReader(`{"email":"Budget@Example.com","password":"password123"}`))
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		h.Register(w, req)
		if w.Code != 202 {
			t.Errorf("registration status %d", w.Code)
		}
		return w.Body.String()
	}
	expected := attempt("192.0.2.1:1000")
	var wg sync.WaitGroup
	for i := 2; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if got := attempt(fmt.Sprintf("192.0.2.%d:1000", i)); got != expected {
				t.Error("throttled registration changed response")
			}
		}(i)
	}
	wg.Wait()
	if mail.sends.Load() != 1 {
		t.Fatalf("distributed resend bypassed recipient budget: %d", mail.sends.Load())
	}
	var digest string
	var rows int
	if err := p.QueryRow(context.Background(), "SELECT count(*),min(recipient_digest) FROM mail_send_budgets").Scan(&rows, &digest); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || len(digest) != 64 || strings.Contains(digest, "@") {
		t.Fatalf("recipient budget is not normalized and pseudonymous: rows=%d digest=%q", rows, digest)
	}
	testutil.Exec(t, p, "UPDATE mail_send_budgets SET next_send_at=NOW()-interval '1 second'")
	if got := attempt("198.51.100.1:1000"); got != expected {
		t.Fatal("cooldown expiry altered opaque response")
	}
	if mail.sends.Load() != 2 {
		t.Fatal("mail was not admitted after cooldown")
	}
}
