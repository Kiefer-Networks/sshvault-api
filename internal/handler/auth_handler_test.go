package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// newAuthHandler creates a minimal AuthHandler with nil services for input-validation tests.
// These tests only verify handler-level validation (before the service is called).
func newAuthHandler() *AuthHandler {
	return &AuthHandler{
		authService: nil,
		apple:       nil,
		google:      nil,
		audit:       nil,
	}
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	return resp["error"]
}

func TestRegisterMissingFields(t *testing.T) {
	h := newAuthHandler()

	tests := []struct {
		name string
		body string
		want string
	}{
		{"empty body", `{}`, "email and password are required"},
		{"missing password", `{"email":"a@b.com"}`, "email and password are required"},
		{"missing email", `{"password":"12345678"}`, "email and password are required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			h.Register(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			msg := decodeError(t, rec)
			if msg != tt.want {
				t.Errorf("error = %q, want %q", msg, tt.want)
			}
		})
	}
}

func TestRegisterShortPassword(t *testing.T) {
	h := newAuthHandler()

	req := httptest.NewRequest(http.MethodPost, "/register",
		strings.NewReader(`{"email":"a@b.com","password":"short"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "at least 8") {
		t.Errorf("error = %q, want 'at least 8 characters'", msg)
	}
}

func TestRegisterInvalidJSON(t *testing.T) {
	h := newAuthHandler()

	req := httptest.NewRequest(http.MethodPost, "/register",
		strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRefreshMissingToken(t *testing.T) {
	h := newAuthHandler()

	req := httptest.NewRequest(http.MethodPost, "/refresh",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "refresh_token is required") {
		t.Errorf("error = %q, want 'refresh_token is required'", msg)
	}
}

func TestVerifyEmailMissingToken(t *testing.T) {
	h := newAuthHandler()

	req := httptest.NewRequest(http.MethodGet, "/verify-email", nil)
	rec := httptest.NewRecorder()

	h.VerifyEmail(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if msg != "token is required" {
		t.Errorf("error = %q, want %q", msg, "token is required")
	}
}

func TestResetPasswordMissingFields(t *testing.T) {
	h := newAuthHandler()

	tests := []struct {
		name string
		body string
	}{
		{"empty body", `{}`},
		{"missing token", `{"new_password":"12345678"}`},
		{"missing password", `{"token":"abc"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/reset-password",
				strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			h.ResetPassword(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestResetPasswordShortNewPassword(t *testing.T) {
	h := newAuthHandler()

	req := httptest.NewRequest(http.MethodPost, "/reset-password",
		strings.NewReader(`{"token":"abc","new_password":"short"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.ResetPassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "at least 8") {
		t.Errorf("error = %q, want 'at least 8 characters'", msg)
	}
}

func TestOAuthMissingIDToken(t *testing.T) {
	h := newAuthHandler()

	req := httptest.NewRequest(http.MethodPost, "/oauth/google",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Need chi context for URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "google")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.OAuth(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if msg != "id_token is required" {
		t.Errorf("error = %q, want %q", msg, "id_token is required")
	}
}

func TestOAuthOversizedToken(t *testing.T) {
	h := newAuthHandler()

	oversized := strings.Repeat("a", 11*1024) // > 10 KB
	body := `{"id_token":"` + oversized + `"}`

	req := httptest.NewRequest(http.MethodPost, "/oauth/google",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "google")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.OAuth(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "exceeds maximum size") {
		t.Errorf("error = %q, want 'exceeds maximum size'", msg)
	}
}

func TestOAuthUnsupportedProvider(t *testing.T) {
	h := newAuthHandler()

	req := httptest.NewRequest(http.MethodPost, "/oauth/github",
		strings.NewReader(`{"id_token":"sometoken"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.OAuth(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if msg != "unsupported provider" {
		t.Errorf("error = %q, want %q", msg, "unsupported provider")
	}
}

func TestLoginMissingFields(t *testing.T) {
	h := newAuthHandler()

	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(`{"email":"a@b.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if msg != "email and password are required" {
		t.Errorf("error = %q, want %q", msg, "email and password are required")
	}
}
