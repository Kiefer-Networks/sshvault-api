package middleware

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/model"
)

func newTestJWTManager(t *testing.T) *auth.JWTManager {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return auth.NewJWTManager(priv, 15*time.Minute, 7*24*time.Hour)
}

func TestAuthMiddlewareMissingHeader(t *testing.T) {
	jwt := newTestJWTManager(t)
	mw := NewAuthMiddleware(jwt, activeSessionUsers{})

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddlewareInvalidFormat(t *testing.T) {
	jwt := newTestJWTManager(t)
	mw := NewAuthMiddleware(jwt, activeSessionUsers{})

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "NotBearer sometoken")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// "NotBearer" is not "Bearer" — but the code uses EqualFold, so "bearer" matches.
	// "NotBearer" should fail
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	jwtMgr := newTestJWTManager(t)
	mw := NewAuthMiddleware(jwtMgr, activeSessionUsers{})

	userID := uuid.New()
	pair, _, err := jwtMgr.GenerateTokenPair(userID, 0)
	if err != nil {
		t.Fatalf("generating token pair: %v", err)
	}

	var capturedUserID uuid.UUID
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := GetUserID(r.Context())
		if !ok {
			t.Error("expected user ID in context")
		}
		capturedUserID = id
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if capturedUserID != userID {
		t.Errorf("userID = %s, want %s", capturedUserID, userID)
	}
}

func TestAuthMiddlewareExpiredToken(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Create a JWT manager with already-expired access TTL
	jwtMgr := auth.NewJWTManager(priv, -1*time.Second, 7*24*time.Hour)
	mw := NewAuthMiddleware(jwtMgr, activeSessionUsers{})

	pair, _, err := jwtMgr.GenerateTokenPair(uuid.New(), 0)
	if err != nil {
		t.Fatalf("generating token pair: %v", err)
	}

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddlewareGarbageToken(t *testing.T) {
	jwtMgr := newTestJWTManager(t)
	mw := NewAuthMiddleware(jwtMgr, activeSessionUsers{})

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestGetUserIDFromContext(t *testing.T) {
	id := uuid.New()
	ctx := context.WithValue(context.Background(), UserIDKey, id)

	got, ok := GetUserID(ctx)
	if !ok {
		t.Fatal("expected user ID in context")
	}
	if got != id {
		t.Errorf("userID = %s, want %s", got, id)
	}
}

func TestGetUserIDMissing(t *testing.T) {
	_, ok := GetUserID(context.Background())
	if ok {
		t.Error("expected no user ID in empty context")
	}
}

type activeSessionUsers struct{}

func (activeSessionUsers) GetByID(_ context.Context, id uuid.UUID) (*model.User, error) {
	return &model.User{ID: id}, nil
}

type sessionReadResult struct {
	user *model.User
	err  error
}

func (r sessionReadResult) GetByID(context.Context, uuid.UUID) (*model.User, error) {
	return r.user, r.err
}
func TestAuthMiddlewareRejectsRevokedOrUnavailableAccount(t *testing.T) {
	manager := newTestJWTManager(t)
	id := uuid.New()
	pair, _, err := manager.GenerateTokenPair(id, 7)
	if err != nil {
		t.Fatal(err)
	}
	deleted := time.Now()
	for _, tc := range []struct {
		name   string
		reader sessionReadResult
		status int
	}{
		{"missing", sessionReadResult{}, 401},
		{"deleted", sessionReadResult{user: &model.User{ID: id, SessionVersion: 7, DeletedAt: &deleted}}, 401},
		{"revoked", sessionReadResult{user: &model.User{ID: id, SessionVersion: 8}}, 401},
		{"database_error", sessionReadResult{err: errors.New("database unavailable")}, 503},
		{"active", sessionReadResult{user: &model.User{ID: id, SessionVersion: 7}}, 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewAuthMiddleware(manager, tc.reader).Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status=%d want %d", rec.Code, tc.status)
			}
		})
	}
}
