package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
)

// newAuditHandler creates an AuditHandler with a nil-pool repository.
// This is sufficient for testing handler-level validation (before repo.Query is called).
func newAuditHandler() *AuditHandler {
	repo := audit.NewRepository(nil)
	return NewAuditHandler(repo)
}

func auditAuthedRequest(r *http.Request, userID uuid.UUID) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.UserIDKey, userID)
	return r.WithContext(ctx)
}

// --- GetAuditLogs: authentication tests ---

func TestGetAuditLogs_NoUserID(t *testing.T) {
	h := newAuditHandler()

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	rec := httptest.NewRecorder()

	h.GetAuditLogs(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	msg := decodeError(t, rec)
	if msg != "unauthorized" {
		t.Errorf("error = %q, want %q", msg, "unauthorized")
	}
}

// --- GetAuditLogs: 'from' parameter validation ---

func TestGetAuditLogs_InvalidFromFormat(t *testing.T) {
	h := newAuditHandler()
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/audit?from=not-a-date", nil)
	req = auditAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetAuditLogs(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "'from'") {
		t.Errorf("error = %q, want message about 'from' format", msg)
	}
	if !strings.Contains(msg, "RFC3339") {
		t.Errorf("error = %q, want message about RFC3339", msg)
	}
}

func TestGetAuditLogs_InvalidFromDateOnly(t *testing.T) {
	h := newAuditHandler()
	userID := uuid.New()

	// Date without time is not valid RFC3339
	req := httptest.NewRequest(http.MethodGet, "/audit?from=2024-01-01", nil)
	req = auditAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetAuditLogs(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestGetAuditLogs_InvalidFromUnixTimestamp(t *testing.T) {
	h := newAuditHandler()
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/audit?from=1704067200", nil)
	req = auditAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetAuditLogs(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- GetAuditLogs: 'to' parameter validation ---

func TestGetAuditLogs_InvalidToFormat(t *testing.T) {
	h := newAuditHandler()
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/audit?to=2024-01-01", nil)
	req = auditAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetAuditLogs(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	if !strings.Contains(msg, "'to'") {
		t.Errorf("error = %q, want message about 'to' format", msg)
	}
}

func TestGetAuditLogs_InvalidToGarbage(t *testing.T) {
	h := newAuditHandler()
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/audit?to=garbage", nil)
	req = auditAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetAuditLogs(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- GetAuditLogs: 'limit' parameter validation ---

func TestGetAuditLogs_InvalidLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit string
	}{
		{"non-numeric", "abc"},
		{"zero", "0"},
		{"negative", "-1"},
		{"float", "1.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newAuditHandler()
			userID := uuid.New()

			req := httptest.NewRequest(http.MethodGet, "/audit?limit="+tt.limit, nil)
			req = auditAuthedRequest(req, userID)
			rec := httptest.NewRecorder()

			h.GetAuditLogs(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			msg := decodeError(t, rec)
			if !strings.Contains(msg, "'limit'") {
				t.Errorf("error = %q, want message about 'limit'", msg)
			}
		})
	}
}

// --- GetAuditLogs: 'offset' parameter validation ---

func TestGetAuditLogs_InvalidOffset(t *testing.T) {
	tests := []struct {
		name   string
		offset string
	}{
		{"non-numeric", "abc"},
		{"negative", "-1"},
		{"float", "1.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newAuditHandler()
			userID := uuid.New()

			req := httptest.NewRequest(http.MethodGet, "/audit?offset="+tt.offset, nil)
			req = auditAuthedRequest(req, userID)
			rec := httptest.NewRecorder()

			h.GetAuditLogs(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			msg := decodeError(t, rec)
			if !strings.Contains(msg, "'offset'") {
				t.Errorf("error = %q, want message about 'offset'", msg)
			}
		})
	}
}

// --- GetAuditLogs: combination validation failures ---

func TestGetAuditLogs_InvalidFromStopsBeforeTo(t *testing.T) {
	// If 'from' is invalid, handler should return 400 before checking 'to'.
	h := newAuditHandler()
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/audit?from=bad&to=also-bad", nil)
	req = auditAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetAuditLogs(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	// Should report 'from' error first (checked before 'to')
	if !strings.Contains(msg, "'from'") {
		t.Errorf("error = %q, want message about 'from' (checked first)", msg)
	}
}

func TestGetAuditLogs_InvalidLimitStopsBeforeOffset(t *testing.T) {
	h := newAuditHandler()
	userID := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/audit?limit=bad&offset=bad", nil)
	req = auditAuthedRequest(req, userID)
	rec := httptest.NewRecorder()

	h.GetAuditLogs(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	msg := decodeError(t, rec)
	// Should report 'limit' error first (checked before 'offset')
	if !strings.Contains(msg, "'limit'") {
		t.Errorf("error = %q, want message about 'limit' (checked first)", msg)
	}
}

// --- NewAuditHandler construction ---

func TestNewAuditHandler_NotNil(t *testing.T) {
	repo := audit.NewRepository(nil)
	h := NewAuditHandler(repo)
	if h == nil {
		t.Fatal("NewAuditHandler returned nil")
	}
}
