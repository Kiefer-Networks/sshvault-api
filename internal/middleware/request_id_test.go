package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestID_GeneratesNewID(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := r.Context().Value(RequestIDKey).(string)
		if !ok || id == "" {
			t.Error("request ID not found in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	respID := w.Header().Get("X-Request-ID")
	if respID == "" {
		t.Error("X-Request-ID response header should not be empty")
	}
}

func TestRequestID_UsesProvidedID(t *testing.T) {
	providedID := "my-custom-request-id-12345"

	var contextID string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = r.Context().Value(RequestIDKey).(string)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", providedID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if contextID != providedID {
		t.Errorf("context request ID = %q, want %q", contextID, providedID)
	}

	respID := w.Header().Get("X-Request-ID")
	if respID != providedID {
		t.Errorf("response X-Request-ID = %q, want %q", respID, providedID)
	}
}

func TestRequestID_GeneratedIDIsUUID(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	id := w.Header().Get("X-Request-ID")
	// UUID v4 format: 8-4-4-4-12 hex chars
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Errorf("generated ID %q does not look like a UUID (expected 5 parts, got %d)", id, len(parts))
	}
	if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		t.Errorf("generated ID %q does not match UUID format 8-4-4-4-12", id)
	}
}

func TestRequestID_UniquePerRequest(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		id := w.Header().Get("X-Request-ID")
		if ids[id] {
			t.Fatalf("duplicate request ID generated: %q on iteration %d", id, i)
		}
		ids[id] = true
	}
}

func TestRequestID_SetsResponseHeader(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("X-Request-ID") == "" {
		t.Error("X-Request-ID should be set in response headers")
	}
}

func TestRequestID_ContextKeyType(t *testing.T) {
	// Verify RequestIDKey is the expected type and value.
	if RequestIDKey != contextKey("request_id") {
		t.Errorf("RequestIDKey = %v, want %v", RequestIDKey, contextKey("request_id"))
	}
}

func TestRequestID_CallsNextHandler(t *testing.T) {
	called := false
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler was not called")
	}
	if w.Code != http.StatusTeapot {
		t.Errorf("expected status 418, got %d", w.Code)
	}
}

func TestRequestID_EmptyHeaderGeneratesNew(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Context().Value(RequestIDKey).(string)
		if id == "" {
			t.Error("context request ID should not be empty")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", "")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	respID := w.Header().Get("X-Request-ID")
	if respID == "" {
		t.Error("response X-Request-ID should not be empty when request header is empty")
	}
}

func TestRequestID_PreservesExistingContext(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request ID is in context
		id := r.Context().Value(RequestIDKey)
		if id == nil {
			t.Error("RequestIDKey should be present in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestRequestID_ResponseHeaderMatchesContext(t *testing.T) {
	var contextID string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = r.Context().Value(RequestIDKey).(string)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	respID := w.Header().Get("X-Request-ID")
	if respID != contextID {
		t.Errorf("response header ID %q does not match context ID %q", respID, contextID)
	}
}

func TestRequestID_RejectsInvalidID(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name string
		id   string
	}{
		{"too long", "aaaaaaaaaa-bbbbbbbbbb-cccccccccc-dddddddd"},
		{"special chars", "abc<script>alert(1)</script>"},
		{"spaces", "abc def ghi"},
		{"unicode", "abc\u00e9def"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Request-ID", tt.id)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			respID := w.Header().Get("X-Request-ID")
			if respID == tt.id {
				t.Errorf("invalid X-Request-ID %q should have been replaced", tt.id)
			}
			// Should be a valid UUID
			parts := strings.Split(respID, "-")
			if len(parts) != 5 {
				t.Errorf("replaced ID %q does not look like a UUID", respID)
			}
		})
	}
}

func TestRequestID_DifferentHTTPMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Header().Get("X-Request-ID") == "" {
				t.Errorf("X-Request-ID missing for method %s", method)
			}
		})
	}
}
