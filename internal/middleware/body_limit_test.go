package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBodyLimit_AllowsSmallBody(t *testing.T) {
	limit := int64(1024)
	body := strings.NewReader(`{"key":"value"}`)

	called := false
	handler := BodyLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler was not called for small body")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestBodyLimit_RejectsLargeContentLength(t *testing.T) {
	limit := int64(100)

	handler := BodyLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for oversized body")
	}))

	body := bytes.NewReader(make([]byte, 200))
	req := httptest.NewRequest("POST", "/", body)
	req.ContentLength = 200
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected status 413, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "request body too large" {
		t.Errorf("expected error message 'request body too large', got %q", resp["error"])
	}
}

func TestBodyLimit_ContentTypeJSON(t *testing.T) {
	limit := int64(10)
	handler := BodyLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest("POST", "/", strings.NewReader("a]long body that is over 10"))
	req.ContentLength = 26
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestBodyLimit_ExactLimit(t *testing.T) {
	limit := int64(10)
	body := strings.NewReader("0123456789") // exactly 10 bytes

	called := false
	handler := BodyLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("unexpected error reading body: %v", err)
		}
		if string(data) != "0123456789" {
			t.Errorf("body = %q, want %q", string(data), "0123456789")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", body)
	req.ContentLength = 10
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler was not called for body exactly at limit")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestBodyLimit_OneBeyondLimit(t *testing.T) {
	limit := int64(10)

	handler := BodyLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for body exceeding limit")
	}))

	body := strings.NewReader("01234567890") // 11 bytes
	req := httptest.NewRequest("POST", "/", body)
	req.ContentLength = 11
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected status 413, got %d", w.Code)
	}
}

func TestBodyLimit_EmptyBody(t *testing.T) {
	limit := int64(1024)

	called := false
	handler := BodyLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler was not called for empty body")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestBodyLimit_MaxBytesReaderWraps(t *testing.T) {
	limit := int64(5)

	handler := BodyLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Body is wrapped in MaxBytesReader, reading beyond limit should fail.
		// ContentLength is not set, so the middleware lets it through to MaxBytesReader.
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Error("expected error reading body beyond limit, got nil")
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Do not set ContentLength so the Content-Length check is bypassed,
	// but MaxBytesReader will still enforce the limit.
	req := httptest.NewRequest("POST", "/", strings.NewReader("this is way too long for a 5 byte limit"))
	req.ContentLength = -1
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestBodyLimit_ZeroLimit(t *testing.T) {
	limit := int64(0)

	handler := BodyLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called with content-length > 0 and limit 0")
	}))

	req := httptest.NewRequest("POST", "/", strings.NewReader("data"))
	req.ContentLength = 4
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected status 413, got %d", w.Code)
	}
}

func TestBodyLimit_DifferentMethods(t *testing.T) {
	limit := int64(50)
	methods := []string{"POST", "PUT", "PATCH", "DELETE"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			called := false
			handler := BodyLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(method, "/", strings.NewReader(`{"a":"b"}`))
			req.ContentLength = 9
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if !called {
				t.Errorf("next handler not called for method %s with small body", method)
			}
		})
	}
}
