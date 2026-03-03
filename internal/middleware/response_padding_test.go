package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponsePaddingTo1KB(t *testing.T) {
	handler := ResponsePadding(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`)) // 15 bytes
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	bodyLen := len(w.Body.Bytes())
	if bodyLen != 1024 {
		t.Errorf("expected body padded to 1024, got %d", bodyLen)
	}
}

func TestResponsePaddingExact1KB(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = 'A'
	}

	handler := ResponsePadding(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	bodyLen := len(w.Body.Bytes())
	if bodyLen != 1024 {
		t.Errorf("exact 1KB should not be padded further, got %d", bodyLen)
	}
}

func TestResponsePaddingMultiKB(t *testing.T) {
	data := make([]byte, 1025) // Just over 1KB
	for i := range data {
		data[i] = 'B'
	}

	handler := ResponsePadding(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	bodyLen := len(w.Body.Bytes())
	if bodyLen != 2048 {
		t.Errorf("expected body padded to 2048, got %d", bodyLen)
	}
}

func TestResponsePaddingEmpty(t *testing.T) {
	handler := ResponsePadding(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	bodyLen := len(w.Body.Bytes())
	if bodyLen != 0 {
		t.Errorf("empty body should not be padded, got %d", bodyLen)
	}
}

func TestPadToKB(t *testing.T) {
	tests := []struct {
		inputLen int
		expected int
	}{
		{0, 0},
		{1, 1024},
		{512, 1024},
		{1023, 1024},
		{1024, 1024},
		{1025, 2048},
		{2048, 2048},
		{3000, 3072},
	}
	for _, tt := range tests {
		data := make([]byte, tt.inputLen)
		result := padToKB(data)
		if len(result) != tt.expected {
			t.Errorf("padToKB(%d) = %d, want %d", tt.inputLen, len(result), tt.expected)
		}
	}
}
