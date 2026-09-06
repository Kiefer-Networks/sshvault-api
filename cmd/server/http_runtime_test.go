package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/kiefernetworks/shellvault-server/internal/config"
	mw "github.com/kiefernetworks/shellvault-server/internal/middleware"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEarlyRejectionsHaveCORSAndUncompressedPadding(t *testing.T) {
	for _, kind := range []string{"body", "rate", "proxy"} {
		t.Run(kind, func(t *testing.T) {
			limiter := mw.NewRateLimiter(0.001, 1)
			defer limiter.Stop()
			cfg := &config.Config{}
			cfg.Vault.MaxSizeMB = 15
			cfg.Server.CORSOrigins = "https://app.example.com"
			cfg.Server.TrustedProxies = "127.0.0.1/32"
			r := chi.NewRouter()
			productionGlobalMiddleware(r, cfg, limiter)
			r.Post("/v1/test", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":true}`))
			})
			request := func() *http.Request {
				q := httptest.NewRequest("POST", "/v1/test", nil)
				q.RemoteAddr = "127.0.0.1:3333"
				q.Header.Set("Origin", "https://app.example.com")
				q.Header.Set("Accept-Encoding", "gzip")
				return q
			}
			req := request()
			want := 413
			switch kind {
			case "body":
				req.ContentLength = 11 << 20
			case "rate":
				r.ServeHTTP(httptest.NewRecorder(), request())
				want = 429
			default:
				req.Header.Set("X-Forwarded-For", "invalid")
				want = 400
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != want {
				t.Errorf("status=%d want %d", w.Code, want)
			}
			if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
				t.Error("early rejection lacks CORS")
			}
			if w.Body.Len()%1024 != 0 || w.Body.Len() == 0 {
				t.Errorf("early rejection not padded: %d", w.Body.Len())
			}
			if w.Header().Get("Content-Encoding") != "" {
				t.Error("compression invalidated padding")
			}
		})
	}
}

func TestProductionRequestsHaveContextDeadline(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost/test")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	limiter := mw.NewRateLimiter(100, 100)
	defer limiter.Stop()
	r := chi.NewRouter()
	productionGlobalMiddleware(r, cfg, limiter)
	r.Get("/deadline", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("request has no cancellation deadline")
		}
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/deadline", nil))
}
