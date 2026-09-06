package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/service"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

func TestFailedAuthenticationAuditDoesNotStoreEmailOrIP(t *testing.T) {
	for _, action := range []string{"login", "register"} {
		t.Run(action, func(t *testing.T) {
			p := testutil.Database(t, 0)
			logger := audit.NewLogger(audit.NewRepository(p), 8)
			defer logger.Stop(context.Background())
			svc := service.NewAuthService(nil, nil, nil, nil, nil, nil, nil)
			h := NewAuthHandler(svc, logger)
			const email = "private-person@example.com@invalid"
			req := httptest.NewRequest(http.MethodPost, "/"+action, strings.NewReader(`{"email":"`+email+`","password":"password123"}`))
			req.RemoteAddr = "192.0.2.4:3210"
			rec := httptest.NewRecorder()
			if action == "login" {
				h.Login(rec, req)
			} else {
				h.Register(rec, req)
			}
			logger.Stop(context.Background())
			var actorEmail, ip string
			var details []byte
			if err := p.QueryRow(context.Background(), `SELECT actor_email,ip_address,details FROM audit_logs`).Scan(&actorEmail, &ip, &details); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(details), email) || strings.Contains(actorEmail, email) {
				t.Errorf("failed-auth audit retains plaintext email: %s %s", actorEmail, details)
			}
			if ip != "" || strings.Contains(string(details), "192.0.2.4") {
				t.Errorf("audit retains plaintext IP: %q %s", ip, details)
			}
			var values map[string]any
			if err := json.Unmarshal(details, &values); err != nil {
				t.Fatal(err)
			}
			if values["email"] == "" || values["email"] == nil {
				t.Error("expected a masked identifier")
			}
		})
	}
}
