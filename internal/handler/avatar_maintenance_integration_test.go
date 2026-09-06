package handler

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

func TestAvatarHandlersWaitForRestoreMaintenance(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			p := testutil.Database(t, 0)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			id := uuid.New()
			testutil.Exec(t, p, `INSERT INTO users(id,email,password,avatar) VALUES($1,'avatar@example.com','test','original')`, id)
			gate, err := p.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Release()
			if _, err = gate.Exec(ctx, "SELECT pg_advisory_lock(734862190201)"); err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = gate.Exec(context.Background(), "SELECT pg_advisory_unlock(734862190201)") }()
			avatar := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nimage"))
			req := httptest.NewRequest(method, "/v1/me/avatar", strings.NewReader(`{"avatar":"`+avatar+`"}`)).WithContext(ctx)
			req = userAuthedRequest(req, id)
			h := NewUserHandler(nil, repository.NewUserRepository(p), audit.NewNopLogger())
			rec := httptest.NewRecorder()
			done := make(chan int, 1)
			go func() {
				if method == http.MethodPut {
					h.UpdateAvatar(rec, req)
				} else {
					h.DeleteAvatar(rec, req)
				}
				done <- rec.Code
			}()
			for {
				select {
				case status := <-done:
					t.Fatalf("%s avatar crossed exclusive maintenance: HTTP %d", method, status)
				default:
				}
				var waiting bool
				if err = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock_shared%')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				runtime.Gosched()
			}
			// A waiting mutation must have neither changed nor locked the user row.
			tx, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			var got string
			if err = tx.QueryRow(ctx, "SELECT avatar FROM users WHERE id=$1 FOR UPDATE NOWAIT", id).Scan(&got); err != nil {
				t.Fatalf("avatar acquired user row lock before maintenance: %v", err)
			}
			if got != "original" {
				t.Fatal("avatar changed while exclusive maintenance was held")
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = gate.Exec(ctx, "SELECT pg_advisory_unlock(734862190201)"); err != nil {
				t.Fatal(err)
			}
			if status := <-done; status != http.StatusOK {
				t.Fatalf("avatar status after maintenance = %d", status)
			}
			if err = p.QueryRow(ctx, "SELECT avatar FROM users WHERE id=$1", id).Scan(&got); err != nil {
				t.Fatal(err)
			}
			expected := avatar
			if method == http.MethodDelete {
				expected = ""
			}
			if got != expected {
				t.Fatal("avatar mutation did not commit after maintenance ended")
			}
		})
	}
}
