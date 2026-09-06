package repository

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

func TestAccountCreationAndPurgeObserveMaintenance(t *testing.T) {
	for _, action := range []string{"create", "hard_delete", "purge"} {
		t.Run(action, func(t *testing.T) {
			p := testutil.Database(t, 0)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			id := uuid.New()
			testutil.Exec(t, p, `INSERT INTO users(id,email,password,deleted_at) VALUES($1,'retained@example.com','test',now()-interval '40 days')`, id)
			gate, err := p.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Release()
			if _, err = gate.Exec(ctx, "SELECT pg_advisory_lock($1)", maintenanceLockKey); err != nil {
				t.Fatal(err)
			}
			defer gate.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", maintenanceLockKey)
			done := make(chan error, 1)
			go func() {
				r := NewUserRepository(p)
				var err error
				switch action {
				case "create":
					err = r.Create(ctx, &model.User{Email: "new@example.com", Password: "test"})
				case "hard_delete":
					_, err = r.HardDelete(ctx, id)
				case "purge":
					_, err = r.PurgeDeleted(ctx, time.Now().Add(-30*24*time.Hour))
				}
				done <- err
			}()
			for {
				select {
				case err := <-done:
					t.Fatalf("%s crossed exclusive maintenance lock: %v", action, err)
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
			if _, err = gate.Exec(ctx, "SELECT pg_advisory_unlock($1)", maintenanceLockKey); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
