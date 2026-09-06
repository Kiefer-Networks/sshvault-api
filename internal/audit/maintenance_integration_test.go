package audit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

func TestAuditInsertWaitsForMaintenanceBeforeTableLocks(t *testing.T) {
	for _, withActor := range []bool{true, false} {
		t.Run(fmt.Sprintf("actor=%t", withActor), func(t *testing.T) {
			pool := testutil.Database(t, 0)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			entry := &audit.Entry{ID: uuid.New(), Category: audit.CatAuth, Action: audit.ActLogin}
			if withActor {
				id := uuid.New()
				testutil.Exec(t, pool, `INSERT INTO users(id,email,password) VALUES($1,'audit-maintenance@example.com','unused')`, id)
				entry.ActorID = &id
			}
			result := make(chan error, 1)
			err := repository.WithExclusiveMaintenance(ctx, pool, func(*pgx.Conn) error {
				go func() { result <- audit.NewRepository(pool).Insert(ctx, entry) }()
				ticker := time.NewTicker(5 * time.Millisecond)
				defer ticker.Stop()
				var pid int
				for pid == 0 {
					select {
					case err := <-result:
						return fmt.Errorf("audit insert crossed exclusive maintenance: %v", err)
					case <-ctx.Done():
						return fmt.Errorf("audit insert never waited on maintenance: %w", ctx.Err())
					case <-ticker.C:
						err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(l.pid),0) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name=$1 AND l.locktype='advisory' AND NOT l.granted`, pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&pid)
						if err != nil {
							return err
						}
					}
				}
				var tableLocks int
				if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid=$1 AND relation IN ('users'::regclass,'audit_logs'::regclass)`, pid).Scan(&tableLocks); err != nil {
					return err
				}
				if tableLocks != 0 {
					return fmt.Errorf("waiting audit insert already touched %d user/audit table locks", tableLocks)
				}
				// Restore runs DDL in a separate session while holding maintenance.
				tx, err := pool.Begin(ctx)
				if err != nil {
					return err
				}
				defer func() { _ = tx.Rollback(context.Background()) }()
				_, err = tx.Exec(ctx, `LOCK TABLE users, audit_logs IN ACCESS EXCLUSIVE MODE NOWAIT`)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("audit insert did not resume after maintenance")
			}
			var exists bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_logs WHERE id=$1)`, entry.ID).Scan(&exists); err != nil || !exists {
				t.Fatalf("audit insert not committed: exists=%t err=%v", exists, err)
			}
		})
	}
}
