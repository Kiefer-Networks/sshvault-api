package repository_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/testutil"
)

func TestMigration020ClearsLegacyIPAndRestoresImmutability(t *testing.T) {
	p := testutil.Database(t, 19)
	testutil.Exec(t, p, `INSERT INTO audit_logs(category,action,ip_address) VALUES('auth','login','192.0.2.41'),('auth','login','0.0.0.0')`)
	sql, err := os.ReadFile(filepath.Join(testutil.MigrationDir(), "020_remove_ip_tracking.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(context.Background(), string(sql)); err != nil {
		t.Fatalf("upgrade with legacy IP must succeed: %v", err)
	}
	var count int
	if err := p.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE ip_address <> ''`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("retained %d legacy IPs", count)
	}
	if _, err := p.Exec(context.Background(), `UPDATE audit_logs SET action='tampered'`); err == nil {
		t.Fatal("immutability trigger was not restored")
	}
}

func TestPurgeDeletesOnlyExpiredAccountsAndAnonymizesAudit(t *testing.T) {
	p := testutil.Database(t, 0)
	expired := seedPurgeUser(t, p, true)
	active := seedPurgeUser(t, p, false)
	recent := seedPurgeUser(t, p, true)
	testutil.Exec(t, p, `UPDATE users SET deleted_at=now() WHERE id=$1`, recent)
	testutil.Exec(t, p, `INSERT INTO vaults(user_id,version,blob,checksum) VALUES($1,1,'secret','checksum')`, expired)
	testutil.Exec(t, p, `INSERT INTO vault_history(vault_id,version,blob,checksum) SELECT id,1,'history','checksum' FROM vaults WHERE user_id=$1`, expired)
	testutil.Exec(t, p, `INSERT INTO verification_tokens(user_id,token_hash,kind,expires_at) VALUES($1,'verify','email_verify',now())`, expired)
	testutil.Exec(t, p, `INSERT INTO login_attempts(email,ip_address,success) VALUES($1,'hash',FALSE)`, expired.String()+"@example.com")
	// Legacy failed-auth records may have an email and no actor ID.
	testutil.Exec(t, p, `INSERT INTO audit_logs(category,action,details) VALUES('auth','login_failed',jsonb_build_object('email',$1::text))`, expired.String()+"@example.com")
	repo := repository.NewUserRepository(p)
	ids, err := repo.PurgeDeleted(context.Background(), time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != expired {
		t.Fatalf("deleted IDs=%v", ids)
	}
	for _, table := range []string{"vaults", "vault_history", "verification_tokens", "login_attempts"} {
		var count int
		if err := p.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("retained %d %s rows", count, table)
		}
	}
	for _, uid := range []uuid.UUID{active, recent} {
		var count int
		if err := p.QueryRow(context.Background(), `SELECT count(*) FROM users u JOIN refresh_tokens r ON r.user_id=u.id JOIN devices d ON d.user_id=u.id WHERE u.id=$1`, uid).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("unexpired account %s lost data", uid)
		}
	}
	var anonymized int
	if err := p.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE actor_id IS NULL AND actor_email='' AND details='{}' AND ip_address=''`).Scan(&anonymized); err != nil {
		t.Fatal(err)
	}
	if anonymized != 2 {
		t.Fatalf("anonymized=%d, expected known-user and legacy failed-auth entries", anonymized)
	}
	ids, err = repo.PurgeDeleted(context.Background(), time.Now().Add(-30*24*time.Hour))
	if err != nil || len(ids) != 0 {
		t.Fatalf("retry IDs=%v err=%v", ids, err)
	}
	if _, err := p.Exec(context.Background(), `UPDATE audit_logs SET action='tampered'`); err == nil {
		t.Fatal("purge left update trigger disabled")
	}
}

func TestPurgeChildDeletionFailureRestoresAuditAndIdentity(t *testing.T) {
	p := testutil.Database(t, 0)
	uid := seedPurgeUser(t, p, true)
	testutil.Exec(t, p, `CREATE FUNCTION reject_child_delete() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected child failure'; END $$ LANGUAGE plpgsql; CREATE TRIGGER reject_child BEFORE DELETE ON devices FOR EACH ROW EXECUTE FUNCTION reject_child_delete()`)
	ids, err := repository.NewUserRepository(p).PurgeDeleted(context.Background(), time.Now())
	if err == nil || len(ids) != 0 {
		t.Fatalf("expected rollback, IDs=%v err=%v", ids, err)
	}
	var count int
	if err := p.QueryRow(context.Background(), `SELECT count(*) FROM users u JOIN audit_logs a ON a.actor_id=u.id JOIN refresh_tokens r ON r.user_id=u.id WHERE u.id=$1 AND a.actor_email=u.email AND a.details->>'device'='private'`, uid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("failed deletion did not restore identity, children and audit")
	}
	if _, err := p.Exec(context.Background(), `UPDATE audit_logs SET action='tampered'`); err == nil {
		t.Fatal("rollback left trigger disabled")
	}
}

func TestDelayedAuditAfterHardDeleteDoesNotRestoreIdentity(t *testing.T) {
	p := testutil.Database(t, 0)
	uid := seedPurgeUser(t, p, false)
	if _, err := repository.NewUserRepository(p).HardDelete(context.Background(), uid); err != nil {
		t.Fatal(err)
	}
	// A buffered event can reach the repository after the user's purge commits.
	entry := &audit.Entry{Category: audit.CatAuth, Action: audit.ActLogin, ActorID: &uid, ActorEmail: uid.String() + "@example.com", ResourceType: "user", ResourceID: uid.String(), IPAddress: "192.0.2.9", Details: map[string]any{"private": "data"}}
	if err := audit.NewRepository(p).Insert(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := p.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE actor_id IS NOT NULL OR actor_email<>'' OR ip_address<>'' OR details<>'{}' OR resource_id<>''`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("delayed audit restored purged identity or private details")
	}
}

func seedPurgeUser(t *testing.T, p *pgxpool.Pool, deleted bool) uuid.UUID {
	t.Helper()
	uid := uuid.New()
	testutil.Exec(t, p, `INSERT INTO users(id,email,password,deleted_at) VALUES($1,$2,'test',CASE WHEN $3 THEN now()-interval '40 days' ELSE NULL END)`, uid, uid.String()+"@example.com", deleted)
	testutil.Exec(t, p, `INSERT INTO refresh_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 day')`, uid, uid.String())
	testutil.Exec(t, p, `INSERT INTO devices(user_id,name,platform) VALUES($1,'laptop','linux')`, uid)
	testutil.Exec(t, p, `INSERT INTO audit_logs(category,action,actor_id,actor_email,details) VALUES('auth','login',$1,$2,'{"device":"private"}')`, uid, uid.String()+"@example.com")
	return uid
}

func TestPurgeAnonymizationFailureRollsBack(t *testing.T) {
	p := testutil.Database(t, 0)
	uid := seedPurgeUser(t, p, true)
	testutil.Exec(t, p, `CREATE OR REPLACE FUNCTION audit_anonymize_user(target_user_id uuid) RETURNS int AS $$ BEGIN RAISE EXCEPTION 'injected anonymization failure'; END $$ LANGUAGE plpgsql`)
	_, err := repository.NewUserRepository(p).PurgeDeleted(context.Background(), time.Now().Add(-30*24*time.Hour))
	if err == nil {
		t.Error("purge must abort when audit anonymization fails")
	}
	for _, table := range []string{"users", "refresh_tokens", "devices"} {
		var count int
		if err := p.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("%s lost data after failed anonymization for %s", table, uid)
		}
	}
}

func TestPurgeConcurrentActivationPreservesChildren(t *testing.T) {
	p := testutil.Database(t, 0)
	uid := seedPurgeUser(t, p, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	barrier, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Release()
	if _, err = barrier.Exec(ctx, `SELECT pg_advisory_lock(740120)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = barrier.Exec(context.Background(), `SELECT pg_advisory_unlock(740120)`) }()
	testutil.Exec(t, p, `CREATE FUNCTION pause_refresh_delete() RETURNS trigger AS $$ BEGIN PERFORM pg_advisory_xact_lock(740120); RETURN OLD; END $$ LANGUAGE plpgsql; CREATE TRIGGER pause_refresh BEFORE DELETE ON refresh_tokens FOR EACH ROW EXECUTE FUNCTION pause_refresh_delete()`)
	activation, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer activation.Rollback(context.Background())
	if _, err = activation.Exec(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, uid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := repository.NewUserRepository(p).PurgeDeleted(ctx, time.Now().Add(-30*24*time.Hour))
		done <- err
	}()
	// The old purge waits in the child-delete trigger; the fixed purge waits
	// for the user lock. Both are observable PostgreSQL lock waits, not sleeps.
	for {
		var waiting bool
		err = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND pid<>pg_backend_pid() AND wait_event_type='Lock')`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
	}
	if _, err = activation.Exec(ctx, `UPDATE users SET deleted_at=NULL WHERE id=$1`, uid); err != nil {
		t.Fatal(err)
	}
	if err = activation.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = barrier.Exec(ctx, `SELECT pg_advisory_unlock(740120)`); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"refresh_tokens", "devices"} {
		var count int
		if err := p.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE user_id=$1", uid).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("reactivated user lost %s: count=%d", table, count)
		}
	}
}

func TestPurgeWinningLockPreventsReactivation(t *testing.T) {
	p := testutil.Database(t, 0)
	uid := seedPurgeUser(t, p, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	barrier, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Release()
	if _, err = barrier.Exec(ctx, `SELECT pg_advisory_lock(740121)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = barrier.Exec(context.Background(), `SELECT pg_advisory_unlock(740121)`) }()
	testutil.Exec(t, p, `CREATE FUNCTION pause_purge() RETURNS trigger AS $$ BEGIN PERFORM pg_advisory_xact_lock(740121); RETURN OLD; END $$ LANGUAGE plpgsql; CREATE TRIGGER pause_purge BEFORE DELETE ON devices FOR EACH ROW EXECUTE FUNCTION pause_purge()`)
	purgeDone := make(chan error, 1)
	go func() { _, err := repository.NewUserRepository(p).PurgeDeleted(ctx, time.Now()); purgeDone <- err }()
	for {
		var waiting bool
		if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event='advisory')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
	}
	activation, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer activation.Release()
	pid := activation.Conn().PgConn().PID()
	activated := make(chan int64, 1)
	activationErr := make(chan error, 1)
	go func() {
		result, err := activation.Exec(ctx, `UPDATE users SET deleted_at=NULL WHERE id=$1`, uid)
		activated <- result.RowsAffected()
		activationErr <- err
	}()
	for {
		var blocked bool
		if err := p.QueryRow(ctx, `SELECT cardinality(pg_blocking_pids($1)) > 0`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
	}
	if _, err = barrier.Exec(ctx, `SELECT pg_advisory_unlock(740121)`); err != nil {
		t.Fatal(err)
	}
	if err := <-purgeDone; err != nil {
		t.Fatal(err)
	}
	if count := <-activated; count != 0 {
		t.Fatalf("activation revived a purged account: rows=%d", count)
	}
	if err := <-activationErr; err != nil {
		t.Fatal(err)
	}
}

func TestPurgeCandidateDiscoveryFailureDoesNotMutateData(t *testing.T) {
	p := testutil.Database(t, 0)
	seedPurgeUser(t, p, true)
	testutil.Exec(t, p, `ALTER TABLE users RENAME COLUMN deleted_at TO unavailable_deleted_at`)
	ids, err := repository.NewUserRepository(p).PurgeDeleted(context.Background(), time.Now())
	if err == nil || len(ids) != 0 {
		t.Fatalf("candidate failure returned IDs=%v err=%v", ids, err)
	}
	var count int
	if err := p.QueryRow(context.Background(), `SELECT count(*) FROM users u JOIN devices d ON d.user_id=u.id JOIN audit_logs a ON a.actor_id=u.id WHERE a.actor_email=u.email`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("candidate discovery failure mutated identity, audit, or children")
	}
}

func TestForwardMigrationRemovesLegacyFailedAuthDetails(t *testing.T) {
	p := testutil.Database(t, 21)
	testutil.Exec(t, p, `INSERT INTO audit_logs(category,action,ip_address,details) VALUES('auth','login_failed','192.0.2.8','{"email":"legacy@example.com","error":"duplicate legacy@example.com"}')`)
	sql, err := os.ReadFile(filepath.Join(testutil.MigrationDir(), "022_atomic_user_purge.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	testutil.Exec(t, p, string(sql))
	var ip, details string
	if err := p.QueryRow(context.Background(), `SELECT ip_address,details::text FROM audit_logs`).Scan(&ip, &details); err != nil {
		t.Fatal(err)
	}
	if ip != "" || details != `{"email": "[redacted]"}` {
		t.Fatalf("legacy PII retained: ip=%q details=%s", ip, details)
	}
	if _, err := p.Exec(context.Background(), `UPDATE audit_logs SET action='tampered'`); err == nil {
		t.Fatal("forward migration left trigger disabled")
	}
}
