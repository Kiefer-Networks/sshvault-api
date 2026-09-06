package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

const maintenanceTestKey int64 = 734862190201

func safetyDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	p, dsn := backupTestDB(t)
	old := pool
	pool = p
	t.Cleanup(func() { pool = old })
	execSQL(t, p, `CREATE TABLE users(id uuid PRIMARY KEY,email text,deleted_at timestamptz,updated_at timestamptz,session_version bigint DEFAULT 0); CREATE TABLE refresh_tokens(user_id uuid,revoked boolean); CREATE TABLE verification_tokens(used boolean); INSERT INTO users(id,email,deleted_at) VALUES('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','test@example.com','2026-01-01Z')`)
	return p, dsn
}

func confirmedRestore(t *testing.T, dsn, path string, override bool) func() error {
	t.Helper()
	t.Setenv("DATABASE_URL", dsn)
	input, err := os.CreateTemp(t.TempDir(), "confirmation")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = input.WriteString("yes\n"); err != nil {
		t.Fatal(err)
	}
	if _, err = input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = input
	t.Cleanup(func() {
		os.Stdin = old
		if err := input.Close(); err != nil {
			t.Error(err)
		}
	})
	cmd := backupRestoreCmd()
	args := []string{path}
	if override {
		args = append(args, "--no-reconcile")
	}
	cmd.SetArgs(args)
	return cmd.Execute
}

func waitBackupQuery(t *testing.T, p *pgxpool.Pool, fragment string, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		select {
		case err := <-done:
			t.Fatalf("operation completed before lock barrier: %v", err)
		default:
		}
		var waiting bool
		err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE $1)`, "%"+fragment+"%").Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		runtime.Gosched()
	}
}

func TestSnapshotBoundManifest(t *testing.T) {
	p, dsn := safetyDB(t)
	ctx := context.Background()
	gate, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Rollback(context.Background()) }()
	if _, err = gate.Exec(ctx, "LOCK TABLE refresh_tokens IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	done := make(chan error, 1)
	var path string
	go func() { var err error; path, err = createBackupWithManifest(dsn, dir); done <- err }()
	waitBackupQuery(t, p, "COUNT(*) FROM refresh_tokens", done)
	execSQL(t, p, "UPDATE users SET deleted_at=NULL")
	if err = gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	m, err := loadManifestFile(strings.TrimSuffix(path, ".sql.gz") + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = restoreBackup(dsn, path, nil); err != nil {
		t.Fatal(err)
	}
	var deleted bool
	if err = p.QueryRow(ctx, "SELECT deleted_at IS NOT NULL FROM users").Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if !deleted || len(m.DeletedUsers) != 1 {
		t.Fatalf("dump and manifest disagree across concurrent activation: dump deleted=%v, manifest tombstones=%d", deleted, len(m.DeletedUsers))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	metadata, err := os.ReadFile(strings.TrimSuffix(path, ".sql.gz") + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var binding struct {
		FormatVersion int    `json:"format_version"`
		DumpSHA256    string `json:"dump_sha256"`
	}
	if err = json.Unmarshal(metadata, &binding); err != nil {
		t.Fatal(err)
	}
	if binding.FormatVersion != 1 || binding.DumpSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("backup lacks versioned digest binding: %+v", binding)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("unexpected backup artifacts: %v", entries)
	}
}

func TestMergePreservesLatestTombstone(t *testing.T) {
	id := uuid.New()
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := early.Add(24 * time.Hour)
	for _, reverse := range []bool{false, true} {
		a, b := early, late
		if reverse {
			a, b = b, a
		}
		m := mergeManifests(&restoreManifest{DeletedUsers: []manifestUser{{ID: id, DeletedAt: a}}}, &restoreManifest{DeletedUsers: []manifestUser{{ID: id, DeletedAt: b}}})
		if len(m.DeletedUsers) != 1 || !m.DeletedUsers[0].DeletedAt.Equal(late) {
			t.Errorf("latest tombstone lost: %+v", m.DeletedUsers)
		}
	}
}

func TestReconcilePreservesLatestRestoredTombstone(t *testing.T) {
	p, dsn := safetyDB(t)
	path, err := createBackup(dsn, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	late := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	m := &restoreManifest{DeletedUsers: []manifestUser{{ID: uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), DeletedAt: late}}}
	if err = restoreBackup(dsn, path, m); err != nil {
		t.Fatal(err)
	}
	var got time.Time
	if err = p.QueryRow(context.Background(), "SELECT deleted_at FROM users").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(late) {
		t.Fatalf("reconciliation kept older deletion timestamp %s", got)
	}
	path, err = createBackup(dsn, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m.DeletedUsers[0].DeletedAt = late.Add(-24 * time.Hour)
	if err = restoreBackup(dsn, path, m); err != nil {
		t.Fatal(err)
	}
	if err = p.QueryRow(context.Background(), "SELECT deleted_at FROM users").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(late) {
		t.Fatalf("reconciliation shortened restored retention: %s", got)
	}
}

func TestRestoreRejectsUnboundSidecar(t *testing.T) {
	for _, sidecar := range []string{"missing", "legacy", "mismatched"} {
		t.Run(sidecar, func(t *testing.T) {
			p, dsn := safetyDB(t)
			path := gzipSQL(t, "UPDATE users SET email='changed@example.com';")
			if sidecar != "missing" {
				data := `{"created_at":"2026-01-01T00:00:00Z"}`
				if sidecar == "mismatched" {
					data = `{"created_at":"2026-01-01T00:00:00Z","format_version":1,"dump_sha256":"` + strings.Repeat("0", 64) + `"}`
				}
				if err := os.WriteFile(strings.TrimSuffix(path, ".sql.gz")+".manifest.json", []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := confirmedRestore(t, dsn, path, false)(); err == nil {
				t.Error("unsafe sidecar must fail before restore")
			}
			var email string
			if err := p.QueryRow(context.Background(), "SELECT email FROM users").Scan(&email); err != nil {
				t.Fatal(err)
			}
			if email != "test@example.com" {
				t.Fatalf("unbound restore changed database to %s", email)
			}
		})
	}
}

func TestRestoreOverrideStillInvalidatesTokens(t *testing.T) {
	p, dsn := safetyDB(t)
	execSQL(t, p, "INSERT INTO refresh_tokens(revoked) VALUES(false); INSERT INTO verification_tokens(used) VALUES(false)")
	path := gzipSQL(t, "UPDATE users SET deleted_at=NULL;")
	if err := confirmedRestore(t, dsn, path, true)(); err != nil {
		t.Fatal(err)
	}
	var safe bool
	if err := p.QueryRow(context.Background(), "SELECT deleted_at IS NULL AND session_version>0 AND (SELECT bool_and(revoked) FROM refresh_tokens) AND (SELECT bool_and(used) FROM verification_tokens) FROM users").Scan(&safe); err != nil {
		t.Fatal(err)
	}
	if !safe {
		t.Fatal("override must skip tombstones while revoking all tokens")
	}
}

func TestRestoreSerializesConcurrentDeletion(t *testing.T) {
	p, dsn := safetyDB(t)
	ctx := context.Background()
	execSQL(t, p, "UPDATE users SET deleted_at=NULL")
	gate, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Release()
	if _, err = gate.Exec(ctx, "SELECT pg_advisory_lock(56789)"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = gate.Exec(context.Background(), "SELECT pg_advisory_unlock(56789)") }()
	path := gzipSQL(t, "SELECT pg_advisory_xact_lock(56789); UPDATE users SET deleted_at=NULL;")
	run := confirmedRestore(t, dsn, path, true)
	restored := make(chan error, 1)
	go func() { restored <- run() }()
	waitBackupQuery(t, p, "pg_advisory_xact_lock(56789)", restored)
	deleted := make(chan error, 1)
	go func() {
		deleted <- repository.NewUserRepository(p).SoftDelete(ctx, uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
	}()
	// An observed PostgreSQL lock wait, not elapsed time, establishes serialization.
	waitBackupQuery(t, p, "pg_advisory_xact_lock_shared", deleted)
	if _, err = gate.Exec(ctx, "SELECT pg_advisory_unlock(56789)"); err != nil {
		t.Fatal(err)
	}
	if err = <-restored; err != nil {
		t.Fatal(err)
	}
	if err = <-deleted; err != nil {
		t.Fatal(err)
	}
	var remains bool
	if err = p.QueryRow(ctx, "SELECT deleted_at IS NOT NULL FROM users").Scan(&remains); err != nil {
		t.Fatal(err)
	}
	if !remains {
		t.Fatal("concurrent deletion was lost by restore")
	}
}

func TestAccountMutationsWaitForMaintenance(t *testing.T) {
	for _, action := range []string{"api_delete", "cli_activate", "cli_deactivate", "transaction"} {
		t.Run(action, func(t *testing.T) {
			p, _ := safetyDB(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			gate, err := p.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Release()
			if _, err = gate.Exec(ctx, "SELECT pg_advisory_lock($1)", maintenanceTestKey); err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = gate.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", maintenanceTestKey) }()
			done := make(chan error, 1)
			go func() {
				var err error
				switch action {
				case "api_delete":
					err = repository.NewUserRepository(p).SoftDelete(ctx, uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
				case "transaction":
					err = repository.NewTransactor(p).WithTransaction(ctx, func(context.Context) error { return nil })
				default:
					_, err = updateUserSessions(ctx, uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), strings.TrimPrefix(action, "cli_"))
				}
				done <- err
			}()
			waitBackupQuery(t, p, "pg_advisory_xact_lock_shared", done)
			if _, err = gate.Exec(ctx, "SELECT pg_advisory_unlock($1)", maintenanceTestKey); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBackupProcessDoesNotExposeCredentials(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process argv inspection requires Linux /proc")
	}
	p, dsn := safetyDB(t)
	ctx := context.Background()
	gate, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Rollback(context.Background()) }()
	if _, err = gate.Exec(ctx, "LOCK TABLE users IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	done := make(chan error, 1)
	go func() { _, err := createBackup(dsn, dir); done <- err }()
	waitBackupQuery(t, p, "LOCK TABLE", done)
	paths, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	inspected := false
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		args := strings.Split(string(data), "\x00")
		if len(args) == 0 || filepath.Base(args[0]) != "pg_dump" {
			continue
		}
		if strings.Contains(string(data), "backup_test_") {
			inspected = true
			if strings.Contains(string(data), dsn) {
				t.Error("database credentials exposed in pg_dump argv")
			}
		}
	}
	if !inspected {
		t.Error("pg_dump process was not observed")
	}
	if err = gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDefaultRestoreCapturesCommittedDeletionAfterMaintenanceWait(t *testing.T) {
	p, dsn := safetyDB(t)
	ctx := context.Background()
	execSQL(t, p, "UPDATE users SET deleted_at=NULL")
	path, err := createBackupWithManifest(dsn, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	deleted := make(chan error, 1)
	mutated := make(chan struct{})
	release := make(chan struct{})
	go func() {
		deleted <- repository.NewTransactor(p).WithTransaction(ctx, func(txCtx context.Context) error {
			if err := repository.NewUserRepository(p).SoftDelete(txCtx, uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")); err != nil {
				return err
			}
			close(mutated)
			<-release
			return nil
		})
	}()
	select {
	case <-mutated:
	case err := <-deleted:
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	run := confirmedRestore(t, dsn, path, false)
	restored := make(chan error, 1)
	go func() { restored <- run() }()
	waitBackupQuery(t, p, "pg_advisory_lock", restored)
	close(release)
	released = true
	if err = <-deleted; err != nil {
		t.Fatal(err)
	}
	if err = <-restored; err != nil {
		t.Fatal(err)
	}
	var remains bool
	if err = p.QueryRow(ctx, "SELECT deleted_at IS NOT NULL AND session_version>0 FROM users").Scan(&remains); err != nil {
		t.Fatal(err)
	}
	if !remains {
		t.Fatal("restore did not capture deletion committed before exclusive lock")
	}
}

func TestFailedRestoreReleasesMaintenance(t *testing.T) {
	p, dsn := safetyDB(t)
	path := gzipSQL(t, "SELECT missing_column FROM users;")
	if err := confirmedRestore(t, dsn, path, true)(); err == nil {
		t.Fatal("invalid SQL must fail")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := repository.NewUserRepository(p).SoftDelete(ctx, uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")); err != nil {
		t.Fatalf("failed restore leaked maintenance lock: %v", err)
	}
}

func TestBackupWaitsForRestoreBeforeOpeningSnapshot(t *testing.T) {
	p, dsn := safetyDB(t)
	ctx := context.Background()
	gate, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Release()
	if _, err = gate.Exec(ctx, "SELECT pg_advisory_lock($1)", maintenanceTestKey); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = gate.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", maintenanceTestKey) }()
	dir := t.TempDir()
	done := make(chan error, 1)
	var path string
	go func() { var err error; path, err = createBackupWithManifest(dsn, dir); done <- err }()
	waitBackupQuery(t, p, "pg_advisory_lock_shared", done)
	execSQL(t, p, "UPDATE users SET deleted_at=NULL")
	if _, err = gate.Exec(ctx, "SELECT pg_advisory_unlock($1)", maintenanceTestKey); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	m, err := loadManifestFile(strings.TrimSuffix(path, ".sql.gz") + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.DeletedUsers) != 0 {
		t.Fatal("backup opened stale snapshot before maintenance finished")
	}
	if err = restoreBackup(dsn, path, nil); err != nil {
		t.Fatal(err)
	}
	var active bool
	if err = p.QueryRow(ctx, "SELECT deleted_at IS NULL FROM users").Scan(&active); err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("dump snapshot predates maintenance completion")
	}
}

func TestBackupSidecarFailurePublishesNoDump(t *testing.T) {
	p, dsn := safetyDB(t)
	ctx := context.Background()
	execSQL(t, p, "CREATE TABLE backup_gate(value text)")
	gate, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Rollback(context.Background()) }()
	if _, err = gate.Exec(ctx, "LOCK TABLE backup_gate IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	done := make(chan error, 1)
	go func() { _, err := createBackupWithManifest(dsn, dir); done <- err }()
	waitBackupQuery(t, p, "LOCK TABLE", done)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".sql.gz.partial") {
		t.Fatalf("in-progress dump must use a temporary name: %v", entries)
	}
	sidecar := filepath.Join(dir, strings.TrimSuffix(entries[0].Name(), ".sql.gz.partial")+".manifest.json.partial")
	if err = os.Mkdir(sidecar, 0700); err != nil {
		t.Fatal(err)
	}
	if err = gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("sidecar write failure must fail backup")
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed sidecar left published or partial artifacts: %v", entries)
	}
}
