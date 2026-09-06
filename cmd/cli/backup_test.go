package main

import (
	"compress/gzip"
	"context"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func backupTestDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is required for PostgreSQL integration tests")
	}
	for _, name := range []string{"pg_dump", "psql"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	name := "backup_test_" + uuid.New().String()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		_, _ = admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		_ = admin.Close(ctx)
	})
	dsn := &url.URL{Scheme: "postgresql", User: url.UserPassword(cfg.ConnConfig.User, cfg.ConnConfig.Password), Host: net.JoinHostPort(cfg.ConnConfig.Host, strconv.Itoa(int(cfg.ConnConfig.Port))), Path: "/" + name, RawQuery: "sslmode=disable"}
	return p, dsn.String()
}

func execSQL(t *testing.T, p *pgxpool.Pool, sql string) {
	t.Helper()
	if _, err := p.Exec(context.Background(), sql); err != nil {
		t.Fatal(err)
	}
}
func gzipSQL(t *testing.T, sql string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sql.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	if _, err = z.Write([]byte(sql)); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
func value(t *testing.T, p *pgxpool.Pool) string {
	t.Helper()
	var v string
	if err := p.QueryRow(context.Background(), "SELECT value FROM sample").Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}
func TestBackupRestoreExistingDatabase(t *testing.T) {
	p, url := backupTestDB(t)
	execSQL(t, p, "CREATE TABLE sample(value text); INSERT INTO sample VALUES ('saved'); CREATE TABLE refresh_tokens(revoked boolean); INSERT INTO refresh_tokens VALUES(false)")
	path, err := createBackup(url, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	execSQL(t, p, "UPDATE sample SET value='newer'")
	if err := restoreBackup(url, path, nil); err != nil {
		t.Fatal(err)
	}
	if got := value(t, p); got != "saved" {
		t.Fatalf("restored %q, want saved", got)
	}
}
func TestRestoreSQLFailureRollsBack(t *testing.T) {
	p, url := backupTestDB(t)
	execSQL(t, p, "CREATE TABLE sample(value text); INSERT INTO sample VALUES ('original')")
	path := gzipSQL(t, "UPDATE sample SET value='partial'; SELECT nonexistent_column FROM sample;")
	if err := restoreBackup(url, path, nil); err == nil {
		t.Error("restore must fail on SQL error")
	}
	if got := value(t, p); got != "original" {
		t.Fatalf("failed restore changed data to %q", got)
	}
}
func TestCorruptGzipDoesNotModifyDatabase(t *testing.T) {
	p, url := backupTestDB(t)
	execSQL(t, p, "CREATE TABLE sample(value text); INSERT INTO sample VALUES ('original')")
	path := gzipSQL(t, "UPDATE sample SET value='partial';")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-8] ^= 0xff
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackup(url, path, nil); err == nil {
		t.Error("restore must reject invalid checksum")
	}
	if got := value(t, p); got != "original" {
		t.Fatalf("corrupt restore changed data to %q", got)
	}
}

func TestRestoreReconciliationIsAtomic(t *testing.T) {
	p, url := backupTestDB(t)
	execSQL(t, p, `CREATE TABLE users(id uuid, deleted_at timestamptz, updated_at timestamptz, session_version bigint NOT NULL DEFAULT 0); CREATE TABLE refresh_tokens(revoked boolean); CREATE TABLE verification_tokens(used boolean); INSERT INTO users(id) VALUES('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'); INSERT INTO refresh_tokens VALUES(false); INSERT INTO verification_tokens VALUES(false)`)
	path, err := createBackup(url, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := &restoreManifest{DeletedUsers: []manifestUser{{ID: uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), DeletedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}}}
	if err := restoreBackup(url, path, m); err != nil {
		t.Fatal(err)
	}
	var deleted, revoked, used bool
	var version int64
	if err := p.QueryRow(context.Background(), "SELECT deleted_at IS NOT NULL, session_version FROM users").Scan(&deleted, &version); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(context.Background(), "SELECT revoked FROM refresh_tokens").Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(context.Background(), "SELECT used FROM verification_tokens").Scan(&used); err != nil {
		t.Fatal(err)
	}
	if !deleted || !revoked || !used || version == 0 {
		t.Fatalf("unsafe restored state: deleted=%v revoked=%v used=%v version=%d", deleted, revoked, used, version)
	}
	// An incompatible backup must not commit even the SQL preceding reconciliation.
	execSQL(t, p, "CREATE TABLE sample(value text); INSERT INTO sample VALUES('original')")
	broken := gzipSQL(t, "UPDATE sample SET value='partial'; DROP TABLE refresh_tokens;")
	if err := restoreBackup(url, broken, m); err == nil {
		t.Fatal("reconciliation failure must abort restore")
	}
	if got := value(t, p); got != "original" {
		t.Fatalf("reconciliation failure committed %q", got)
	}
}
func TestRestorePreSessionVersionBackup(t *testing.T) {
	p, url := backupTestDB(t)
	execSQL(t, p, "CREATE TABLE users(id uuid, deleted_at timestamptz, updated_at timestamptz); CREATE TABLE refresh_tokens(revoked boolean); CREATE TABLE verification_tokens(used boolean); INSERT INTO users(id) VALUES('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')")
	path, err := createBackup(url, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreBackup(url, path, &restoreManifest{}); err != nil {
		t.Fatal(err)
	}
	var version int64
	if err := p.QueryRow(context.Background(), "SELECT session_version FROM users").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version == 0 {
		t.Fatal("old schema restore must invalidate access sessions")
	}
}
func TestLoadManifestRejectsMissingSafetyData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.manifest.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManifestFile(path); err == nil {
		t.Fatal("empty manifest must fail validation")
	}
}
func TestBackupPreservesLargeDump(t *testing.T) {
	p, url := backupTestDB(t)
	execSQL(t, p, "CREATE TABLE payload AS SELECT n, repeat(md5(n::text), 64) AS data FROM generate_series(1,3000) n")
	path, err := createBackup(url, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	execSQL(t, p, "DELETE FROM payload")
	if err := restoreBackup(url, path, nil); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := p.QueryRow(context.Background(), "SELECT COUNT(*) FROM payload WHERE data = repeat(md5(n::text),64)").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 3000 {
		t.Fatalf("restored %d intact rows, want 3000", rows)
	}
}
func TestBackupFailsWhenManifestCannotBeCaptured(t *testing.T) {
	p, url := backupTestDB(t)
	oldPool := pool
	pool = p
	t.Cleanup(func() { pool = oldPool })
	dir := t.TempDir()
	if _, err := createBackupWithManifest(url, dir); err == nil {
		t.Fatal("missing users table must fail backup")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("failed manifest left a backup advertised as usable")
	}
}
func createBackup(databaseURL, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	staged, err := dumpBackup(ctx, databaseURL, dir, "")
	if err != nil {
		return "", err
	}
	final := strings.TrimSuffix(staged, ".partial")
	if err := os.Rename(staged, final); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	return final, nil
}

// Validate the complete compressed stream before opening a database transaction.
// Staging on disk also prevents decompression errors from committing partial SQL.
func restoreBackup(databaseURL, file string, manifest *restoreManifest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return restoreBackupContext(ctx, databaseURL, file, manifest)
}

func TestBackupRestoreKeywordConnectionString(t *testing.T) {
	p, dsn := backupTestDB(t)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string {
		return "'" + strings.ReplaceAll(strings.ReplaceAll(s, "\\", "\\\\"), "'", "\\'") + "'"
	}
	keyword := "host=" + quote(cfg.Host) + " port=" + strconv.Itoa(int(cfg.Port)) + " user=" + quote(cfg.User) + " password=" + quote(cfg.Password) + " dbname=" + quote(cfg.Database) + " sslmode=disable"
	execSQL(t, p, "CREATE TABLE sample(value text); INSERT INTO sample VALUES('saved')")
	path, err := createBackup(keyword, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	execSQL(t, p, "UPDATE sample SET value='changed'")
	if err = restoreBackup(keyword, path, nil); err != nil {
		t.Fatal(err)
	}
	if got := value(t, p); got != "saved" {
		t.Fatalf("keyword-DSN restore returned %q", got)
	}
}

func TestBackupRestoreURIPercentEncodedOptions(t *testing.T) {
	p, dsn := backupTestDB(t)
	dsn += "&options=-c%20statement_timeout%3D5000"
	execSQL(t, p, "CREATE TABLE sample(value text); INSERT INTO sample VALUES('saved')")
	path, err := createBackup(dsn, t.TempDir())
	if err != nil {
		t.Fatalf("valid percent-encoded libpq option prevented backup: %v", err)
	}
	execSQL(t, p, "UPDATE sample SET value='changed'")
	if err = restoreBackup(dsn, path, nil); err != nil {
		t.Fatalf("valid percent-encoded libpq option prevented restore: %v", err)
	}
	if got := value(t, p); got != "saved" {
		t.Fatalf("restored %q instead of saved", got)
	}
}
