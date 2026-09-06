// Package testutil provides isolated PostgreSQL fixtures for integration tests.
package testutil

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Database creates an isolated schema and applies migrations through version.
// A zero version applies every migration.
func Database(t *testing.T, version int) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required for PostgreSQL integration tests")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "integrity_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	Exec(t, admin, "CREATE SCHEMA "+schema)
	t.Cleanup(func() { _, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); admin.Close() })
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.RuntimeParams["application_name"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	paths, err := filepath.Glob(filepath.Join(MigrationDir(), "*.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		v, err := strconv.Atoi(strings.SplitN(filepath.Base(p), "_", 2)[0])
		if err != nil {
			t.Fatal(err)
		}
		if version > 0 && v > version {
			continue
		}
		sql, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		Exec(t, pool, string(sql))
	}
	return pool
}

func MigrationDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}

func Exec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}
