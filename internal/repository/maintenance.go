package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maintenanceLockKey int64 = 734862190201

// LockAccountMutation must precede all table and user-row locks. Transaction
// scope releases the shared lock on both commit and rollback.
func LockAccountMutation(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared($1)", maintenanceLockKey)
	if err != nil {
		return fmt.Errorf("locking account maintenance: %w", err)
	}
	return nil
}

// WithExclusiveMaintenance uses a dedicated session without an open transaction:
// pg_dump/psql use other sessions and must be able to acquire table locks. Closing
// this connection (never returning a locked session to the pool) releases the lock
// even after cancellation or an error in fn.
func WithExclusiveMaintenance(ctx context.Context, p *pgxpool.Pool, fn func(*pgx.Conn) error) error {
	return withMaintenanceSession(ctx, p, "SELECT pg_advisory_lock($1)", fn)
}

// WithSharedMaintenance permits account changes and other backups, while
// excluding restore. Acquire it before starting the backup snapshot transaction.
func WithSharedMaintenance(ctx context.Context, p *pgxpool.Pool, fn func(*pgx.Conn) error) error {
	return withMaintenanceSession(ctx, p, "SELECT pg_advisory_lock_shared($1)", fn)
}

func withMaintenanceSession(ctx context.Context, p *pgxpool.Pool, query string, fn func(*pgx.Conn) error) error {
	connection, err := pgx.ConnectConfig(ctx, p.Config().ConnConfig.Copy())
	if err != nil {
		return fmt.Errorf("opening maintenance connection: %w", err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	if _, err := connection.Exec(ctx, query, maintenanceLockKey); err != nil {
		return fmt.Errorf("locking maintenance: %w", err)
	}
	return fn(connection)
}
