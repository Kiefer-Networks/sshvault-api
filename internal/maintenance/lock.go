// Package maintenance coordinates mutations with database backup and restore.
package maintenance

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const LockKey int64 = 734862190201

// LockAccountMutation must precede all table and user-row locks. Transaction
// scope releases the shared lock on both commit and rollback.
func LockAccountMutation(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared($1)", LockKey)
	if err != nil {
		return fmt.Errorf("locking account maintenance: %w", err)
	}
	return nil
}
