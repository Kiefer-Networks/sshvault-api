package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

func updateUserSessions(ctx context.Context, userID uuid.UUID, state string) (int64, error) {
	query := `UPDATE users SET session_version=session_version+1,updated_at=now()`
	switch state {
	case "logout":
	case "deactivate":
		query += `,deleted_at=now()`
	case "activate":
		query += `,deleted_at=NULL`
	default:
		return 0, fmt.Errorf("invalid session action: %s", state)
	}
	query += ` WHERE id=$1`
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := repository.LockAccountMutation(ctx, tx); err != nil {
		return 0, err
	}
	result, err := tx.Exec(ctx, query, userID)
	if err != nil {
		return 0, err
	}
	if result.RowsAffected() != 1 {
		return 0, fmt.Errorf("user not found")
	}
	result, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked=TRUE WHERE user_id=$1 AND NOT revoked`, userID)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
