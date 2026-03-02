package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the common interface satisfied by both *pgxpool.Pool and pgx.Tx.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type ctxTxKey struct{}

// Transactor provides database transaction support across repositories.
type Transactor struct {
	pool *pgxpool.Pool
}

// NewTransactor creates a new Transactor backed by the given connection pool.
func NewTransactor(pool *pgxpool.Pool) *Transactor {
	return &Transactor{pool: pool}
}

// WithTransaction executes fn within a database transaction. If fn returns
// an error the transaction is rolled back; otherwise it is committed.
func (t *Transactor) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	tx, err := t.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	txCtx := context.WithValue(ctx, ctxTxKey{}, tx)
	if err := fn(txCtx); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// conn returns the transaction from context if present, otherwise the pool.
func conn(ctx context.Context, pool *pgxpool.Pool) Querier {
	if tx, ok := ctx.Value(ctxTxKey{}).(pgx.Tx); ok {
		return tx
	}
	return pool
}
