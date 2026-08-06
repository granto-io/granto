package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DBTX is satisfied by *pgxpool.Pool and pgx.Tx.
type DBTX interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type txCtxKey struct{}

// DB wraps a connection pool and provides transaction-aware access for repositories.
type DB struct {
	pool *pgxpool.Pool
}

// New wraps a pool.
func New(pool *pgxpool.Pool) *DB {
	return &DB{pool: pool}
}

// Pool returns the underlying connection pool.
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}

// Close closes the underlying pool.
func (db *DB) Close() {
	db.pool.Close()
}

// Conn returns the transaction from ctx when present, otherwise the pool.
func (db *DB) Conn(ctx context.Context) DBTX {
	if tx, ok := ctx.Value(txCtxKey{}).(pgx.Tx); ok {
		return tx
	}
	return db.pool
}

// WithinTx runs fn inside a SQL transaction. Nested calls that use Conn(ctx)
// with the derived context join the same transaction.
func (db *DB) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		return fn(context.WithValue(ctx, txCtxKey{}, tx))
	})
}
