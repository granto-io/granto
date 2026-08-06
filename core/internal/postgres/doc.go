// Package postgres will hold the PostgreSQL pool, migration runner, and
// repository implementations for granto-core.
//
// Blank imports keep pgx and golang-migrate in go.mod until the real wiring
// lands in a following step.
package postgres

import (
	_ "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/pgxpool"
)
