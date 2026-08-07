package postgres

import (
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/granto-io/granto/core/migrations"
)

// Migrate applies all pending SQL migrations. Safe to call on every startup.
func Migrate(dsn string) (err error) {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, toPgx5DSN(dsn))
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer func() {
		srcErr, dbErr := m.Close()
		if err != nil {
			return
		}
		if srcErr != nil {
			err = fmt.Errorf("close migration source: %w", srcErr)
			return
		}
		if dbErr != nil {
			err = fmt.Errorf("close migration database: %w", dbErr)
		}
	}()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

func toPgx5DSN(dsn string) string {
	dsn = strings.Replace(dsn, "postgresql://", "pgx5://", 1)
	return strings.Replace(dsn, "postgres://", "pgx5://", 1)
}
