package di

import (
	"context"
	"fmt"

	"github.com/google/wire"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/postgres"
	"github.com/granto-io/granto/core/internal/repository"
	repopg "github.com/granto-io/granto/core/internal/repository/postgres"
)

// PostgresSet provides DB (pool + optional migrate) and postgres-backed repositories.
// Requires *config.Config from ConfigSet.
var PostgresSet = wire.NewSet(
	provideDB,
	repopg.NewClientRepository,
	wire.Bind(new(repository.ClientRepository), new(*repopg.ClientRepository)),
	repopg.NewLoginSessionRepository,
	wire.Bind(new(repository.LoginSessionRepository), new(*repopg.LoginSessionRepository)),
	repopg.NewConsentGrantRepository,
	wire.Bind(new(repository.ConsentGrantRepository), new(*repopg.ConsentGrantRepository)),
)

func provideDB(cfg *config.Config) (*postgres.DB, error) {
	if cfg.Postgres.MigrateOnStart {
		if err := postgres.Migrate(cfg.Postgres.DSN); err != nil {
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}

	pool, err := postgres.NewPool(context.Background(), cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("postgres pool: %w", err)
	}
	return postgres.New(pool), nil
}
