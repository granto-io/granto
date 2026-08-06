package di

import (
	"context"
	"fmt"
	"os"

	"github.com/google/wire"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/postgres"
	"github.com/granto-io/granto/core/internal/repository"
	repopg "github.com/granto-io/granto/core/internal/repository/postgres"
)

// PostgresSet provides config, DB (pool + migrations), and postgres-backed repositories.
var PostgresSet = wire.NewSet(
	provideConfig,
	provideDB,
	repopg.NewClientRepository,
	wire.Bind(new(repository.ClientRepository), new(*repopg.ClientRepository)),
)

func provideConfig() (*config.Config, error) {
	path := os.Getenv("GRANTO_CONFIG")
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

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
