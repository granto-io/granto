package di

import (
	"context"
	"fmt"

	"github.com/google/wire"

	"github.com/granto-io/granto/core/internal/config"
	intredis "github.com/granto-io/granto/core/internal/redis"
	"github.com/granto-io/granto/core/internal/repository"
	reporredis "github.com/granto-io/granto/core/internal/repository/redis"
)

// RedisSet provides Redis client and redis-backed repositories.
// Requires *config.Config from ConfigSet.
var RedisSet = wire.NewSet(
	provideRedis,
	reporredis.NewLoginChallengeRepository,
	wire.Bind(new(repository.LoginChallengeRepository), new(*reporredis.LoginChallengeRepository)),
)

func provideRedis(cfg *config.Config) (*intredis.Client, error) {
	client, err := intredis.NewClient(context.Background(), cfg.Redis)
	if err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}
	return client, nil
}
