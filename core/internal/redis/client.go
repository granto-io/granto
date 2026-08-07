package redis

import (
	"context"
	"fmt"

	goredis "github.com/redis/go-redis/v9"

	"github.com/granto-io/granto/core/internal/config"
)

// Client wraps a go-redis client for DI and lifecycle (Close on shutdown).
type Client struct {
	rdb *goredis.Client
}

// NewClient creates and pings a Redis client from config (standalone or Sentinel).
func NewClient(ctx context.Context, cfg config.RedisConfig) (*Client, error) {
	var rdb *goredis.Client
	if len(cfg.SentinelAddrs) > 0 {
		rdb = goredis.NewFailoverClient(&goredis.FailoverOptions{
			MasterName:    cfg.SentinelMaster,
			SentinelAddrs: cfg.SentinelAddrs,
			Password:      cfg.Password,
			DB:            cfg.DB,
			PoolSize:      cfg.PoolSize,
		})
	} else {
		rdb = goredis.NewClient(&goredis.Options{
			Addr:     cfg.Addr,
			Password: cfg.Password,
			DB:       cfg.DB,
			PoolSize: cfg.PoolSize,
		})
	}

	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return &Client{rdb: rdb}, nil
}

// RDB returns the underlying go-redis client for repositories.
func (c *Client) RDB() *goredis.Client {
	return c.rdb
}

// Close closes the underlying connection pool.
func (c *Client) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}
