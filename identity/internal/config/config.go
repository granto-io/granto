// Package config loads granto-identity settings: defaults → optional YAML → env overrides.
package config

import (
	"time"
)

// Config is the root configuration for granto-identity.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Postgres PostgresConfig `yaml:"postgres"`
	Log      LogConfig      `yaml:"log"`
}

// ServerConfig holds listen addresses and process lifecycle settings.
type ServerConfig struct {
	// GRPCAddr is the gRPC listen address for IdentityService.
	GRPCAddr string `yaml:"grpc_addr"`
	// RESTAddr is the grpc-gateway HTTP/JSON listen address.
	RESTAddr string `yaml:"rest_addr"`
	// ShutdownTimeout is the graceful shutdown budget.
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// PostgresConfig holds PostgreSQL pool and migration settings.
type PostgresConfig struct {
	DSN             string        `yaml:"dsn"`
	MaxOpenConns    int           `yaml:"max_open"`
	MaxIdleConns    int           `yaml:"max_idle"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
	MigrateOnStart  bool          `yaml:"migrate_on_start"`
}

// LogConfig controls the process logger.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // json | text
}
