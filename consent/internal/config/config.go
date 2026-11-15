// Package config loads granto-consent settings: defaults → optional YAML → env overrides.
package config

import (
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration for granto-consent.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	CSRF     CSRFConfig     `yaml:"csrf"`
	Core     CoreConfig     `yaml:"core"`
	Identity IdentityConfig `yaml:"identity"`
	Plugins  PluginsConfig  `yaml:"plugins"`
	Log      LogConfig      `yaml:"log"`
}

// ServerConfig holds the listen address and process lifecycle settings.
type ServerConfig struct {
	Addr            string        `yaml:"addr"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// CSRFConfig holds the secret used to bind CSRF tokens to challenge ids.
//
// An empty secret makes the process generate a random one at startup:
// fine for a single instance, but every replica would reject tokens issued
// by another. Set a shared secret (env only) when running more than one.
type CSRFConfig struct {
	Secret string `yaml:"secret"`
}

// CoreConfig points consent at the core Admin gRPC API.
//
// AdminToken must come from the environment or a secret file, never from a
// committed YAML file.
type CoreConfig struct {
	AdminAddr string `yaml:"admin_addr"`
	// AdminToken is the bearer token for the core Admin API.
	AdminToken string `yaml:"admin_token"`
	// AdminTLSCAFile optionally pins a private CA for the Admin gRPC TLS
	// connection. Ignored for plain-text loopback addresses.
	AdminTLSCAFile string `yaml:"admin_tls_ca_file"`
}

// IdentityConfig points consent at the identity service gRPC API.
//
// The identity service implements the public IdentityService contract
// (identity/api/identity/v1). Only loopback addresses are supported for now.
type IdentityConfig struct {
	Addr string `yaml:"addr"`
}

// PluginsConfig selects which registered plugins run and carries their
// per-plugin configuration.
type PluginsConfig struct {
	// Enabled lists registered plugin names, in display order.
	Enabled []string `yaml:"enabled"`
	// Config holds per-plugin settings passed to Plugin.Init via Host.Config.
	Config map[string]yaml.Node `yaml:"config"`
}

// LogConfig controls the process logger.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}
