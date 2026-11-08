package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Load builds the effective config:
//  1. built-in defaults
//  2. optional YAML file (missing keys keep defaults)
//  3. CONSENT_* environment overrides
//  4. validation of required fields
//
// path may be empty: then only defaults + env are used.
func Load(path string) (*Config, error) {
	cfg := defaults()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config file: %w", err)
		}
	}

	overrideFromEnv(cfg)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Addr:            ":4455",
			ShutdownTimeout: 30 * time.Second,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

func overrideFromEnv(cfg *Config) {
	if v := os.Getenv("CONSENT_ADDR"); v != "" {
		cfg.Server.Addr = v
	}
	if v := os.Getenv("CONSENT_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("CONSENT_LOG_FORMAT"); v != "" {
		cfg.Log.Format = v
	}
}

func validate(cfg *Config) error {
	if cfg.Server.Addr == "" {
		return fmt.Errorf("server.addr is required (set yaml or CONSENT_ADDR)")
	}
	if cfg.Server.ShutdownTimeout <= 0 {
		return fmt.Errorf("server.shutdown_timeout must be positive")
	}
	return nil
}
