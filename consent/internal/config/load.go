package config

import (
	"fmt"
	"os"
	"strings"
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
		Core: CoreConfig{
			AdminAddr: "127.0.0.1:4446",
		},
		Identity: IdentityConfig{
			Addr: "127.0.0.1:4456",
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
	if v := os.Getenv("CONSENT_CSRF_SECRET"); v != "" {
		cfg.CSRF.Secret = v
	}
	if v := os.Getenv("CONSENT_CORE_ADMIN_ADDR"); v != "" {
		cfg.Core.AdminAddr = v
	}
	if v := os.Getenv("CONSENT_CORE_ADMIN_TOKEN"); v != "" {
		cfg.Core.AdminToken = v
	}
	if v := os.Getenv("CONSENT_CORE_ADMIN_TLS_CA_FILE"); v != "" {
		cfg.Core.AdminTLSCAFile = v
	}
	if v := os.Getenv("CONSENT_IDENTITY_ADDR"); v != "" {
		cfg.Identity.Addr = v
	}
	if v := os.Getenv("CONSENT_PLUGINS_ENABLED"); v != "" {
		cfg.Plugins.Enabled = splitList(v)
	}
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func validate(cfg *Config) error {
	if cfg.Server.Addr == "" {
		return fmt.Errorf("server.addr is required (set yaml or CONSENT_ADDR)")
	}
	if cfg.Server.ShutdownTimeout <= 0 {
		return fmt.Errorf("server.shutdown_timeout must be positive")
	}
	if cfg.Core.AdminAddr == "" {
		return fmt.Errorf("core.admin_addr is required (set yaml or CONSENT_CORE_ADMIN_ADDR)")
	}
	if cfg.Core.AdminToken == "" {
		return fmt.Errorf("core.admin_token is required (set CONSENT_CORE_ADMIN_TOKEN)")
	}
	if len(cfg.Plugins.Enabled) == 0 {
		return fmt.Errorf("plugins.enabled must list at least one plugin (set yaml or CONSENT_PLUGINS_ENABLED)")
	}
	return nil
}
