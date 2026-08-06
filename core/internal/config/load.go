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
//  3. GRANTO_* environment overrides (secrets and deploy knobs)
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
			PublicAddr:      ":4444",
			AdminRESTAddr:   ":4445",
			AdminGRPCAddr:   ":4446",
			MetricsAddr:     ":4447",
			ShutdownTimeout: 30 * time.Second,
		},
		Postgres: PostgresConfig{
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
			MigrateOnStart:  true,
		},
		Redis: RedisConfig{
			Addr:     "localhost:6379",
			PoolSize: 10,
		},
		Token: TokenConfig{
			DefaultAlgorithm: "RS256",
			AccessTokenTTL:   1 * time.Hour,
			RefreshTokenTTL:  720 * time.Hour,
			IDTokenTTL:       1 * time.Hour,
		},
		Session: SessionConfig{
			DefaultTTL: 24 * time.Hour,
			MaxTTL:     720 * time.Hour,
		},
		CORS: CORSConfig{
			Enabled:        false,
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"Authorization", "Content-Type"},
			MaxAge:         300,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
		Telemetry: TelemetryConfig{
			ServiceName: "granto-core",
			SampleRate:  1.0,
		},
	}
}

func overrideFromEnv(cfg *Config) {
	if v := os.Getenv("GRANTO_PUBLIC_ADDR"); v != "" {
		cfg.Server.PublicAddr = v
	}
	if v := os.Getenv("GRANTO_ADMIN_REST_ADDR"); v != "" {
		cfg.Server.AdminRESTAddr = v
	}
	if v := os.Getenv("GRANTO_ADMIN_GRPC_ADDR"); v != "" {
		cfg.Server.AdminGRPCAddr = v
	}
	if v := os.Getenv("GRANTO_METRICS_ADDR"); v != "" {
		cfg.Server.MetricsAddr = v
	}
	if v := os.Getenv("GRANTO_POSTGRES_DSN"); v != "" {
		cfg.Postgres.DSN = v
	}
	if v := os.Getenv("GRANTO_REDIS_ADDR"); v != "" {
		cfg.Redis.Addr = v
	}
	if v := os.Getenv("GRANTO_REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("GRANTO_ISSUER"); v != "" {
		cfg.Token.Issuer = v
	}
	if v := os.Getenv("GRANTO_MASTER_KEY"); v != "" {
		cfg.Token.MasterKey = v
	}
	if v := os.Getenv("GRANTO_LOGIN_URL"); v != "" {
		cfg.OAuth2.LoginURL = v
	}
	if v := os.Getenv("GRANTO_CONSENT_URL"); v != "" {
		cfg.OAuth2.ConsentURL = v
	}
	if v := os.Getenv("GRANTO_LOGOUT_URL"); v != "" {
		cfg.OAuth2.LogoutURL = v
	}
	if v := os.Getenv("GRANTO_ADMIN_TOKEN"); v != "" {
		cfg.Admin.Token = v
	}
	if v := os.Getenv("GRANTO_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("GRANTO_LOG_FORMAT"); v != "" {
		cfg.Log.Format = v
	}
	if v := os.Getenv("GRANTO_CORS_ENABLED"); v != "" {
		cfg.CORS.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("GRANTO_CORS_ORIGINS"); v != "" {
		cfg.CORS.AllowedOrigins = splitComma(v)
	}
}

func splitComma(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func validate(cfg *Config) error {
	if cfg.Token.Issuer == "" {
		return fmt.Errorf("token.issuer is required (set yaml or GRANTO_ISSUER)")
	}
	if cfg.Token.MasterKey == "" {
		return fmt.Errorf("token.master_key is required (set yaml or GRANTO_MASTER_KEY)")
	}
	if len(cfg.Token.MasterKey) < 32 {
		return fmt.Errorf("token.master_key must be at least 32 characters")
	}
	if cfg.Postgres.DSN == "" {
		return fmt.Errorf("postgres.dsn is required (set yaml or GRANTO_POSTGRES_DSN)")
	}
	if cfg.Admin.Token == "" {
		return fmt.Errorf("admin.token is required (set yaml or GRANTO_ADMIN_TOKEN)")
	}
	if cfg.OAuth2.LoginURL == "" {
		return fmt.Errorf("oauth2.login_url is required (set yaml or GRANTO_LOGIN_URL)")
	}
	return nil
}
