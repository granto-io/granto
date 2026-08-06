// Package config loads granto-core settings: defaults → optional YAML → env overrides.
package config

import "time"

// Config is the root configuration for granto-core.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Postgres  PostgresConfig  `yaml:"postgres"`
	Redis     RedisConfig     `yaml:"redis"`
	Token     TokenConfig     `yaml:"token"`
	Session   SessionConfig   `yaml:"session"`
	OAuth2    OAuth2Config    `yaml:"oauth2"`
	OIDC      OIDCConfig      `yaml:"oidc"`
	Admin     AdminConfig     `yaml:"admin"`
	CORS      CORSConfig      `yaml:"cors"`
	Log       LogConfig       `yaml:"log"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
}

// ServerConfig holds listen addresses and process lifecycle settings.
type ServerConfig struct {
	PublicAddr      string        `yaml:"public_addr"`
	AdminRESTAddr   string        `yaml:"admin_rest_addr"`
	AdminGRPCAddr   string        `yaml:"admin_grpc_addr"`
	MetricsAddr     string        `yaml:"metrics_addr"`
	TLSCertFile     string        `yaml:"tls_cert_file"`
	TLSKeyFile      string        `yaml:"tls_key_file"`
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

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	Addr           string   `yaml:"addr"`
	Password       string   `yaml:"password"`
	DB             int      `yaml:"db"`
	SentinelAddrs  []string `yaml:"sentinel_addrs"`
	SentinelMaster string   `yaml:"sentinel_master"`
	PoolSize       int      `yaml:"pool_size"`
}

// TokenConfig holds token issuance defaults and crypto material.
type TokenConfig struct {
	Issuer           string        `yaml:"issuer"`
	DefaultAlgorithm string        `yaml:"default_algorithm"`
	AccessTokenTTL   time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL  time.Duration `yaml:"refresh_token_ttl"`
	IDTokenTTL       time.Duration `yaml:"id_token_ttl"`
	// MasterKey encrypts signing material at rest. Prefer GRANTO_MASTER_KEY in production.
	MasterKey string `yaml:"master_key"`
}

// SessionConfig holds session TTL bounds.
type SessionConfig struct {
	DefaultTTL time.Duration `yaml:"default_ttl"`
	MaxTTL     time.Duration `yaml:"max_ttl"`
}

// OAuth2Config holds OAuth2 flow URLs (login/consent UI lives outside core).
type OAuth2Config struct {
	LoginURL   string `yaml:"login_url"`
	ConsentURL string `yaml:"consent_url"`
	LogoutURL  string `yaml:"logout_url"`
}

// OIDCConfig holds OIDC-specific knobs.
type OIDCConfig struct {
	ExtraScopes []string `yaml:"extra_scopes"`
}

// AdminConfig holds Admin API access settings (MVP: static bearer).
type AdminConfig struct {
	Token      string   `yaml:"token"`
	AllowedIPs []string `yaml:"allowed_ips"`
}

// CORSConfig holds Cross-Origin Resource Sharing settings.
//
// Enabled = false (default) — no CORS headers. Suitable for server-to-server
// and local curl/Postman.
type CORSConfig struct {
	Enabled        bool     `yaml:"enabled"`
	AllowedOrigins []string `yaml:"allowed_origins"`
	AllowedMethods []string `yaml:"allowed_methods"`
	AllowedHeaders []string `yaml:"allowed_headers"`
	MaxAge         int      `yaml:"max_age"`
}

// LogConfig holds slog-oriented logging settings.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // json | text
}

// TelemetryConfig holds OpenTelemetry settings.
type TelemetryConfig struct {
	Enabled     bool    `yaml:"enabled"`
	Endpoint    string  `yaml:"endpoint"` // empty → stdout exporter when enabled
	Insecure    bool    `yaml:"insecure"`
	ServiceName string  `yaml:"service_name"`
	SampleRate  float64 `yaml:"sample_rate"`
}
