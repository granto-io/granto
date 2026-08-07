package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/granto-io/granto/core/internal/config"
)

func TestLoad_YAMLMergesDefaultsAndEnvWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
server:
  public_addr: ":9999"
log:
  level: warn
token:
  issuer: https://auth.example.com
  master_key: "01234567890123456789012345678901"
postgres:
  dsn: postgres://from-yaml/db
oauth2:
  login_url: https://app.example.com/login
admin:
  token: yaml-admin-token
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	t.Setenv("GRANTO_POSTGRES_DSN", "postgres://from-env/db")
	t.Setenv("GRANTO_LOG_LEVEL", "debug")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load(%q) unexpected error: %v", path, err)
	}

	if cfg.Server.PublicAddr != ":9999" {
		t.Fatalf("Server.PublicAddr = %q, want %q (from YAML)", cfg.Server.PublicAddr, ":9999")
	}
	if cfg.Server.AdminRESTAddr != ":4445" {
		t.Fatalf("Server.AdminRESTAddr = %q, want default %q", cfg.Server.AdminRESTAddr, ":4445")
	}
	if cfg.Server.ShutdownTimeout != 30*time.Second {
		t.Fatalf("Server.ShutdownTimeout = %v, want default %v", cfg.Server.ShutdownTimeout, 30*time.Second)
	}
	if cfg.Postgres.DSN != "postgres://from-env/db" {
		t.Fatalf("Postgres.DSN = %q, want env override %q", cfg.Postgres.DSN, "postgres://from-env/db")
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("Log.Level = %q, want env override %q", cfg.Log.Level, "debug")
	}
	if cfg.Token.AccessTokenTTL != time.Hour {
		t.Fatalf("Token.AccessTokenTTL = %v, want default %v", cfg.Token.AccessTokenTTL, time.Hour)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	_, err := config.Load("")
	if err == nil {
		t.Fatalf("Load(\"\") = nil error, want validation error for missing required fields")
	}
	if !strings.Contains(err.Error(), "invalid config") {
		t.Fatalf("Load(\"\") error = %q, want it to mention %q", err.Error(), "invalid config")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.yaml")
	_, err := config.Load(path)
	if err == nil {
		t.Fatalf("Load(%q) = nil error, want read error for missing file", path)
	}
	if !strings.Contains(err.Error(), "read config file") {
		t.Fatalf("Load missing file error = %q, want substring %q", err.Error(), "read config file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte(":\n  -"), 0o600); err != nil {
		t.Fatalf("write bad yaml fixture: %v", err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatalf("Load(%q) = nil error, want YAML parse error", path)
	}
	if !strings.Contains(err.Error(), "parse config file") {
		t.Fatalf("Load invalid YAML error = %q, want substring %q", err.Error(), "parse config file")
	}
}

func TestLoad_EnvCORSAndOIDCDCR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `
token:
  issuer: https://auth.example.com
  master_key: "01234567890123456789012345678901"
postgres:
  dsn: postgres://db
oauth2:
  login_url: https://app.example.com/login
admin:
  token: admin-token
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	t.Setenv("GRANTO_CORS_ENABLED", "1")
	t.Setenv("GRANTO_CORS_ORIGINS", "https://a.com, https://b.com")
	t.Setenv("GRANTO_OIDC_DCR_ENABLED", "true")
	t.Setenv("GRANTO_OIDC_DCR_DEFAULT_SCOPES", "openid, profile")
	t.Setenv("GRANTO_ISSUER", "https://from-env")
	t.Setenv("GRANTO_LOGIN_URL", "https://login-from-env")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load unexpected error: %v", err)
	}
	if !cfg.CORS.Enabled {
		t.Fatalf("CORS.Enabled = false, want true from GRANTO_CORS_ENABLED=1")
	}
	if len(cfg.CORS.AllowedOrigins) != 2 {
		t.Fatalf("CORS.AllowedOrigins len = %d (%#v), want 2", len(cfg.CORS.AllowedOrigins), cfg.CORS.AllowedOrigins)
	}
	if cfg.CORS.AllowedOrigins[1] != "https://b.com" {
		t.Fatalf("CORS.AllowedOrigins[1] = %q, want %q", cfg.CORS.AllowedOrigins[1], "https://b.com")
	}
	if !cfg.OIDC.DynamicClientRegistration.Enabled {
		t.Fatalf("OIDC.DynamicClientRegistration.Enabled = false, want true from GRANTO_OIDC_DCR_ENABLED")
	}
	if len(cfg.OIDC.DynamicClientRegistration.DefaultScopes) != 2 {
		t.Fatalf("DCR DefaultScopes = %#v, want 2 scopes", cfg.OIDC.DynamicClientRegistration.DefaultScopes)
	}
	if cfg.Token.Issuer != "https://from-env" {
		t.Fatalf("Token.Issuer = %q, want env override %q", cfg.Token.Issuer, "https://from-env")
	}
	if cfg.OAuth2.LoginURL != "https://login-from-env" {
		t.Fatalf("OAuth2.LoginURL = %q, want env override %q", cfg.OAuth2.LoginURL, "https://login-from-env")
	}
}

func TestLoad_MasterKeyTooShort(t *testing.T) {
	t.Setenv("GRANTO_ISSUER", "https://issuer")
	t.Setenv("GRANTO_MASTER_KEY", "too-short")
	t.Setenv("GRANTO_POSTGRES_DSN", "postgres://db")
	t.Setenv("GRANTO_ADMIN_TOKEN", "admin")
	t.Setenv("GRANTO_LOGIN_URL", "https://login")

	_, err := config.Load("")
	if err == nil {
		t.Fatalf("Load with short master_key = nil error, want validation error")
	}
	if !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("error = %q, want substring %q", err.Error(), "at least 32")
	}
}
