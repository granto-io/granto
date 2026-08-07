package config_test

import (
	"os"
	"path/filepath"
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
		t.Fatal(err)
	}

	t.Setenv("GRANTO_POSTGRES_DSN", "postgres://from-env/db")
	t.Setenv("GRANTO_LOG_LEVEL", "debug")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.PublicAddr != ":9999" {
		t.Fatalf("public_addr: got %q", cfg.Server.PublicAddr)
	}
	if cfg.Server.AdminRESTAddr != ":4445" {
		t.Fatalf("admin_rest_addr default lost: got %q", cfg.Server.AdminRESTAddr)
	}
	if cfg.Server.ShutdownTimeout != 30*time.Second {
		t.Fatalf("shutdown_timeout default lost: got %v", cfg.Server.ShutdownTimeout)
	}
	if cfg.Postgres.DSN != "postgres://from-env/db" {
		t.Fatalf("env should win for DSN: got %q", cfg.Postgres.DSN)
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("env should win for log level: got %q", cfg.Log.Level)
	}
	if cfg.Token.AccessTokenTTL != time.Hour {
		t.Fatalf("token TTL default lost: got %v", cfg.Token.AccessTokenTTL)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	_, err := config.Load("")
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected read error")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte(":\n  -"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected parse error")
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
		t.Fatal(err)
	}

	t.Setenv("GRANTO_CORS_ENABLED", "1")
	t.Setenv("GRANTO_CORS_ORIGINS", "https://a.com, https://b.com")
	t.Setenv("GRANTO_OIDC_DCR_ENABLED", "true")
	t.Setenv("GRANTO_OIDC_DCR_DEFAULT_SCOPES", "openid, profile")
	t.Setenv("GRANTO_ISSUER", "https://from-env")
	t.Setenv("GRANTO_LOGIN_URL", "https://login-from-env")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.CORS.Enabled {
		t.Fatal("cors enabled")
	}
	if len(cfg.CORS.AllowedOrigins) != 2 || cfg.CORS.AllowedOrigins[1] != "https://b.com" {
		t.Fatalf("origins: %#v", cfg.CORS.AllowedOrigins)
	}
	if !cfg.OIDC.DynamicClientRegistration.Enabled {
		t.Fatal("dcr enabled")
	}
	if len(cfg.OIDC.DynamicClientRegistration.DefaultScopes) != 2 {
		t.Fatalf("dcr scopes: %#v", cfg.OIDC.DynamicClientRegistration.DefaultScopes)
	}
	if cfg.Token.Issuer != "https://from-env" {
		t.Fatalf("issuer: %q", cfg.Token.Issuer)
	}
	if cfg.OAuth2.LoginURL != "https://login-from-env" {
		t.Fatalf("login: %q", cfg.OAuth2.LoginURL)
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
		t.Fatal("expected validation error")
	}
}
