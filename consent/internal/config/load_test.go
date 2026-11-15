package config

import (
	"testing"
	"time"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CONSENT_CORE_ADMIN_TOKEN", "test-admin-token")
	t.Setenv("CONSENT_PLUGINS_ENABLED", "email-otp")
}

func TestLoad_Defaults(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Addr != ":4455" {
		t.Errorf("Server.Addr = %q, want %q", cfg.Server.Addr, ":4455")
	}
	if cfg.Server.ShutdownTimeout != 30*time.Second {
		t.Errorf("Server.ShutdownTimeout = %v, want 30s", cfg.Server.ShutdownTimeout)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "info")
	}
	if cfg.Core.AdminAddr != "127.0.0.1:4446" {
		t.Errorf("Core.AdminAddr = %q, want %q", cfg.Core.AdminAddr, "127.0.0.1:4446")
	}
	if len(cfg.Plugins.Enabled) != 1 || cfg.Plugins.Enabled[0] != "email-otp" {
		t.Errorf("Plugins.Enabled = %v, want [email-otp]", cfg.Plugins.Enabled)
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("CONSENT_ADDR", ":9999")
	t.Setenv("CONSENT_LOG_LEVEL", "debug")
	t.Setenv("CONSENT_LOG_FORMAT", "text")
	t.Setenv("CONSENT_CSRF_SECRET", "csrf-secret")
	t.Setenv("CONSENT_CORE_ADMIN_ADDR", "core.internal:4446")
	t.Setenv("CONSENT_CORE_ADMIN_TOKEN", "admin-token")
	t.Setenv("CONSENT_CORE_ADMIN_TLS_CA_FILE", "/etc/granto/ca.pem")
	t.Setenv("CONSENT_PLUGINS_ENABLED", "password, email-otp")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Addr != ":9999" {
		t.Errorf("Server.Addr = %q, want %q", cfg.Server.Addr, ":9999")
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
	}
	if cfg.Log.Format != "text" {
		t.Errorf("Log.Format = %q, want %q", cfg.Log.Format, "text")
	}
	if cfg.CSRF.Secret != "csrf-secret" {
		t.Errorf("CSRF.Secret = %q, want %q", cfg.CSRF.Secret, "csrf-secret")
	}
	if cfg.Core.AdminAddr != "core.internal:4446" {
		t.Errorf("Core.AdminAddr = %q, want %q", cfg.Core.AdminAddr, "core.internal:4446")
	}
	if cfg.Core.AdminToken != "admin-token" {
		t.Errorf("Core.AdminToken = %q, want %q", cfg.Core.AdminToken, "admin-token")
	}
	if cfg.Core.AdminTLSCAFile != "/etc/granto/ca.pem" {
		t.Errorf("Core.AdminTLSCAFile = %q, want %q", cfg.Core.AdminTLSCAFile, "/etc/granto/ca.pem")
	}
	if len(cfg.Plugins.Enabled) != 2 || cfg.Plugins.Enabled[0] != "password" || cfg.Plugins.Enabled[1] != "email-otp" {
		t.Errorf("Plugins.Enabled = %v, want [password email-otp]", cfg.Plugins.Enabled)
	}
}

func TestLoad_RequiresAdminToken(t *testing.T) {
	t.Setenv("CONSENT_PLUGINS_ENABLED", "email-otp")

	if _, err := Load(""); err == nil {
		t.Fatal("Load: expected error without core.admin_token")
	}
}

func TestLoad_RequiresEnabledPlugins(t *testing.T) {
	t.Setenv("CONSENT_CORE_ADMIN_TOKEN", "token")

	if _, err := Load(""); err == nil {
		t.Fatal("Load: expected error without plugins.enabled")
	}
}
