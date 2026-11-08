package config

import (
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
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
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("CONSENT_ADDR", ":9999")
	t.Setenv("CONSENT_LOG_LEVEL", "debug")
	t.Setenv("CONSENT_LOG_FORMAT", "text")

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
}
