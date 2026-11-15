package config

import (
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("IDENTITY_POSTGRES_DSN", "postgres://u:p@localhost:5432/db")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.GRPCAddr != "127.0.0.1:4456" {
		t.Fatalf("grpc_addr = %q, want default", cfg.Server.GRPCAddr)
	}
	if cfg.Server.RESTAddr != "127.0.0.1:4457" {
		t.Fatalf("rest_addr = %q, want default", cfg.Server.RESTAddr)
	}
	if !cfg.Postgres.MigrateOnStart {
		t.Fatal("migrate_on_start should default to true")
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	t.Setenv("IDENTITY_POSTGRES_DSN", "postgres://u:p@localhost:5432/db")
	t.Setenv("IDENTITY_GRPC_ADDR", "0.0.0.0:9999")
	t.Setenv("IDENTITY_LOG_LEVEL", "debug")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.GRPCAddr != "0.0.0.0:9999" {
		t.Fatalf("grpc_addr = %q, want env override", cfg.Server.GRPCAddr)
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("log.level = %q, want debug", cfg.Log.Level)
	}
}

func TestLoad_RequiresDSN(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Fatal("expected error for missing postgres.dsn")
	}
}
