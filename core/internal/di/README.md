# di

Dependency graph for granto-core, assembled with [Google Wire](https://github.com/google/wire).

This package only defines providers and injectors. Process lifecycle
(HTTP servers, graceful shutdown) belongs elsewhere (`internal/app` / `cmd`).

## Provider files

| File | Provides |
|------|----------|
| `config.go` | `*config.Config` from injector param `ConfigPath` |
| `logger.go` | Process logger (`slog`) |
| `public_http.go` | Public HTTP handler (OAuth2 / OIDC / GNAP) |
| `postgres.go` | `*postgres.DB` (migrate + pool), `ClientRepository`, `LoginSessionRepository` (needs Config) |
| `redis.go` | `*redis.Client`, challenges, FlowVerifier, AuthorizationCode, Token repositories |
| `admin.go` | Admin gRPC `ClientServer` + `admin.Server` (gRPC + gateway) |
| `app.go` | Composed `AppSet` (`App.Run` — lifecycle outside Wire) |
| `wire.go` | `InitializeApp(ConfigPath)` injector (wireinject) |

`ConfigPath` is supplied by `main` (`-config` flag or `GRANTO_CONFIG`). Providers receive `*config.Config` as a normal dependency.

## Regenerate

```bash
go generate ./internal/di
# or: make generate-wire
```

(`//go:generate` lives in `generate.go` so it runs without the `wireinject` build tag.)

`wire_gen.go` is generated — do not edit by hand.
