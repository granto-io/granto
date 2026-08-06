# di

Dependency graph for granto-core, assembled with [Google Wire](https://github.com/google/wire).

This package only defines providers and injectors. Process lifecycle
(HTTP servers, graceful shutdown) belongs elsewhere (`internal/app` / `cmd`).

## Provider files

| File | Provides |
|------|----------|
| `logger.go` | Process logger (`slog`) |
| `public_http.go` | Public HTTP handler (OAuth2 / OIDC / GNAP) |
| `postgres.go` | Config, `*postgres.DB` (migrate + pool), `ClientRepository` |
| `app.go` | Composed `AppSet` |
| `wire.go` | `InitializeApp` injector (wireinject) |

## Regenerate

```bash
go generate ./internal/di
```

(`//go:generate` lives in `generate.go` so it runs without the `wireinject` build tag.)

`wire_gen.go` is generated — do not edit by hand.
