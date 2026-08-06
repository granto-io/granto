# Granto

Modular authorization: OAuth 2.0, OpenID Connect, and GNAP.

## Modules

| Module | Role |
|--------|------|
| `core/` | Sessions, OAuth2/OIDC, GNAP (authorization server kernel) |
| `consent/` | Login / consent (engine + auth plugins) — planned |
| `rbac/` | Authorization policies — planned |

Each module is intended to be installable (and replaceable) on its own.

## `core` layout

```
core/
  api/admin/v1/               # Admin API protobuf sources
  api/public/                 # Public API notes (RFC surface)
  migrations/                 # Postgres SQL migrations (golang-migrate)
  gen/admin/v1/               # Generated gRPC / gateway code
  cmd/granto-core/            # Process entrypoint
  internal/di/                # Dependency graph (Google Wire sets)
  internal/app/               # App type / process lifecycle (no Wire)
  internal/transport/public/  # Public HTTP adapters (chi)
```

Public HTTP stack: **chi**, **slog**, OpenTelemetry (`otelhttp` at the server boundary). Admin API: protobuf → gRPC + gRPC-Gateway. Persistence: **PostgreSQL** via **pgx** + **golang-migrate**.

Internal wiring uses **Google Wire** in `internal/di`. Third-party consent plugins (later) will use a Host API, not Wire.

### Regenerate Wire

```bash
cd core
go generate ./internal/di
```

See `core/internal/di/README.md`, `core/api/public/README.md`, and `core/api/admin/README.md`.

## Local stack (Docker Compose)

From the `granto/` directory:

```bash
docker compose up --build
```

Services: **postgres** (`localhost:5432`), **redis** (`localhost:6379`), **core** (Air hot-reload; public HTTP `:4444` when the server listens). Env defaults: `POSTGRES_DSN`, `REDIS_ADDR`, `PUBLIC_HTTP_ADDR`.
