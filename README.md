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
  cmd/                        # Process entrypoint (main.go)
  internal/di/                # Dependency graph (Google Wire sets)
  internal/app/               # App type / process lifecycle (no Wire)
  internal/config/            # defaults → YAML → GRANTO_* env
  internal/domain/            # Domain types
  internal/repository/        # Storage interfaces
  internal/repository/postgres/
  internal/repository/redis/
  internal/transport/public/  # Public HTTP adapters (chi)
```

Public HTTP stack: **chi**, **slog**, OpenTelemetry (`otelhttp` at the server boundary). Admin API: protobuf → gRPC + gRPC-Gateway. Persistence: **PostgreSQL** via **pgx** + **golang-migrate**.

Internal wiring uses **Google Wire** in `internal/di`. Third-party consent plugins (later) will use a Host API, not Wire.

### Regenerate code

From `core/` (or repo root via the root Makefile):

```bash
make generate          # all generators
make generate-wire     # Google Wire only
make generate-proto    # admin: api/admin → gen/admin (buf)
```

Requires [buf](https://buf.build/docs/installation) for proto. Equivalent: `buf generate` from `core/`.

See `core/internal/di/README.md`, `core/api/public/README.md`, and `core/api/admin/README.md`.

## Local stack (Docker Compose)

From the `granto/` directory:

```bash
docker compose up --build
```

Services: **postgres** (`localhost:5432`), **redis** (`localhost:6379`), **core** (Air hot-reload; public HTTP `:4444` when the server listens). Env: `GRANTO_*` (see `core/config.example.yaml` / `internal/config`).

### Configuration

Load order: **built-in defaults → YAML file → `GRANTO_*` env**. Example file: `core/config.example.yaml`. Package: `internal/config` (`config.Load(path)`).
