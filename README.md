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
  gen/admin/v1/               # Generated gRPC / gateway code
  cmd/                        # Process entrypoint
  internal/transport/public/  # Public HTTP adapters (chi)
```

Public HTTP stack: **chi**, **slog**, OpenTelemetry (`otelhttp` at the server boundary). Admin API: protobuf → gRPC + gRPC-Gateway.

See `core/api/public/README.md` and `core/api/admin/README.md` for API surfaces.
