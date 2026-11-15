# Configuration (`internal/config`)

How granto-identity loads settings and what each section means.

## Load order

1. **Built-in defaults** (`defaults()` in `load.go`)
2. **Optional YAML file** — path from `-config` flag or `IDENTITY_CONFIG` in `main`
3. **`IDENTITY_*` environment overrides** — secrets and deploy knobs
4. **Validation** of required fields

Missing YAML keys keep defaults. Env wins over YAML when set.

```bash
granto-identity -config /etc/granto/identity.yaml
# or
export IDENTITY_CONFIG=/etc/granto/identity.yaml
```

Example file: [`../../config.example.yaml`](../../config.example.yaml).

---

## Sections

### `server`

| Key | Default | Purpose |
|-----|---------|---------|
| `grpc_addr` | `127.0.0.1:4456` | IdentityService gRPC listen address |
| `rest_addr` | `127.0.0.1:4457` | grpc-gateway HTTP/JSON listen address |
| `shutdown_timeout` | `30s` | Graceful shutdown budget |

Env: `IDENTITY_GRPC_ADDR`, `IDENTITY_REST_ADDR`.

### `postgres`

| Key | Default | Purpose |
|-----|---------|---------|
| `dsn` | empty (required) | PostgreSQL connection string |
| `max_open` | 0 (pool default) | Max open connections |
| `max_idle` | 0 (pool default) | Min idle connections |
| `conn_max_lifetime` | 0 (pool default) | Connection max lifetime |
| `migrate_on_start` | `true` | Apply pending migrations at startup |

Env: `IDENTITY_POSTGRES_DSN`.

### `log`

| Key | Default | Purpose |
|-----|---------|---------|
| `level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `format` | `json` | `json` \| `text` |

Env: `IDENTITY_LOG_LEVEL`, `IDENTITY_LOG_FORMAT`.

---

## Validation guards

`Load` rejects a config that could not start the process:

- `server.grpc_addr` must be non-empty
- `server.shutdown_timeout` must be positive
- `postgres.dsn` must be non-empty

---

## Health

The gRPC server exposes the standard gRPC health check
(`grpc.health.v1.Health`). There is no separate HTTP `/health` endpoint yet;
add one on a dedicated listener if an HTTP probe is required.
