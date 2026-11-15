# Configuration (`internal/config`)

How granto-consent loads settings and what each section means.

## Load order

1. **Built-in defaults** (`defaults()` in `load.go`)
2. **Optional YAML file** — path from `-config` flag or `CONSENT_CONFIG` in `main`
3. **`CONSENT_*` environment overrides** — secrets and deploy knobs
4. **Validation** of required fields

Missing YAML keys keep defaults. Env wins over YAML when set.

```bash
granto-consent -config /etc/granto/consent.yaml
# or
export CONSENT_CONFIG=/etc/granto/consent.yaml
```

Example file: [`../../config.example.yaml`](../../config.example.yaml).

---

## Sections

### `server`

| Key | Default | Purpose |
|-----|---------|---------|
| `addr` | `:4455` | HTTP listen address (login/consent pages) |
| `shutdown_timeout` | `30s` | Graceful shutdown budget |

Env: `CONSENT_ADDR`.

Note: `/health` is served by the same listener but registered outside the `public` router (see `pkg/server.Run`), same split as `core/internal/app`.

### `log`

| Key | Default | Purpose |
|-----|---------|---------|
| `level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `format` | `json` | `json` \| `text` |

Env: `CONSENT_LOG_LEVEL`, `CONSENT_LOG_FORMAT`.

---

## Validation guards

`Load` rejects a config that could not start the process:

- `server.addr` must be non-empty
- `server.shutdown_timeout` must be positive

Both have defaults, so these only trigger when a YAML or env value explicitly empties or zeroes them.

---

## Wire

Not yet wired through Google Wire — `pkg/server.Run` calls `config.Load` directly. A `di.ConfigSet` analogous to core's will be added once the DI graph is introduced.
