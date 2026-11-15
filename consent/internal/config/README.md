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

Note: `/health` is served separately from the `public` router (see `pkg/server.Run`), same split as `core/internal/app` — it is not part of this `addr`'s protocol surface, just the same listener.

### `log`

| Key | Default | Purpose |
|-----|---------|---------|
| `level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `format` | `json` | `json` \| `text` |

Env: `CONSENT_LOG_LEVEL`, `CONSENT_LOG_FORMAT`.

---

## Required at startup

Validation fails unless these are set (YAML and/or env):

- `server.addr` / `CONSENT_ADDR`
- `server.shutdown_timeout` — must be positive (has a default, so only fails if explicitly zeroed)

---

## Wire

Not yet wired through Google Wire — `pkg/server.Run` calls `config.Load` directly. A `di.ConfigSet` analogous to core's will be added once the DI graph is introduced.
