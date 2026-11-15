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

### `csrf`

| Key | Default | Purpose |
|-----|---------|---------|
| `secret` | empty | HMAC key for challenge-bound CSRF tokens |

Env: `CONSENT_CSRF_SECRET` (the only supported source for a shared secret).

An empty secret makes the process generate a random key at startup, which is fine for one instance but makes replicas reject each other's forms. Set a shared secret (32+ random bytes) whenever more than one instance runs.

This CSRF token is separate from core's `accept_token`: the token binds the browser to the `login_challenge` / `consent_challenge` and is always verified by the engine, so a plugin cannot skip it.

### `core`

| Key | Default | Purpose |
|-----|---------|---------|
| `admin_addr` | `127.0.0.1:4446` | core Admin gRPC API address |
| `admin_token` | empty | Bearer token for the Admin API |
| `admin_tls_ca_file` | empty | Optional private CA bundle for the Admin gRPC TLS connection |

Env: `CONSENT_CORE_ADMIN_ADDR`, `CONSENT_CORE_ADMIN_TOKEN`, `CONSENT_CORE_ADMIN_TLS_CA_FILE`.

`admin_token` is required and should only come from the environment or a secret file. Plain text gRPC is allowed only for loopback addresses (`localhost`, `127.0.0.1`, `::1`); any other address uses TLS, pinning `admin_tls_ca_file` when set.

### `identity`

| Key | Default | Purpose |
|-----|---------|---------|
| `addr` | `127.0.0.1:4456` | identity service gRPC API address |

Env: `CONSENT_IDENTITY_ADDR`.

The identity service implements the public `IdentityService` contract
(`identity/api/identity/v1`). Only loopback addresses are supported for now
(plain text); TLS for non-loopback is a later step. Plugins that need an
identity backend (email-OTP, password) receive it via `Host.Identity()`.

### `plugins`

| Key | Default | Purpose |
|-----|---------|---------|
| `enabled` | empty (required) | Registered plugin names to activate, in display order |
| `config` | empty | Per-plugin YAML passed to `Plugin.Init` through `Host.Config()` |

Env: `CONSENT_PLUGINS_ENABLED` (comma-separated names).

Activation is a runtime concern; the plugin code itself must be compiled into the binary (blank import or `pkg/server` library mode). A name that is enabled but not registered fails startup, as does an empty list or a duplicate.

One enabled plugin means `/login` redirects straight to its form; two or more render a method chooser.

### `plugins.config.email-otp`

| Key | Default | Purpose |
|-----|---------|---------|
| `code_ttl` | `10m` | How long a 6-digit code stays valid |
| `max_attempts` | `5` | Wrong guesses before the code is discarded |
| `resend_cooldown` | `1m` | Minimum delay between two codes for one challenge |
| `dev_log_codes` | `false` | Write codes to the log instead of email |

`dev_log_codes` is a development aid only; never enable it outside a local environment.

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
- `core.admin_addr` must be non-empty
- `core.admin_token` must be non-empty
- `plugins.enabled` must list at least one plugin

The server and admin address have defaults, so those checks only trigger when a YAML or env value explicitly empties them.

---

## Wire

The dependency graph is wired through Google Wire in `internal/di`
(`ConfigSet`, `LoggerSet`, `ClientSet`, `EngineSet`, `AppSet`). `pkg/server.Run`
calls `di.InitializeApp` and then `app.Run`; `cmd/main.go` wraps `pkg/server.Run`
with the built-in plugins.
