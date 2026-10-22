# Configuration (`internal/config`)

How granto-core loads settings and what each section means.

## Load order

1. **Built-in defaults** (`defaults()` in `load.go`)
2. **Optional YAML file** — path from `InitializeApp(ConfigPath)` (`-config` flag or `GRANTO_CONFIG` in `main`)
3. **`GRANTO_*` environment overrides** — secrets and deploy knobs
4. **Validation** of required fields

Missing YAML keys keep defaults. Env wins over YAML when set.

```bash
granto-core -config /etc/granto/config.yaml
# or
export GRANTO_CONFIG=/etc/granto/config.yaml
```

Example file: [`../../config.example.yaml`](../../config.example.yaml).

---

## Sections

### `server`

HTTP/gRPC listen addresses and process shutdown.

| Key | Default | Purpose |
|-----|---------|---------|
| `public_addr` | `:4444` | Public OAuth2 / OIDC / GNAP HTTP |
| `admin_rest_addr` | `:4445` | Admin REST (gRPC-Gateway) — often reachable by login/consent apps |
| `admin_grpc_addr` | `127.0.0.1:4446` | Admin gRPC — **loopback by default** (gateway + local tools). Port-only `:4446` listens on all interfaces; set that only if you mean to expose gRPC. Bearer auth still required either way. |
| `metrics_addr` | `:4447` | Metrics (when enabled) |
| `tls_cert_file` / `tls_key_file` | empty | Optional TLS files |
| `shutdown_timeout` | `30s` | Graceful shutdown budget |

Env: `GRANTO_PUBLIC_ADDR`, `GRANTO_ADMIN_REST_ADDR`, `GRANTO_ADMIN_GRPC_ADDR`, `GRANTO_METRICS_ADDR`.

Note: `dialLocal` in the Admin server rewrites a port-only gRPC addr to `127.0.0.1:…` for the **gateway's outbound dial** only. It does not change what `Listen` binds — hence the loopback default on `admin_grpc_addr`.

### `postgres`

Database pool and migrations.

| Key | Default | Purpose |
|-----|---------|---------|
| `dsn` | *(required)* | Connection string |
| `max_open` / `max_idle` | `25` / `5` | Pool sizing |
| `conn_max_lifetime` | `5m` | Max connection age |
| `migrate_on_start` | `true` | Run `postgres.Migrate` before serving |

Env: `GRANTO_POSTGRES_DSN`.

### `redis`

Sessions, auth codes, and similar short-lived state (when wired).

| Key | Default | Purpose |
|-----|---------|---------|
| `addr` | `localhost:6379` | Host:port |
| `password` | empty | AUTH password |
| `db` | `0` | Logical DB index |
| `sentinel_addrs` / `sentinel_master` | empty | Sentinel mode |
| `pool_size` | `10` | Client pool |

Env: `GRANTO_REDIS_ADDR`, `GRANTO_REDIS_PASSWORD`.

### `token`

Issuance defaults and crypto for signing material at rest.

| Key | Default | Purpose |
|-----|---------|---------|
| `issuer` | *(required)* | `iss` claim / discovery issuer |
| `default_algorithm` | `RS256` | Default signing alg |
| `access_token_ttl` / `refresh_token_ttl` / `id_token_ttl` | `1h` / `720h` / `1h` | Server defaults (clients may override) |
| `master_key` | — | Required for auto-gen signing keys (AES-256-GCM at rest). Skip if static PEM is set. `GRANTO_MASTER_KEY` |
| `signing_keys.private_key_file` / `private_key_pem` / `kid` | empty | Static AS signing key (prod). Env: `GRANTO_TOKEN_SIGNING_PRIVATE_KEY_FILE`, `…_PEM`, `…_KID` |
| `master_key` | *(required, ≥32 chars)* | Encrypts private keys in DB |

Env: `GRANTO_ISSUER`, `GRANTO_MASTER_KEY`. Prefer env for `master_key` in production.

### `session`

Authentication session TTL bounds (consent / login session store).

| Key | Default | Purpose |
|-----|---------|---------|
| `default_ttl` | `24h` | Default session lifetime |
| `max_ttl` | `720h` | Hard ceiling |
| `logout_scope` | `session` | How far `/oauth2/logout` reaches: `session` \| `device` \| `subject`. For `device`/`subject`, GET → confirm, POST completes. Also: `Sec-Fetch-Site=cross-site` without `id_token_hint` forces confirm even for `session` (warn-logged). |

### `oauth2`

URLs of the login/consent UI (usually the **consent** module or an external app). Core redirects browsers here during authorize.

| Key | Default | Purpose |
|-----|---------|---------|
| `login_url` | *(required)* | Where to send the user to authenticate |
| `consent_url` | empty | Consent UI (MVP may reuse login) |
| `logout_url` | empty | Post-logout / RP logout UX |

Env: `GRANTO_LOGIN_URL`, `GRANTO_CONSENT_URL`, `GRANTO_LOGOUT_URL`.

### `oidc`

OIDC extras and **Dynamic Client Registration** (public `/oauth2/register`).

| Key | Default | Purpose |
|-----|---------|---------|
| `extra_scopes` | empty | Extra scopes advertised / allowed beyond standard OIDC |
| `dynamic_client_registration.enabled` | **`false`** | When `true`, public RFC 7591 / OIDC DCR endpoints are available. When `false`, external self-registration must be rejected (admin CRUD remains on Admin API). Same idea as Hydra `oidc.dynamic_client_registration.enabled`. |
| `dynamic_client_registration.default_scopes` | empty | Scopes applied to clients created via DCR when the request omits scopes |

Env: `GRANTO_OIDC_DCR_ENABLED`, `GRANTO_OIDC_DCR_DEFAULT_SCOPES` (comma-separated).

**Security note:** leave DCR disabled unless you intentionally allow untrusted parties to register OAuth clients on the public port.

### `admin`

Admin API access (MVP: static bearer; production may move to mTLS / OAuth).

| Key | Default | Purpose |
|-----|---------|---------|
| `token` | *(required)* | Bearer token for Admin API |
| `accept_strict` | `false` | When `true`, AcceptLogin/AcceptConsent require `accept_token` from Get*. Default = Hydra-compatible (challenge id + Admin auth enough) |

Env: `GRANTO_ADMIN_TOKEN`, `GRANTO_ADMIN_ACCEPT_STRICT`. Prefer env for `token` in production. IP allow-listing is out of MVP (network / reverse-proxy concern for now).

### `cors`

Cross-Origin Resource Sharing on the public HTTP surface.

| Key | Default | Purpose |
|-----|---------|---------|
| `enabled` | `false` | Off = no CORS headers (fine for server-to-server / curl) |
| `allowed_origins` | empty | Explicit list, or `["*"]` for open (dev only) |
| `allowed_methods` / `allowed_headers` | GET,POST,OPTIONS / Authorization,Content-Type | Preflight advertisements |
| `max_age` | `300` | Preflight cache (seconds) |

Env: `GRANTO_CORS_ENABLED`, `GRANTO_CORS_ORIGINS` (comma-separated).

### `log`

| Key | Default | Purpose |
|-----|---------|---------|
| `level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `format` | `json` | `json` \| `text` |

Env: `GRANTO_LOG_LEVEL`, `GRANTO_LOG_FORMAT`.

### `telemetry`

OpenTelemetry tracing.

| Key | Default | Purpose |
|-----|---------|---------|
| `enabled` | `false` | Turn tracing on |
| `endpoint` | empty | OTLP host:port; empty may mean stdout exporter when enabled |
| `insecure` | `false` | HTTP instead of HTTPS to collector |
| `service_name` | `granto-core` | Resource attribute |
| `sample_rate` | `1.0` | Trace sampling 0.0–1.0 |

---

## Required at startup

Validation fails unless these are set (YAML and/or env):

- `token.issuer` / `GRANTO_ISSUER`
- `token.master_key` / `GRANTO_MASTER_KEY` (≥ 32 characters)
- `postgres.dsn` / `GRANTO_POSTGRES_DSN`
- `admin.token` / `GRANTO_ADMIN_TOKEN`
- `oauth2.login_url` / `GRANTO_LOGIN_URL`

---

## Wire

`di.ConfigSet` builds `*config.Config` from injector param `ConfigPath`. Downstream providers (e.g. `provideDB`) take `*config.Config` and use the relevant nested struct (`cfg.Postgres`, `cfg.OIDC.DynamicClientRegistration`, …). We do **not** register a separate Wire set per subsection.
