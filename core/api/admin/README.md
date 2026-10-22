# Admin API contracts (proto)

Source of truth for the **Admin API** of Granto Core: Protocol Buffers + gRPC + [gRPC-Gateway](https://grpc-ecosystem.github.io/grpc-gateway/).

## Layout

| Path | Role |
|------|------|
| `v1/*.proto` | Service contracts + `google.api.http` annotations |
| `../../../gen/admin/v1/` | Generated Go (messages, gRPC, gateway) — **do not edit** |
| `../../../internal/transport/admin/` | Hand-written service implementations (one package; files by domain: `client.go`, `client_mapper.go`, …) |

Root of the module also has `buf.yaml` / `buf.gen.yaml` (buf module path = `api/`).

## Generate

From `core/`:

```bash
make generate-proto
# or: buf generate
```

Requires [buf](https://buf.build/docs/installation) CLI. Deps resolve from the BSR (`buf.build/googleapis/googleapis`).

Full regenerate (Wire + proto): `make generate`.

## Current services

| Service | Proto | HTTP prefix | Impl |
|---------|-------|-------------|------|
| `ClientService` | `v1/client.proto` | `/admin/v1/clients` | `internal/transport/admin/client.go` |
| `OAuth2Service` | `v1/oauth2.proto` | `/admin/oauth2/auth/requests/...` (Hydra-like) | `internal/transport/admin/oauth2.go` → `internal/oauth2.Flow` |
| `LoginSessionService` | `v1/session.proto` | `/admin/v1/login-sessions` (+ Hydra revoke path) | `internal/transport/admin/session.go` → `internal/oauth2.Flow` |
| `ConsentGrantService` | `v1/consent_grant.proto` | `/admin/v1/consent-grants` (+ Hydra consent sessions paths) | `internal/transport/admin/consent_grant.go` → `internal/oauth2.Flow` |

Client CRUD: create / get / list / update / delete. Path `{id}` is the internal UUID (`clients.id`), not `client_id`.

OAuth2 login/consent Admin (Hydra-compatible paths):

| Method | Path |
|--------|------|
| GET | `/admin/oauth2/auth/requests/login?login_challenge=` |
| PUT | `/admin/oauth2/auth/requests/login/accept?login_challenge=` |
| PUT | `/admin/oauth2/auth/requests/login/reject?login_challenge=` |
| GET | `/admin/oauth2/auth/requests/consent?consent_challenge=` |
| PUT | `/admin/oauth2/auth/requests/consent/accept?consent_challenge=` |
| PUT | `/admin/oauth2/auth/requests/consent/reject?consent_challenge=` |

`accept_token` is always returned by Get*; required on Accept/Reject only when `admin.accept_strict` is true.

**Accept modes (default vs strict):** see [`ACCEPT_MODES.md`](./ACCEPT_MODES.md) — required reading before shipping a login/consent app against Admin.

Login sessions (SSO cookie / OIDC `sid`):

| Method | Path |
|--------|------|
| GET | `/admin/v1/login-sessions/{id}` |
| GET | `/admin/v1/login-sessions?subject=` (required) |
| DELETE | `/admin/v1/login-sessions/{id}` |
| DELETE | `/admin/oauth2/auth/sessions/login?sid=` **or** `?subject=` (Hydra-compatible; exactly one) |

Delete / revoke **first revokes refresh tokens** bound to the session, then deletes the LoginSession (so a revoke failure does not leave orphan RTs without a session). Also sends **back-channel logout** (`logout_token` POST) to RPs that registered `backchannel_logout_uri` and received tokens for that session. Front-channel (browser iframes) runs on public `/oauth2/logout` only.

Remembered consent grants (`ConsentGrant`):

| Method | Path |
|--------|------|
| GET | `/admin/v1/consent-grants?subject=` (required; optional `client_id=`) |
| DELETE | `/admin/v1/consent-grants?subject=` (optional `client_id=` → one client; omit → all for subject) |
| GET | `/admin/oauth2/auth/sessions/consent?subject=` (Hydra-compatible alias) |
| DELETE | `/admin/oauth2/auth/sessions/consent?subject=` (optional `client_id=`) |

Revoke removes the grant row so the next authorize shows consent UI again. Unlike Hydra, outstanding AT/RT are **not** invalidated here yet (no revoke-by-subject index). Query param is `client_id` (Hydra used `client`).

Audit events are **not** listed via Admin API. Core emits a stream (Postgres outbox → configured channels: `stdout`, `webhook`). See `audit` in config / `internal/config/README.md`.

Public Dynamic Client Registration (`/oauth2/register`) is **not** part of Admin API.

## Conventions

- `option go_package = "github.com/granto-io/granto/core/gen/admin/v1;adminv1"`
- REST paths under `/admin/v1/...`
- Implementations embed `Unimplemented*Server` and live only under `internal/transport/admin`
- Wire registration of admin servers / gateway mux — separate step
