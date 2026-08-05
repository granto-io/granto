# Public API (Granto Core)

The public surface is defined by **RFCs / standards**, not by a custom OpenAPI spec or codegen.

This directory does **not** use `oapi-codegen`. Endpoint behaviour follows the relevant specifications (and the supported subset documented below). Product admin operations are not part of this surface — see `../admin/`.

HTTP adapters live in `../../internal/transport/public/`.

## Scope

Public API of `core` exposes only what belongs to:

- OAuth 2.0
- OpenID Connect
- GNAP ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635.html))

plus discovery / JWKS needed by those protocols.

## Codegen

OpenAPI + `oapi-codegen` is **not** used for public. Contract-first codegen is for **admin** (`../admin/` → proto → `../../../gen/admin/`). Documentation-only OpenAPI for public may appear later without generating handlers.

## Endpoints

OAuth/OIDC paths follow common AS practice. GNAP paths are **Granto’s concrete URIs** for the abstract endpoints in RFC 9635 (the RFC does not mandate path names).

### Discovery / keys (OIDC)

| Method | Path | Spec |
|--------|------|------|
| `GET` | `/.well-known/openid-configuration` | OpenID Connect Discovery |
| `GET` | `/.well-known/jwks.json` | JWK Set |

### OAuth 2.0

| Method | Path | Spec |
|--------|------|------|
| `GET` | `/oauth2/auth` | RFC 6749 Authorization Endpoint (often + PKCE / OIDC) |
| `POST` | `/oauth2/token` | RFC 6749 Token Endpoint |
| `POST` | `/oauth2/revoke` | RFC 7009 Token Revocation |
| `POST` | `/oauth2/introspect` | RFC 7662 Token Introspection |

### OpenID Connect

| Method | Path | Spec |
|--------|------|------|
| `GET` / `POST` | `/userinfo` | OIDC Core — UserInfo |
| `GET` | `/oauth2/logout` | RP-Initiated Logout |

### GNAP ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635.html))

| Method | Path | Role in RFC |
|--------|------|-------------|
| `POST` | `/gnap` | Grant endpoint (§2) |
| `OPTIONS` | `/gnap` | AS discovery (§9) |
| `POST` | `/gnap/continue` | Continuation API — stable URI (§5.1 / §5.2) |
| `PATCH` | `/gnap/continue` | Modify ongoing grant (§5.3) |
| `DELETE` | `/gnap/continue` | Cancel / finalize grant (§5.4) |
| `POST` / `PATCH` / `DELETE` | `/gnap/continue/{continueID}` | Continuation API — unique-per-grant URI (§5) |
| `POST` | `/gnap/token/{tokenID}` | Token management — rotate (§6.1) |
| `DELETE` | `/gnap/token/{tokenID}` | Token management — revoke (§6.2) |
| `GET` | `/gnap/interact/{interactID}` | AS-hosted redirect interaction (§4.1.1); may later integrate with the consent module |
| `GET` | `/gnap/device` | Static user_code entry URI (§4.1.2) |

GNAP errors follow §3.6 (`error` as `{code, description}` or a string code), **not** OAuth’s `error` / `error_description`. Helpers in transport: `writeGNAPError` / `writeOAuthError`.

Continuation and token-management URIs in live AS responses are absolute URLs matching these templates; clients call them with the continuation / management access token and key proof (§7).

## Out of scope here

- `*.proto`, generated Go, handlers, domain, storage
- Custom JSON APIs outside the RFCs
- Admin CRUD — see `api/admin`
