# Public API (Granto Core)

Источник правды для публичной поверхности — **RFC / стандарты**, не собственная OpenAPI-спека и не codegen.

В этой папке **нет** `oapi-codegen` и нет «нашего» контракта, который можно произвольно менять. Менять поведение endpoint’ов можно только в рамках поддержки стандарта (и явного решения владельца о subset’е).

Реализация HTTP-адаптеров — в `internal/` (например `internal/transport/public`), не здесь.

## Принцип

Public API модуля `core` содержит **только** то, что описано в релевантных спецификациях:

- OAuth 2.0
- OpenID Connect
- GNAP

Плюс связанные well-known / discovery / JWKS, необходимые для этих протоколов. Продуктовые admin-операции сюда не входят — см. `../admin/`.

## Codegen

**Не используем** OpenAPI + `oapi-codegen` для public. Привычный contract-first codegen оставлен для **admin** (`../admin/` → proto → `../../../gen/admin/`).

При необходимости позже можно добавить documentation-only материалы — без обязательства генерировать handlers.

## Целевой список endpoint’ов (планируемый subset)

Пути и набор будут уточняться по мере реализации. Ориентир (как в типичном AS и в `granto_old`):

### Discovery / keys

| Method | Path | Спека |
|--------|------|--------|
| `GET` | `/.well-known/openid-configuration` | OpenID Connect Discovery |
| `GET` | `/.well-known/jwks.json` | JWK Set (OIDC / OAuth) |

### OAuth 2.0

| Method | Path | Спека (ориентир) |
|--------|------|------------------|
| `GET` | `/oauth2/auth` | RFC 6749 Authorization Endpoint (часто + PKCE / OIDC) |
| `POST` | `/oauth2/token` | RFC 6749 Token Endpoint |
| `POST` | `/oauth2/revoke` | RFC 7009 Token Revocation |
| `POST` | `/oauth2/introspect` | RFC 7662 Token Introspection |

### OpenID Connect

| Method | Path | Спека (ориентир) |
|--------|------|------------------|
| `GET` / `POST` | `/userinfo` | OIDC Core — UserInfo Endpoint |
| `GET` | `/oauth2/logout` | RP-Initiated Logout (OIDC) |

### GNAP

Endpoint’ы GNAP (grant endpoint и связанные) — **будут добавлены** в этот список при реализации, строго по спецификации GNAP. Пока не зафиксированы.

## Что сюда не кладём

- `*.proto`, сгенерённый Go, handlers, domain, storage
- Собственные «удобные» JSON API вне RFC
- Admin CRUD (clients, sessions admin, trusted issuance, …) — это `api/admin`
