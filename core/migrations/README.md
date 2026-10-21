# migrations

SQL schema migrations for granto-core ([golang-migrate](https://github.com/golang-migrate/migrate)).

Naming: `NNNNNN_name.up.sql` / `NNNNNN_name.down.sql`.

| Version | Name |
|---------|------|
| 000001 | `create_tenants` — tenants + default MVP row |
| 000002 | `create_clients` — OAuth2/OIDC/GNAP clients |
| 000003 | `client_dcr_fields` — DCR: `registration_access_token_hash`, `is_dynamic` |
| 000004 | `create_login_sessions` — AS SSO sessions |
| 000005 | `create_signing_keys` — AS signing keys (auto-gen path) |
| 000006 | `create_consent_grants` — remembered consent (subject+client) |

`fs.go` embeds `*.sql` for the in-process runner (`internal/postgres.Migrate`). Repositories stay under `internal/repository/`; this folder is only the schema source of truth.

Apply via app (`migrate_on_start: true`) or CLI:

```bash
migrate -path ./migrations -database "$DATABASE_URL" up
```
