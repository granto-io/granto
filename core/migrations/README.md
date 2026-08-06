# migrations

SQL schema migrations for granto-core ([golang-migrate](https://github.com/golang-migrate/migrate)).

Naming: `NNNNNN_name.up.sql` / `NNNNNN_name.down.sql`.

| Version | Name |
|---------|------|
| 000001 | `create_tenants` — tenants + default MVP row |
| 000002 | `create_clients` — OAuth2/OIDC/GNAP clients |

When embedding into the binary, keep a small Go file in this directory (Go cannot `embed` paths outside the package). Repositories and domain code stay under `internal/`; this folder is only the schema source of truth.

Apply (example, when a runner / DSN is wired):

```bash
migrate -path ./migrations -database "$DATABASE_URL" up
```
