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
| `ClientService` | `v1/client.proto` | `/admin/v1/clients` | `internal/transport/admin/client.go` (CRUD via `ClientRepository`) |

Client CRUD: create / get / list / update / delete. Path `{id}` is the internal UUID (`clients.id`), not `client_id`.

Public Dynamic Client Registration (`/oauth2/register`) is **not** part of Admin API.

## Conventions

- `option go_package = "github.com/granto-io/granto/core/gen/admin/v1;adminv1"`
- REST paths under `/admin/v1/...`
- Implementations embed `Unimplemented*Server` and live only under `internal/transport/admin`
- Wire registration of admin servers / gateway mux — separate step
