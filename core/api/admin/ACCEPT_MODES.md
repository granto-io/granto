# Admin Accept login/consent: default vs strict

This document is part of the **opensource** Admin API docs. It describes how
Granto protects Admin Accept/Reject for login and consent challenges, and how
that relates to ORY Hydra.

Public OAuth 2.0 / OIDC / GNAP endpoints are **not** covered here — they follow
RFCs and do not use Admin `accept_token`.

## Two modes

Configured with `admin.accept_strict` (YAML) or `GRANTO_ADMIN_ACCEPT_STRICT=true`.

| Mode | Config | AcceptLogin / AcceptConsent |
|------|--------|-----------------------------|
| **default** (Hydra-compatible) | `accept_strict: false` (default) | Enough: challenge id in query + **Admin API auth** (bearer). Body `accept_token` is **optional**. |
| **strict** | `accept_strict: true` | Same as default **plus** required `accept_token` from the preceding GetLogin / GetConsent response. |

Reject behaves the same: in strict mode (or if a token is sent), `accept_token` must match.

### What is always true

- On **Create** of a LoginChallenge / ConsentChallenge, Granto generates an
  `accept_token` and stores it on the Redis object.
- **GetLogin** / **GetConsent** always return that token so clients can use
  strict mode or add defence in depth even in default mode.
- This is **not** browser CSRF. The browser never sees Admin Accept; your
  consent/login app calls Admin with a privileged credential.

## Default mode (recommended for Hydra migrations)

Flow for a login/consent app:

1. AS redirects the browser to your UI with `login_challenge` / `consent_challenge`.
2. App calls **Get** with that id (Admin auth).
3. App authenticates the user / shows consent UI.
4. App calls **Accept** with the challenge id (+ Admin auth).  
   `accept_token` may be omitted.

This matches Hydra’s mental model: knowing the challenge id is not enough without
Admin credentials; Admin is the privilege boundary.

## Strict mode

Use when Admin is exposed more widely than you like, or you want an extra
one-time secret bound to the challenge:

1. GetLogin / GetConsent → read `accept_token`.
2. Accept / Reject **must** send the same `accept_token` in the body.
3. Wrong or missing token → error (`accept token invalid`).

Enable only after your consent/login apps send the token.

## Honest differences from Hydra

| Topic | Hydra (typical) | Granto |
|-------|-----------------|--------|
| Challenge id | Often a long encrypted blob | Short UUID in Redis |
| Accept proof | Challenge + Admin auth | Same in **default**; optional **strict** + `accept_token` |
| Paths | `/admin/oauth2/auth/requests/...` | Same Hydra-like paths |
| Public authorize/token | OAuth/OIDC RFCs | Same idea; Granto public surface is RFC-only |

Granto does **not** promise bit-identical Hydra challenge encoding or every
Hydra extension field. Path and Accept semantics in default mode are intended
to make porting login/consent apps straightforward.

## Config examples

```yaml
admin:
  token: "..."           # Admin bearer (MVP)
  accept_strict: false   # default
```

```bash
export GRANTO_ADMIN_ACCEPT_STRICT=true
```

## Related

- HTTP table: [`README.md`](./README.md)
- Proto: `v1/oauth2.proto`
- Implementation: `internal/oauth2` (Flow), `internal/transport/admin/oauth2.go`
