# granto

Активная кодовая база (монорепо модулей).

## Модули

- `core/` — сессии, OAuth2/OIDC, GNAP
- `consent/` — engine + auth plugins (позже)
- `rbac/` — позже

## `core` — контракты

```
core/
  api/admin/v1/   # proto (пока пусто)
  api/public/     # RFC-only docs (README)
  gen/admin/v1/   # сгенерённый Go из proto
  cmd/            # entrypoint
  internal/       # реализация (ещё не разложена)
```

См. корневые `CONTEXT.md`, `DECISIONS.md` (D-006, D-007), `STEPS.md`.
