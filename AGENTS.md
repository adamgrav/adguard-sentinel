# Agent guidance

Read `docs/PRODUCT.md`, `docs/SUPPORT.md`, `docs/ARCHITECTURE.md`, and the
relevant ADRs in `docs/decisions/` before editing.

## Boundaries

- Never add an AdGuard mutation request, a generic arbitrary-endpoint or
  arbitrary-method constructor, query-log retrieval, remediation, or telemetry.
  The allowlist in `docs/API_ALLOWLIST.md` is the complete AdGuard surface.
- Never weaken strict external-data handling. Missing or invalid required data
  makes an observation incomplete; it must never become a healthy default.
- Keep credentials, private service data, client and domain activity, live API
  responses, and absolute home paths out of Git and out of fixtures. Fixtures
  use RFC 5737 addresses and reserved `.invalid` names only.
- Never deploy, publish, push, tag, sign, or send real notifications without
  explicit authorization.

## Workflow

- Work on a feature branch and preserve unrelated changes.
- Generate lockfiles and schemas with their real tools; never hand-author them.
  Run `tools/update-schemas.sh` after an intentional public type change.
- Run `nix develop -c just check` before submitting changes.
- Report files changed, commands run, authoritative results, assumptions,
  unverified claims, and unresolved issues.
