# Agent guidance

Read the assigned work package, `docs/PRODUCT.md`, `docs/MVP_SCOPE.md`,
`docs/ARCHITECTURE.md`, and relevant ADRs before editing.

- Work on a feature branch and preserve unrelated changes.
- Never merge, publish, push, deploy, sign, or send real notifications without
  explicit authorization.
- Never add an AdGuard mutation request, generic arbitrary endpoint, query-log
  retrieval, or telemetry.
- Keep credentials, private service data, client/domain activity, and absolute
  home paths out of Git and fixtures.
- Generate lockfiles with their real tools; never hand-author them.
- Use `rtk` for local commands when it is available. It is not a dependency.
- Run `nix develop -c just check` before handoff when Nix is available.
- Report files changed, commands run, authoritative results, assumptions,
  unverified claims, and unresolved issues.
