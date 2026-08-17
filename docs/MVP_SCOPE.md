# MVP scope

## Included

- Rust 2024 workspace pinned to Rust 1.97.1.
- `validate-config`, `check`, `report`, `migrate-state`, and `print-schema`.
- AdGuard Home versions `>=0.107.78,<0.108.0`.
- Six allowlisted AdGuard GET operations.
- Strict response parsing, bounded target concurrency, request timeouts, and
  response-size limits.
- Per-target operational and policy findings plus one explicit behavior group.
- Pushover as the only notification sink.
- SQLite schema v1, explicit migration, bounded retention, and a transactional
  outbox.
- Versioned config and run-report schemas.
- Synthetic API fixtures and deterministic behavior, transport, state, and CLI
  tests.
- A Nix package, checks, and development shell. A supported-platform claim is
  made only for a system on which the package has actually been built.

## Excluded

- A web UI, daemon, Prometheus, HTML output, other notification sinks,
  containers, signed binaries, prebuilt release artifacts, or Windows.
- A reusable NixOS service module. Host integration — systemd units,
  credentials, timers, and hardening — is owned by the operator's own
  configuration.
- DNS canary probes, query logs, top domains, client identities, caches,
  sessions, persistent clients, or undeclared rewrites.
- Every AdGuard `POST`, `PUT`, `PATCH`, and `DELETE` operation.
