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
- SQLite schema v1, explicit migration, bounded retention, transactional outbox,
  and Python JSON v1 import.
- Versioned config and run-report schemas.
- Synthetic fixture parity and a frozen Python reference oracle.
- A Nix package, checks, and development shell. The release claim is limited to
  x86_64 Linux only after that package is actually built there.

## Excluded

- A web UI, daemon, Prometheus, HTML output, other notification sinks,
  containers, signed binaries, Windows, or public release.
- A reusable NixOS module. Host integration stays in the dotfiles repository.
- DNS canary probes, query logs, top domains, client identities, caches,
  sessions, persistent clients, or undeclared rewrites.
- Every AdGuard `POST`, `PUT`, `PATCH`, and `DELETE` operation.
- Live AdGuard access, real Pushover messages, dotfiles changes, or NixOS
  deployment during MVP implementation.
