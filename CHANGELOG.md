# Changelog

Notable changes to AdGuard Sentinel. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

Nothing yet.

## 0.1.0 — 2026-08-18

The first release. Everything below is new.

### Added

- Read-only monitoring of independent AdGuard Home resolvers over six
  allowlisted GET operations. No mutation API, no query-log retrieval, no
  telemetry.
- Five commands: `validate-config`, `check`, `report`, `migrate-state`, and
  `print-schema`.
- Per-target operational findings for API availability, authentication,
  protection state, DNS processing latency, and upstream latency.
- Declared-policy findings for upstream mode, the upstream set, required filters
  including staleness, required DNS rewrites, and the global rewrite setting.
  Filters and rewrites outside declared policy are ignored.
- One optional behaviour group with a learned same-hour baseline for combined
  query volume and blocked ratio, using a median and scaled median absolute
  deviation.
- Sustain and recovery latches, so a condition alerts once after it persists and
  resolves once after it clears, rather than on every run.
- Pushover notifications with a transactional outbox. Alerts batch ahead of
  resolutions, resolutions send quietly, and an ambiguous delivery is recorded
  and never resent automatically.
- Versioned SQLite state with a checksummed schema, bounded retention, explicit
  migration, `0600` permissions, and permanent binding to live or dry-run use.
- Versioned JSON and JSONL run reports as the automation interface, with
  checked-in schemas for the configuration, the run report, and the state schema.
- Distinct exit codes for configuration errors, insufficient complete targets,
  unconfirmed notification delivery, and state failures, kept separate from
  finding severity.
- A Nix flake providing the package, checks, formatter, and development shell,
  plus a source build path with rustup on Linux.
- Injectable clock, AdGuard reader, notification sink, and state repository, and
  `unsafe_code = "forbid"` across every crate.

### Security

- Credentials are read from files only, never from arguments or the environment,
  and are held in redaction-safe wrappers. Notification credentials are read only
  when a message is actually pending, so a dry run never touches them.
- Outbound notification payloads carry condition summaries only. Structured
  expected and observed values, and raw error detail, stay in local state and the
  versioned report.
- Requests use rustls, follow no redirects, inherit no proxy from the
  environment, and enforce timeouts and response-size limits.

---

Versioning and release policy lives in [RELEASING.md](RELEASING.md). In short:
four surfaces version independently — the release tag, the configuration
`schema_version`, the run-report `schema_version`, and the SQLite
`user_version` — and `check` never migrates state on its own.
