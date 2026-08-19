# Changelog

Notable changes to AdGuard Sentinel. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

Nothing yet.

## 0.1.1 — unreleased

Report presentation and configuration-message fixes, all found during the first
live deployment. Nothing here requires a change on your side: a 0.1.0
configuration still validates, a 0.1.0 state database is still read, and the
state schema is unchanged at version 1.

The run-report `schema_version` stays `1`. Two fields are renamed and the values
`kind` takes have changed, which the pre-1.0 caveat in
[RELEASING.md](RELEASING.md) now covers explicitly. Anything consuming
`evaluations[]` or `findings[]` needs the table below.

### Changed

- **`kind` is now stable for a given condition `id`.** One condition previously
  reported a different kind depending on what it found, so a single filter
  condition alternated between `required_filter_stale` and
  `required_filter_state_drift` across runs, and anything grouping by kind saw
  several conditions where there is one. `kind` now names what was checked; the
  divergence moved to the new `reason` field. The invariant is recorded as
  [ADR 0010](docs/decisions/0010-condition-identity-and-phrasing.md), which also
  records why `severity` deliberately does vary for one condition.

  | Old `kind` | New `kind` | New `reason` |
  | --- | --- | --- |
  | `api` | `api` | `available` |
  | `api_unavailable` | `api` | `unavailable` |
  | `authentication_rejected` | `api` | `authentication_rejected` |
  | `invalid_response` | `api` | `invalid_response` |
  | `unsupported_version` | `api` | `unsupported_version` |
  | `protection_disabled` | `protection` | `disabled`, or `enabled` when clear |
  | `processing_latency` | `processing_latency` | `above_threshold`, `within_threshold` |
  | `upstream_latency` | `upstream_latency` | `above_threshold`, `within_threshold` |
  | `upstream_mode_drift` | `upstream_mode` | `drift`, `matches_policy` |
  | `upstream_set_drift` | `upstream_set` | `drift`, `matches_policy` |
  | `rewrite_settings_drift` | `rewrite_settings` | `drift`, `matches_policy` |
  | `required_filter` | `required_filter` | `matches_policy` |
  | `required_filter_missing` | `required_filter` | `missing` |
  | `required_filter_state_drift` | `required_filter` | `state_drift` |
  | `required_filter_stale` | `required_filter` | `stale` |
  | `required_rewrite_drift` | `required_rewrite` | `missing_or_disabled`, `matches_policy` |
  | `combined_query_volume_anomaly` | `combined_query_volume` | `above_baseline`, `within_baseline`, `baseline_learning` |
  | `combined_blocked_ratio_anomaly` | `combined_blocked_ratio` | `outside_baseline`, `within_baseline`, `baseline_learning` |

- **`summary` is chosen from the outcome rather than from the condition.** A
  clear row used to assert the failure it had ruled out, so a filter 1.9 hours
  old under a 72 hour limit read as "has a stale required filter", and protection
  that was enabled read as "protection is disabled". A clear row now reads as the
  pass. Resolution notifications improve for the same reason: a resolution says
  the condition cleared instead of restating the alert.
- **`evaluations[].active_count` and `evaluations[].clear_count` are now
  `consecutive_active` and `consecutive_clear`**, which is what `findings[]`
  already called them. One concept, one spelling. The SQLite columns keep their
  names, so no state migration is involved.
- Human `check` output names the kind and reason alongside each finding.

### Added

- `reason` on `evaluations[]` and `findings[]`: a machine-readable value for what
  the check found. Absent from reports persisted by 0.1.0, which read back as
  `unrecorded`.
- `observation.allow_untested_adguard_version`, defaulting to `false`. The
  AdGuard Home version requirement was previously pinned to the single tested
  range by validation, with no way past it: an older server was unusable and a
  future `0.108.0` would have stopped every deployment. A different range can now
  be configured deliberately, and every run warns that it carries no evidence.
  Enforcement at the request boundary is unchanged.
- Configuration errors name the offending value. `target "maxwell" references
  unknown policy` is now `... unknown policy "nope"`, and the same applies to
  condition profiles, filter URLs, rewrites, behavioural baseline target ids, and
  each out-of-range condition profile count.

### Note when upgrading

- `runs.config_sha256`, the configuration fingerprint each report records, changes
  on the first 0.1.1 run even if your configuration file is byte-identical: the
  fingerprint covers the new `allow_untested_adguard_version` field. It is
  recorded for audit only and nothing compares it across runs, so this needs no
  action. Expect the value to differ from every 0.1.0 run in the same database.

### Fixed

- Doubled error text. `cannot inspect configuration /path: No such file or
  directory (os error 2): No such file or directory (os error 2)` interpolated a
  source that the error chain then printed again. Five error variants across the
  configuration and state layers did this.

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
