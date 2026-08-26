# Changelog

Notable changes to AdGuard Sentinel. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Fixed

- Behavioural conditions now compare a measurement window rather than a raw
  statistics sample. AdGuard Home resets its counter on its own local hour, so a
  sample is a partial hour total whose size depends mostly on when in the hour it
  was taken; on a live deployment the same traffic read as 169 queries just after
  a reset and 10,167 just before one. Both behavioural conditions were
  consequently unable to fire at all, because a ramp sampled uniformly has a
  maximum near twice its median and the threshold was three times it.
- The blocked-ratio condition could not detect blocking failing. Its absolute
  deviation floor of `0.20` was wider than the entire observed range of the
  ratio, and the `8 * scaled_mad` term was between 1.4 and 3.3 times the median
  in every hour, so either alone was enough to hide a collapse to zero. The
  floor is now `0.04` and the multiple `6`, chosen against 7.7 days of live
  samples: no false-positive latch on either resolver across the whole history.
  Six scaled deviations is wider than a collapse to zero can produce, which is
  deliberate — collapse is the business of `blocking-collapsed`, so the deviation
  rule is tuned to stay quiet rather than stretched across both jobs. At four it
  produced a spurious warning about once a week on one resolver, which the group
  average had hidden.

### Added

- Behavioural windows difference integer counts, and the group total is summed
  from its declared members rather than taken from a stored combined ratio.
  Reconstructing a blocked count from a ratio and differencing two of those can
  round to zero, which is indistinguishable from blocking having stopped on a
  condition that pages.
- Per-target behavioural conditions `target:<id>:query-rate`,
  `target:<id>:blocked-ratio`, and `target:<id>:blocking-collapsed`, for targets
  named in `[behavioral_baseline].target_ids`. A group total dilutes a single
  resolver: one of two losing blocking entirely moves the combined ratio by half
  of what it moved on that resolver. Configurations without `[behavioral_baseline]`,
  and targets not named in it, gain no conditions.
- `aggregate:blocking-collapsed`, a critical condition that reports blocking
  having nearly stopped. This is the case a policy check cannot see: protection
  enabled, every declared filter present, enabled, and fresh, and nothing being
  blocked. See [ADR 0012](docs/decisions/0012-behavioral-conditions-measure-rates.md).

### Changed

- `aggregate:query-spike` (kind `combined_query_volume`) is retired and replaced
  by `aggregate:query-rate` (kind `combined_query_rate`), measured in queries per
  second. ADR 0010 requires `kind` to be stable for an `id` across releases, and
  a rate is a different quantity from a count rather than a better measurement of
  it. `aggregate:blocked-ratio` keeps its identifier and kind, because only its
  measurement window changed. Neither retired condition had ever been active, so
  no latch was carried.
- `aggregate_observations.volume_limit` now holds a queries-per-second limit
  rather than a query count, and `ratio_limit` a deviation computed with the new
  multiple. The column and field names are unchanged, so the state schema, its
  checksum, and the run-report schema version all stay as they are; existing
  databases open without migration and the accumulated baseline is not discarded.
- A run whose sample pair spans the hourly counter reset, or a gap longer than
  600 seconds, leaves the behavioural conditions not evaluated rather than
  guessing the elapsed traffic. About one run in eleven on a five-minute timer.

## 0.2.0 — 2026-08-20

Every configuration accepted by v0.1.3 remains valid and keeps the same target
evaluations. The configuration schema stays at version 1 because the changes
only make previously required declarations optional. The run-report schema and
SQLite schema are unchanged; existing state opens without migration and the
state-schema checksum is unchanged.

### Added

- Per-target `auth = "none"`, which loads no resolver credential and sends no
  `Authorization` header. Omitted `auth` defaults to `basic`, preserving the
  v0.1.3 behavior and its file-only password requirement.
- [`config.minimal.toml`](config.minimal.toml), a one-resolver, no-auth
  configuration with notifications disabled by default.
- `aarch64-linux` flake outputs and a native GitHub Actions matrix job on
  `ubuntu-24.04-arm`, which runs the same reproducible checks as `x86_64`. The
  platform is **Verified** in `docs/SUPPORT.md` on the strength of that job's
  green run, not by inference from `x86_64` passing.
- Documentation for direct tagged Git installation with Cargo; crates.io
  publication remains disabled.

### Changed

- `[state]`, `[observation]`, `[condition_profiles]`, and `[notifications]` now
  default to the values in the complete example. A target defaults to the
  `current` condition profile and `allow_insecure_local_http = false`.
- `[behavioral_baseline]` is optional. Omitting it produces no aggregate
  observation or aggregate evaluation rows. Removing the section from a running
  deployment retains any aggregate latch rather than resolving it, the same rule
  ADR 0011 states for withdrawn policy declarations; let the condition resolve
  before removing the section if you want its alert closed.
- A target policy and every field within one are independently optional. An
  omitted declaration produces no policy evaluation rather than a false
  `clear`; [ADR 0011](docs/decisions/0011-omitted-policy-is-not-evaluated.md)
  records the rule.
- The README now starts with the minimal single-resolver configuration; the
  complete example remains the reference for every setting.

### Fixed

- A required rewrite no longer reports `matches_policy` while the resolver's
  global rewrite switch is off. Making `rewrites.enabled` optional allowed a
  policy to declare only `required`, in which case nothing in the report said
  that no rewrite resolved. The rewrite's own condition now reports
  `globally_disabled`; a rewrite declared `enabled = false` is unaffected, and no
  condition is created for the undeclared switch.
- A `protection_enabled = false` declaration is now honoured. The condition
  compared nothing and fired whenever protection was off, so declaring `false`
  produced a permanent critical finding whose own `expected` and `observed` both
  read `false`. `reason` still names the observed state, so a
  `protection_enabled = true` policy — the only value the example ever used —
  reports exactly as before.

### Note when upgrading

- `runs.config_sha256` changes on the first run even when a v0.1.3 configuration
  file is byte-identical, because the fingerprint now includes the defaulted
  `auth = "basic"` field. The fingerprint is audit metadata and is not compared
  across runs.

## 0.1.3 — 2026-08-19

`rusqlite` 0.37 to 0.40, shipped on its own so a rollback of the storage layer is
one version rather than a bundle.

No interface, configuration, state, or behaviour change. The SQLite schema is
unchanged at version 1 and its checksum is unchanged, so an existing database
opens untouched and `migrate-state` is not involved.

### Changed

- `rusqlite` 0.37 to 0.40, which moves the bundled SQLite to `libsqlite3-sys`
  0.38. `sqlite-wasm-rs` and `rsqlite-vfs` arrive as new transitive dependencies
  but are gated to wasm targets and appear in neither the Linux nor the macOS
  dependency graph.

## 0.1.2 — 2026-08-19

Dependency updates only. No interface, configuration, state, or behaviour
change: the report schema, the configuration schema, and the SQLite schema are
all unchanged, and an existing state database opens untouched.

### Changed

- `toml` 0.9 to 1.1, `base64` 0.22 to 0.23, and `sha2` 0.10 to 0.11.
- Digests are encoded to hexadecimal directly rather than through the `digest`
  crate's `LowerHex`, which `sha2` 0.11 no longer provides. The encoding is
  byte-identical and now pinned by tests against independently computed values,
  because two of these digests are load-bearing: condition identifiers embed
  one, and the state schema checksum that every database is validated against is
  another.
- `docs/DEPENDENCIES.md` records the duplicate set after the upgrade. `toml` 1.1
  removes the duplicate `winnow`; `base64` 0.23 adds a duplicate of its own,
  because `reqwest` and `httpmock` still reach 0.22.

## 0.1.1 — 2026-08-19

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
