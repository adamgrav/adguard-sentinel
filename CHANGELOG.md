# Changelog

Notable changes to AdGuard Sentinel. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

Nothing yet.

## 0.1.0 — unreleased

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

## Versioning policy

Sentinel follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html), with
the pre-1.0 caveat that a minor bump may break compatibility. Read the changelog
before upgrading.

Four things are versioned independently, and only the first is the release
number:

| Surface | Versioned by | Compatibility rule |
| --- | --- | --- |
| The binary and CLI | The release tag | Pre-1.0: a minor bump may change flags or output |
| Configuration | `schema_version` in the TOML | A new schema version is a breaking change and gets a new number |
| Run report JSON | `schema_version` in the report | Additive fields may appear in a patch release; removals and type changes require a new version |
| SQLite state | `PRAGMA user_version` | Upgraded only by `migrate-state`, never implicitly by `check` |

Consequences worth knowing:

- `check` never migrates state. A newer binary meeting older state exits `5` and
  tells you to run `migrate-state`, so an upgrade cannot silently rewrite
  history.
- The supported AdGuard Home API range is part of the compatibility surface.
  Widening it needs evidence against the new version and is at least a minor
  bump.
- Anything `docs/SUPPORT.md` marks **Pending** or **Expected** is not a
  compatibility promise.

### Release process

Releases are tagged `vMAJOR.MINOR.PATCH` from `main` after both CI jobs pass. A
tag is only created once its acceptance evidence exists, so a green tag means the
package built and the suite ran, not that a deployment was validated.

The release date is filled in at tag time; an entry marked "unreleased" has not
shipped.
