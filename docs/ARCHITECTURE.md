# Architecture

## Workspace

```text
crates/
  sentinel-core/       configuration, reports, analysis, findings, latches
  sentinel-adguard/    fixed read-only client and strict response decoding
  sentinel-store/      SQLite schema, migrations, retention, state and outbox
apps/
  sentinel-cli/        CLI, orchestration, Pushover, exit arbitration
```

## Data flow

```text
TOML validation
  -> exclusive state ownership and live/dry-run check
  -> optional secret-file loading
  -> bounded target observation
  -> strict response normalization
  -> per-target operational and declared-policy evaluation
  -> optional per-target and explicit-group behavioral evaluation
  -> atomic run/state/outbox transaction
  -> durable attempt claim, then notification delivery
  -> atomic attempt result and episode delivery update
  -> versioned report and exit status
```

Targets are observed concurrently under one semaphore. Requests within one
target are sequential and can only call typed GET methods. Target data is not
combined except for the configured group's query-rate, blocked-ratio, and
blocking-collapse evaluations. Group members also have independent behavioral
evaluations.

The store persists normalized observations and condition state. A completed run
is inserted with its evaluations, latch changes, pruning, and notification
intents in one transaction. Each send first commits an `in_flight` attempt;
its result and episode delivery state then commit atomically. An unfinished
attempt is quarantined on the next check. Origin-owned notification records
and executing-run delivery snapshots remain separate.

A canonical adjacent `.lock` file excludes other writers for the entire
observation and delivery operation, including access through symlink aliases.
Read-only reports use a SQLite snapshot and do not take writer ownership.
The lock file stays in place when ownership is released. SQLite v2 stores
unsigned counters losslessly and binds live/dry-run mode independently of run
retention. [MIGRATION](MIGRATION.md) owns upgrades and backups.

The CLI is the only application boundary. Domain errors remain typed below it.
Clocks, the AdGuard reader, notification sink, and state repository are
injectable. All project crates forbid unsafe Rust.

## Panic policy

No panic may be reachable from external data. Every AdGuard response, Pushover
response, configuration file, and state database is handled with typed errors.
The remaining non-test `expect` calls are limited to invariants established
earlier in the same function or by configuration validation that has already
succeeded:

- Condition-profile and per-target report lookups in the CLI are keyed by
  identifiers that `Config::validate` has already proved present and unique.
- The two single-entry map reads in the AdGuard decoder are guarded by an
  explicit length check on the line above.
- Serializing a condition's expected and observed values, and fingerprinting a
  configuration, operate on types that cannot fail to serialize. Paths reach
  those types only from TOML, which is UTF-8 by definition.
- The state schema version converts a compile-time constant.

Adding an `expect` outside those categories is a change to this policy and needs
a typed error instead.

## Evidence boundaries

Fixture and mock-server checks prove deterministic domain and transport
properties. Nix evaluation proves only evaluability. Package builds prove only
the target actually built. None proves a deployed timer, live credentials,
network reachability, external job-health integration, or production
notification.
