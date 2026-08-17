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
  -> secret-file loading
  -> bounded target observation
  -> strict response normalization
  -> per-target evaluation
  -> explicit-group behavioral evaluation
  -> atomic run/state/outbox transaction
  -> notification delivery after commit
  -> versioned report and exit status
```

Targets are observed concurrently under one semaphore. Requests within one
target are sequential and can only call typed GET methods. Target data is not
combined except for the configured query-volume and blocked-ratio baseline.

The store persists normalized observations and condition state. A completed run
is inserted with its evaluations, latch changes, pruning, and notification
intents in one transaction. Network notification attempts happen only after
that commit and use short result transactions.

The CLI is the only application boundary. Domain errors remain typed below it.
Clocks, the AdGuard reader, notification sink, and state repository are
injectable. All project crates forbid unsafe Rust.

## Panic policy

No panic may be reachable from external data. Every AdGuard response, Pushover
response, configuration file, and state database is handled with typed errors.
The remaining non-test `expect` calls are limited to invariants established
earlier in the same function or by configuration validation that has already
succeeded:

- Policy, condition-profile, password, and per-target report lookups in the CLI
  are keyed by identifiers that `Config::validate` has already proved present and
  unique.
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
