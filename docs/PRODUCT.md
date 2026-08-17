# Product contract

AdGuard Sentinel is a read-only monitor for independent AdGuard Home resolvers.
It retrieves a fixed set of operational and declared-policy data, rejects
malformed or unsupported responses, persists bounded history, applies sustained
alert and recovery latches, and emits versioned reports and optional Pushover
notifications.

## Invariants

- Resolver observations, histories, authentication cooldowns, and conditions
  remain independent.
- Cross-resolver aggregation occurs only for an explicitly configured behavior
  group. It never implies clustering or synchronization.
- Only declared policy is compared. Extra filters and UI-managed rewrites are
  ignored.
- No AdGuard mutation method, arbitrary endpoint, query-log retrieval,
  synchronization, or remediation exists.
- Missing or invalid required data makes an observation incomplete. It never
  becomes a healthy zero, false, or empty value.
- Observation health, findings, notification delivery, and process exit status
  remain separate.
- Dry-run performs real read-only observations and evolves its selected state
  database, but never loads or sends notification credentials.
- A state database is permanently bound to live or dry-run observations after
  its first non-legacy run, preventing shadow execution from advancing live
  latches.
- SQLite is private runtime state. Versioned JSON is the automation interface.
- There is no telemetry.

## Operator workflow

1. Validate version-1 TOML without network access.
2. Run a dry observation and inspect human or JSON output.
3. Install the recurring systemd oneshot outside this repository.
4. Receive one alert after a sustained condition.
5. Receive one quiet resolution only after a confirmed delivered alert.
6. Inspect bounded resolver, upstream, policy, finding, and notification history.
7. Run explicit state migrations before a newer binary uses old state.

## Success

The product succeeds when multiple independent targets can be monitored without
coupling their state, invalid external data fails closed, the AdGuard transport
cannot express mutation, notification ambiguity is visible, and every runtime
or deployment claim is backed by evidence from that environment.
