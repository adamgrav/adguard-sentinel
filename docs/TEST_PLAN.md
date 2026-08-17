# Test plan

## Deterministic checks

- Configuration schema, size, cross-reference, URL, duration, and secret-file
  validation.
- Strict API decoding for missing, malformed, negative, non-finite, duplicate,
  and unsupported data.
- Recorded method/path assertions for every allowlisted operation and explicit
  query-log/mutation negative checks.
- Python parity for auth cooldowns, sustain/recovery thresholds, aggregation,
  retention, robust bounds, batching, and state evolution.
- Policy findings for upstreams, filters, freshness, rewrites, and protection.
- SQLite creation, refusal of unsupported versions, rollback after interrupted
  transactions, retention, outbox outcomes, and legacy import atomicity.
- Injected time for learning boundaries, clock regression, and both DST edges.
- CLI JSON output validated against the checked-in schema.

## Live acceptance outside this repository

Live acceptance requires an eight-day shadow window with at least 2,189 of
2,304 scheduled runs paired within 90 seconds, no unexplained mismatches, and no
non-GET AdGuard requests. A separate task owns NixOS integration, operator-run
build/switch, Healthchecks verification, test notifications, and rollback.
