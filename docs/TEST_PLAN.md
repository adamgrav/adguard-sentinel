# Test plan

## Deterministic checks

- Configuration schema, size, cross-reference, URL, duration, and secret-file
  validation.
- Strict API decoding for missing, malformed, negative, non-finite, duplicate,
  and unsupported data.
- Recorded method/path assertions for every allowlisted operation and explicit
  query-log/mutation negative checks.
- Behavior tests for auth cooldowns, sustain/recovery thresholds, aggregation,
  retention, robust bounds, batching, and state evolution.
- Policy findings for upstreams, filters, freshness, rewrites, and protection.
- SQLite creation, refusal of unsupported versions, rollback after interrupted
  transactions, retention, and outbox outcomes.
- Injected time for learning boundaries, clock regression, and both DST edges.
- CLI JSON output validated against the checked-in schema.

## Live acceptance outside this repository

Live acceptance requires a real x86_64-Linux package build on the monitor host,
one successful read-only observation of every configured target, an isolated
alert/recovery exercise, and twelve consecutive successful five-minute timer
runs. A separate task owns NixOS integration, operator-run build/switch,
Healthchecks verification, test notifications, and rollback.
