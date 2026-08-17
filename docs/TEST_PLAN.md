# Test plan

This is the target coverage matrix, not a description of current coverage. The
suite today is 29 deterministic tests: one representative case per property
below, biased toward the fail-closed boundaries. Rows marked *thin* have a
representative test but not yet the full case matrix, and rows marked *absent*
have none. `just test` is authoritative.

## Deterministic checks

- Configuration schema, size, cross-reference, URL, duration, and secret-file
  validation. *thin*
- Strict API decoding for missing, malformed, negative, non-finite, duplicate,
  and unsupported data.
- Recorded method/path assertions for every allowlisted operation and explicit
  query-log/mutation negative checks.
- Behavior tests for auth cooldowns, sustain/recovery thresholds, aggregation,
  retention, robust bounds, batching, and state evolution. *thin*
- Policy findings for upstreams, filters, freshness, rewrites, and protection.
  *thin*
- SQLite creation, refusal of unsupported versions, rollback after interrupted
  transactions, retention, and outbox outcomes.
- Injected time for learning boundaries, clock regression, and both DST edges.
  *thin* — one DST case exists; learning boundaries and clock regression do not.
- CLI JSON output validated against the checked-in schema. *absent*
- End-to-end CLI coverage of every documented exit code. *absent*

## Live acceptance outside this repository

The test suite contacts no live AdGuard Home or Pushover service, so it cannot
prove a deployment. Live acceptance is the operator's responsibility and
requires a real package build on the monitor host, one successful read-only
observation of every configured target, an isolated alert/recovery exercise, and
twelve consecutive successful timer runs. Service installation, external
job-health reporting, real notification delivery, and rollback are owned by the
host configuration, not by this repository. See `docs/DEPLOYMENT.md`.
