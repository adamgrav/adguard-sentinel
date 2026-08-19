# Test plan

This page maps what the suite actually covers, boundary by boundary, and marks
where it does not. `just test` is authoritative for what runs; every test here is
deterministic and contacts no live AdGuard Home or Pushover service.

Rows are marked *thin* where a representative test exists but not the full case
matrix, and *absent* where no test exists yet. Those markers are the useful part:
a coverage map that only listed strengths would be marketing.

## AdGuard request boundary

- Every observation is one of the six allowlisted GETs, and no other path is
  requested.
- Unknown response fields are ignored, as ADR 0003 permits for
  forward-compatible patch releases.
- The legacy `upstream_mode = ""` alias normalizes to `load_balance`, an
  explicit mode is preserved unchanged, and whitespace is not the alias.
- Observations fail closed on a redirect, a non-success status, rejected
  authentication, an unsupported version, a stopped server, a malformed body, a
  missing required field, an oversized body, and a request timeout.
- Statistics fail closed on negative processing time, a blocked count above the
  query count, and a duplicated client identity.
- Declared data fails closed on a duplicated upstream set, a duplicated filter
  URL, a required filter updated in the future, an enabled required filter with
  no update time, rewrites that collide after normalization, and an empty
  rewrite domain.
- A failed endpoint aborts that target's remaining requests.
- Proxy environment inheritance is disabled unconditionally in
  `ReqwestAdGuardClient::new`. That is a structural property rather than a test:
  asserting it would require mutating process environment variables, which this
  workspace's `unsafe_code = "forbid"` prevents.

## Policy evaluation

- Required rewrites match after domain and answer normalization, and their
  condition identifiers do not depend on declared spelling, so latches survive a
  configuration reformat.
- A disabled required rewrite, a required rewrite answered differently, an
  absent required rewrite, and a disabled global rewrite setting are each drift.
- Filters and rewrites outside declared policy never produce a finding.
- Required filter absence, state drift, and staleness at the configured age are
  detected.
- One condition id keeps one `kind` across all four filter outcomes and across a
  reachable and an unreachable target, and only `reason` varies.
- Every evaluation of a fully compliant target is clear and no clear summary
  contains the failure phrasing it ruled out.
- Latency comparisons are strictly greater-than at their exact boundary.
- Configuration schema, size, cross-reference, URL, duration, and secret-file
  validation. *thin*

## Behavior and state

- Alerts latch once and resolve once. A not-evaluated outcome freezes a firing
  latch without advancing or clearing it.
- A firing, delivered latch fed a renamed kind, reason, and summary emits no
  transition, keeps its lifecycle and delivery state, continues its counter
  rather than restarting it, and keeps its first-observed timestamp.
- Aggregate thresholds are clear at equality and active above it.
- SQLite creation with private permissions, refusal of a newer schema, rollback
  after an interrupted transaction, live and dry-run state binding, retention at
  the inclusive cutoff, and notification backoff before delivery.
- An evaluation persisted by 0.1.0 still deserializes, with the pre-rename
  counter names honoured and `reason` defaulted, so `report` keeps working
  against an existing state database. The current field names round-trip.
- Injected time covers both Amsterdam DST edges.
- A regressed wall clock fails before the run is recorded, leaving the earlier
  run as the only persisted one.
- Learning-boundary time injection. *absent*
- A rejected password records a cooldown, the next run inside it makes no AdGuard
  request at all, a later run resumes observation, and a complete observation
  clears the cooldown rather than letting it merely expire.
- Notification batching order and the rule that a behavior group advances only
  when every member is complete. *absent*

## CLI

Exit codes are the systemd and job-health contract, so each one is exercised
end to end through `check` with an injected clock and a mock AdGuard server.

| Code | Covered by |
| --- | --- |
| `0` | A healthy run with no findings and no transitions |
| `1` | An active warning with `--fail-on warning`, and *not* with `--fail-on error` |
| `2` | An unparseable configuration, a zero or oversized report limit, `--format json` with more than one report, and an invalid `--since` |
| `3` | An unreachable target leaving zero complete targets |
| `4` | A retryable Pushover response, and an ambiguous one |
| `5` | A regressed wall clock, and an absent state database |

Every documented code also has a distinct reason string.

- A dry run never loads notification credentials, and its run is recorded in
  dry-run mode.
- Pushover classification for confirmed success and for retryable versus
  permanent HTTP failures, at the unit level and through a mock endpoint.
- A confirmed delivery records the remote request identifier.
- An ambiguous delivery is recorded as unknown and is never resent on a later
  run, because the outbox only re-selects pending and retryable rows.
- A request carries exactly the declared Pushover fields: the application token,
  the user key, a title, a message, and a priority.
- A sustained condition alerts at normal priority, its recovery resolves once at
  quiet priority `-1`, and a third healthy run sends nothing further.
- No credential reaches a persisted report. Distinct sentinel secrets are
  asserted absent from the serialized report for both a permanently rejected
  notification and a rejected AdGuard password, along with any `Basic ` header
  material.
- A persisted report carries every property the checked-in run-report schema
  requires, declares no property the schema does not, pins both schema versions
  to `1`, and round-trips back through `RunReport`. Because the schema is
  generated from those types and `just schema-check` proves it has not drifted,
  and because every report type denies unknown fields, a round trip is
  equivalent to validation without adding a JSON Schema validator dependency.
- Golden byte-for-byte JSON and JSONL output. *absent*
- Migration tests per released schema version. *absent*; v1 has no predecessor.

## Notification transport

Delivery outcomes separate "definitely not sent" from "possibly sent", which is
what ADR 0006 rests on. A refused connection before any response is retryable. A
timeout after transmission, and an oversized response body, are both ambiguous
and therefore never resent automatically.

`PushoverClient::from_config` is the only constructor reachable outside tests and
always uses the fixed production endpoint. A `#[cfg(test)]` constructor accepts
an endpoint so delivery can be exercised against a mock server; it does not
exist in a release build. `check_with_sink` accepts an already-built client for
the same reason, and the production path passes `None`, which preserves the rule
that credentials are read only when a message is actually pending.

## Fixtures

`testdata/PROVENANCE.md` records every fixture, its purpose, and the reference
instant that timestamped fixtures are relative to. The golden set describes one
healthy resolver matching the declared `home` policy in `config.example.toml`, so
those two files are asserted against each other and cannot drift apart silently.

## Live acceptance outside this repository

The test suite contacts no live AdGuard Home or Pushover service, so it cannot
prove a deployment. Live acceptance is the operator's responsibility and
requires a real package build on the monitor host, one successful read-only
observation of every configured target, an isolated alert/recovery exercise, and
twelve consecutive successful timer runs. Service installation, external
job-health reporting, real notification delivery, and rollback are owned by the
host configuration, not by this repository. See `docs/DEPLOYMENT.md`.
