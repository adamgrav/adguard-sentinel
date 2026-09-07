# Test coverage

`nix develop -c just check` runs formatting, Clippy, tests, build, schema drift,
and supply-chain checks. `just test` runs the Rust suite. Tests use synthetic
fixtures and local mock servers; none contacts a live AdGuard Home or Pushover
service. [PROVENANCE](../testdata/PROVENANCE.md) records fixture sources and time.

## Coverage by boundary

| Boundary | Covered behavior | Source |
| --- | --- | --- |
| AdGuard transport | Six fixed GETs; Basic and no-auth headers; unsupported versions; rejected auth; redirects; failed, oversized, malformed, or timed-out responses; aborting later requests after failure | [sentinel-adguard](../crates/sentinel-adguard/src/lib.rs) |
| Response decoding | Required fields, invalid counters and latency, duplicate clients/upstreams/filters/rewrites, legacy load-balance alias, filter timestamps, and unknown extra fields | [sentinel-adguard](../crates/sentinel-adguard/src/lib.rs) |
| Configuration | Minimal no-auth configuration, default sections, Basic compatibility, required credentials, optional policy fields, and rejection of unknown fields | [config](../crates/sentinel-core/src/config.rs) |
| Policy | Independent declarations, normalized identities, required filter/rewrite drift, global rewrite dependency, all protection combinations, stable kinds, and clear summaries | [analysis](../crates/sentinel-core/src/analysis.rs) |
| Behavioral measurements | Counter resets, long gaps, integer differences, rate threshold equality, collapse detection, complete historical groups, duplicate members, same-second ordering, and historical/current sum overflow | [analysis](../crates/sentinel-core/src/analysis.rs) |
| Behavioral populations | Window-based readiness, independent rate/ratio populations, per-target conditions, low-query windows, and specific not-evaluated reasons | [analysis](../crates/sentinel-core/src/analysis.rs) |
| Latches | Sustain/recovery, frozen not-evaluated state, retained withdrawn declarations, stable identity across presentation changes, and one alert/resolution per episode | [analysis](../crates/sentinel-core/src/analysis.rs), [CLI](../apps/sentinel-cli/src/main.rs) |
| Persistence | Private database creation, schema checksum, future-schema refusal, rollback, live/dry-run binding, inclusive retention, retry backoff, and pending batch ordering | [store](../crates/sentinel-store/src/store.rs) |
| Time and cooldowns | Both Amsterdam DST edges, regressed-clock rejection without a recorded run, and auth cooldown with no requests until retry | [analysis](../crates/sentinel-core/src/analysis.rs), [CLI](../apps/sentinel-cli/src/main.rs) |
| Notification transport | Success requires status and request ID; retryable/permanent/unknown outcomes; timeouts and oversized responses; fixed payload fields; credential exclusion; no resend after ambiguity | [notification adapter](../apps/sentinel-cli/src/notify.rs), [CLI](../apps/sentinel-cli/src/main.rs) |

Proxy inheritance is disabled structurally by `.no_proxy()`; there is no test
that launches the client under hostile proxy environment variables.
Configuration validation has representative cases, not an exhaustive bounds and
cross-reference matrix.

## CLI and reports

CLI tests exercise exit `0` for healthy runs, `1` for matching `--fail-on`
severity, `2` for invalid configuration or report arguments, `3` for no complete
target, `4` for retryable/ambiguous notification attempts, and `5` for state and
clock errors. They also cover omitted behavioral configuration and v0.1.3 target
evaluation compatibility.

The report test checks required and undeclared **top-level** properties against
the generated schema, then round-trips through `RunReport`. The schema drift
check independently compares generated files. Neither performs recursive JSON
Schema validation. Older evaluation field names and the missing `reason` default
have dedicated [model tests](../crates/sentinel-core/src/model.rs).

## Notification regressions

- `enabling_notifications_does_not_resolve_a_suppressed_alert` persists an alert
  with delivery disabled, enables delivery, observes recovery without sending,
  and verifies that a new episode can alert normally through a mock provider.
- `dry_and_disabled_runs_keep_simulated_resolutions` retains the dry-run and
  disabled-provider acceptance behavior.
- `pending_batches_keep_age_order_and_send_alerts_first_at_equal_times` uses
  deliberately inverted message IDs to verify that older work stays first and
  equal-time alert batches precede resolutions.

The two defect regressions were observed failing against the previous behavior
before their fixes. Existing mock-provider tests cover confirmed alert delivery
followed by one quiet resolution.

## Remaining gaps

- Exact learning-age boundary tests and a full configuration-boundary matrix.
- End-to-end orchestration with an incomplete multi-target group; historical
  missing/duplicate-member handling is covered at the core boundary.
- Recursive JSON Schema validation and byte-for-byte JSON/JSONL goldens.
- Released-schema migration fixtures; SQLite v1 currently has no predecessor.
- Linux execution of the documented systemd credential/unit setup. Static unit
  review and macOS tests do not establish it. The manual
  [credential probe](../tools/check-systemd-credentials.sh) uses synthetic files
  and runs only configuration validation.

Live resolver, timer, job-health, and real notification acceptance follows
[DEPLOYMENT](DEPLOYMENT.md#inspect-and-accept). Behavioral calibration supports
the maintainer's recorded traffic and synthetic injections, not universal
false-positive or detection rates; see [ADR 0012](decisions/0012-behavioral-conditions-measure-rates.md#evidence-and-limits).
