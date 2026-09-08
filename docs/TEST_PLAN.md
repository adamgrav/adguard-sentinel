# Test coverage

`nix develop -c just check` runs formatting, Clippy, tests, build, schema drift,
documentation, and supply-chain checks. `just test` runs the Rust suite. Tests
use synthetic fixtures and local mock servers; none contacts a live AdGuard Home
or Pushover service. [PROVENANCE](../testdata/PROVENANCE.md) records fixture sources and time.

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
| Persistence | Private creation and v1 backup, checksummed migration, unsupported-version refusal, migration/write-failure rollback, durable live/dry-run binding, unsigned counters, legacy precision barriers, inclusive retention, and retained unresolved delivery evidence | [store](../crates/sentinel-store/src/store.rs), [reliability tests](../crates/sentinel-store/src/reliability_tests.rs) |
| Time and cooldowns | Both Amsterdam DST edges, fractional/offset timestamp ordering and filtering, observation/delivery clock regression, and auth cooldown without requests | [analysis](../crates/sentinel-core/src/analysis.rs), [reliability tests](../crates/sentinel-store/src/reliability_tests.rs), [process tests](../apps/sentinel-cli/src/crash_tests.rs) |
| Notification transport | Success requires status and request ID; retryable/permanent/unknown outcomes; timeouts and oversized responses; fixed payload fields; credential exclusion; no resend after ambiguity | [notification adapter](../apps/sentinel-cli/src/notify.rs), [CLI](../apps/sentinel-cli/src/main.rs) |
| Delivery state | Complete batch membership, oversized Unicode summaries, partial recovery, preserved backoff, recurrence cancellation, episode guards, and conservative legacy delivery migration | [reliability tests](../crates/sentinel-store/src/reliability_tests.rs) |
| Process ownership | Overlapping live/dry writers, symlink aliases, concurrent read-only reporting, killed senders before/after response completion, recovery without resend, and ownership release after death | [reliability tests](../crates/sentinel-store/src/reliability_tests.rs), [process tests](../apps/sentinel-cli/src/crash_tests.rs) |

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

The [public contract tests](../apps/sentinel-cli/tests/contracts.rs) recursively
validate actual CLI output against JSON Schema, reject invalid nested data,
compare parsed JSON/JSONL with persisted reports, and check an incomplete group
whose complete member still has independent evaluations. The validator refuses
external references. The schema drift check separately compares generated files.
Older evaluation field names and the missing `reason` default have dedicated
[model tests](../crates/sentinel-core/src/model.rs).

[Rendering tests](../apps/sentinel-cli/src/render.rs) distinguish learning,
unavailable and low-traffic windows, incomplete observations, sustain/recovery
progress, and delivery activity originating in older runs. `--explain` is also
exercised through the CLI.

`just doc-check` checks tracked public Markdown links, anchors, and shell syntax;
it executes the README walkthrough and validates documented configurations using
synthetic files and a loopback resolver. It does not execute installation commands.

## Notification regressions

- `enabling_notifications_does_not_resolve_a_suppressed_alert` persists an alert
  with delivery disabled, enables delivery, observes recovery without sending,
  and verifies that a new episode can alert normally through a mock provider.
- `dry_and_disabled_runs_keep_simulated_resolutions` retains the dry-run and
  disabled-provider acceptance behavior.
- `pending_batches_keep_age_order_and_send_alerts_first_at_equal_times` verifies
  that older work stays first and equal-time alert batches precede resolutions.

## Remaining gaps

- Exact learning-age boundary tests and a full configuration-boundary matrix.
- JSON/JSONL byte-for-byte goldens; current checks compare parsed values.
- Power-loss and filesystem failure behavior beyond SQLite write-failure injection.

The [Linux acceptance harness](../tools/check-linux-deployment.py) exercises
the shipped units in a disposable systemd environment: credentials, private
state, hardening, timeout/restart, overlap, timer activation, and migration as
the service user. Its CLI-only mode also runs on macOS. The existence of this
harness or a passing macOS run
does not prove native systemd execution; use CI results and
[SUPPORT](SUPPORT.md) for recorded platform evidence.

Live resolver, timer, job-health, and real notification acceptance follows
[DEPLOYMENT](DEPLOYMENT.md#inspect-and-accept). Behavioral calibration supports
the maintainer's recorded traffic and synthetic injections, not universal
false-positive or detection rates; see [ADR 0012](decisions/0012-behavioral-conditions-measure-rates.md#evidence-and-limits).
