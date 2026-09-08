# Troubleshooting

Diagnostics go to stderr; reports go to stdout. `RUST_LOG=debug` enables more
logging. Keep reports and debug logs private: they can contain resolver names,
URLs, counters, and policy evidence.

## Inspect a recorded run

```sh
adguard-sentinel report --state state.sqlite3 --limit 1
adguard-sentinel report --state state.sqlite3 --limit 1 --explain
```

Use the service's state path and an identity allowed to read it. Reporting is
read-only and makes no network requests. The concise view shows target status,
separate rate and ratio baseline readiness, findings, and notification outcomes.
`ready` means a baseline is trained, not that its condition is clear. A trained
baseline can still have an unavailable or too-small current window. A missing
evaluation supplies no readiness claim.

Delivery lines include the attempt and origin-run IDs for work handled by this
run. They can explain exit `4` even when no notification originated here.
JSON exposes the same snapshots in `delivery_activity[]`; see
[delivery records](SCHEMAS.md#delivery-records).

`--explain` adds every recorded condition's outcome and reason, expected and
observed evidence, sustain/recovery counts, and notification latch. For learning
conditions, the evidence includes population counts and gates; evaluated
conditions include their measurements and thresholds. Not-evaluated conditions
hold their counters. This view reports stored evidence; it does not recalculate
old runs using the current configuration.

`--explain` requires human output. For automation, use `--format json --limit 1`
or `--format jsonl`; both already contain the condition evidence. An empty
notification/activity list does not establish that the outbox has no older
pending or quarantined message.

## Exit codes

| Code | Meaning | Action |
| --- | --- | --- |
| `0` | Minimum complete-target count met, with no other selected failure | Inspect findings separately; some targets may still be incomplete |
| `1` | A finding met the `--fail-on` threshold | Inspect its outcome and evidence; use the default `never` for the service |
| `2` | Invocation or configuration error | Check the diagnostic, arguments, configuration, and referenced files |
| `3` | Minimum complete-target count not met | Inspect incomplete targets below |
| `4` | A notification attempt was not confirmed | Inspect delivery status below |
| `5` | State could not be opened, validated, or persisted | Check the state path, permissions, schema, and clock |

Findings and execution health are separate. `--fail-on` defaults to `never`, so
an active finding need not fail a run. Exit `3` can still result from unavailable
resolvers. Set `minimum_complete_targets` to the availability requirement for
your deployment; a value of one permits a successful run with another target
incomplete.

## An incomplete target

Use `check --format json` or `report --format json` and inspect
`targets[].status`, `error_kind`, and `error_detail` locally.

| Status | Meaning | Check |
| --- | --- | --- |
| `unavailable` | Connection failure, timeout, redirect, or non-success HTTP status | Resolver reachability, proxy routing, and request timeout; redirects are not followed |
| `authentication_rejected` | HTTP 401 or 403 | Basic credentials, or the access policy for no-auth mode |
| `authentication_cooldown` | Requests paused after a rejection | Recorded retry time and the configured cooldown |
| `unsupported_version` | Version outside the configured requirement | The version range in [SUPPORT](SUPPORT.md#adguard-home) |
| `invalid_response` | Required data failed strict validation | The specific field named in `error_detail` |
| `response_too_large` | Body exceeded `max_response_bytes` | Response size and cause before increasing the limit |

Common invalid-response diagnostics include blocked counts above query counts,
negative latency, duplicate normalized clients or upstreams, missing required
fields, a stopped server, and invalid rewrite entries. A required filter's
future update timestamp suggests clock skew; an enabled filter without an
update time may never have downloaded. Unknown extra fields are permitted.

After authentication rejection, no request reaches that target during
`authentication_retry_seconds` (900 by default). Correct the credentials or
access policy and wait for the retry time. A complete observation clears the
recorded rejection. Retain the database to preserve history and latches.

## Configuration or service startup fails

- `missing field 'retention_days'`: you supplied `[state]` without all its fields.
  Most tables default only when omitted; see [SCHEMAS](SCHEMAS.md#configuration-v1).
- A second `[state]` table: edit the existing table in a dry-run copy instead of
  appending another.
- `cannot read configuration`: the service may be trying to read a root-owned
  `0600` file directly. Use the deployment guide's `LoadCredential=config:...`
  and `--config %d/config` pairing.
- Missing `/run/credentials/...` files during manual validation: those paths
  exist only while the named unit runs. Validate inside the unit, or use a
  separate manual configuration with readable secret source paths.
- `inactive (dead)` after a oneshot: inspect `Result`, `ExecMainStatus`, and the
  journal. A completed successful run normally leaves no process running.

[DEPLOYMENT](DEPLOYMENT.md#run-with-systemd) gives the unit and inspection commands.

## State errors

| Diagnostic | Action |
| --- | --- |
| `state parent directory does not exist` | Create the directory, or use the service's `StateDirectory` |
| `cannot open or use state database` | Check ownership and writable paths; use the service identity or privileged reporting for private state |
| `state schema v1 requires explicit migration` | Stop writers and follow [MIGRATION](MIGRATION.md) |
| `state schema version N is unsupported; expected 2` | Check the binary and state versions; only v1-to-v2 migration is supported |
| `state database is already in use` | Wait for the existing check or migration to finish; overlapping checks fail before resolver requests |
| `unversioned nonempty SQLite state is not supported` | Select a dedicated Sentinel database |
| Database bound to a different run mode | Give live and dry-run observations separate databases |
| `wall clock regressed behind the latest completed run` | Correct the clock and retry; the rejected run was not recorded |

A database is bound to live or dry-run use after its first run. Dry-run still
writes observations and advances its own latches. Discarding a database loses
all history, latches, and learned baselines; it is not a routine repair step.

The adjacent `.lock` file remains after a process exits; its existence does not
mean ownership is held. Do not unlink it to bypass contention. A killed process
releases ownership automatically, and reports can read committed state while
a writer is running. Hard-linked databases are unsupported.

Unresolved deliveries can retain evidence beyond `retention_days`; see
[retention rules](BEHAVIOR.md#latches-time-and-retention). Migration creates a
separate private backup, so include both state and backups when assessing disk use.

## Notifications

### Nothing was sent

Delivery is disabled by default. With Pushover configured, a condition must cross
its sustain threshold before an alert is queued. Continuing active findings do
not send repeated alerts. Dry-run never loads notification credentials.

Enabling Pushover does not replay alerts suppressed while delivery was disabled,
and their later recovery does not send a real resolution. A subsequent new
condition episode can alert normally. A real resolution requires a confirmed
alert from that episode.

### Delivery failed

| Status | Handling |
| --- | --- |
| `in_flight` | A durable attempt has started but has no committed result; if its process ends, the next check quarantines it as `unknown` |
| `retryable` | A connection failure or Pushover 5xx remains queued for a later run after backoff |
| `unknown` | Possible delivery, such as a timeout, interrupted response, or malformed success response; quarantined without automatic resend |
| `failed` | Permanent rejection; check the configured application token and user key |

For `unknown`, inspect the Pushover app to determine whether it arrived. There is
no automatic retry or reconciliation command. A later run can exit zero while
an earlier unknown entry remains quarantined.

An interrupted-send recovery is recorded in the new run's delivery activity.
Reading reports does not perform recovery. If migration produced
`legacy_delivery_unconfirmed`, v1 could not prove safe replay or complete
delivered membership; [MIGRATION](MIGRATION.md) explains the retained evidence.

Pushover credential values are loaded when a message is pending. Configuration
validation only checks file metadata, so it cannot establish that a token will
be accepted. [DEPLOYMENT](DEPLOYMENT.md#pushover) shows both required files.

## Behavioral conditions are absent or not evaluated

Without `[behavioral_baseline]`, all three group conditions and all per-target
behavioral conditions are absent. With it, each named target has query-rate,
blocked-ratio, and blocking-collapse conditions when its observation is complete.
The group requires every member; its `aggregate` can be null while a complete
member's conditions remain available.

Inspect each condition's `outcome`, `reason`, and evidence:

| Reason | Interpretation |
| --- | --- |
| `baseline_learning` | History age or that population's same-hour window count is insufficient |
| `rate_window_unavailable` | The trained condition has no valid latest pair, for example after decreasing counters or a gap above 600 seconds |
| `window_too_small` | A ratio condition's latest window contains fewer than 100 queries |

`aggregate.baseline_ready` covers only group query-rate readiness. Ratios have a
separate population, so low traffic can leave them learning or unevaluated even
when that flag is true. [BEHAVIOR](BEHAVIOR.md) owns the formulas and gates.

Removing a behavioral or policy declaration retains its latch and sends no
resolution. Restore the same declaration and observe recovery if you want that
episode to resolve; withdrawing a check is not evidence that it recovered.

## Unexpected policy findings

Only declared policy creates conditions. Extra filters and undeclared rewrites
are ignored. A condition's `id` identifies it; `kind` names the check and
`reason` explains the current result.

- `upstream_mode` / `drift`: AdGuard Home's empty-string load-balance alias is
  normalized to `load_balance`; use that value in policy.
- `required_rewrite` / `missing_or_disabled`: the exact normalized domain and
  answer pair is absent or has the wrong enabled state.
- `required_rewrite` / `globally_disabled`: a required enabled entry cannot take
  effect because the resolver's global rewrite switch is off. This check does
  not require a separate policy declaration for the global switch.
- `required_filter` / `stale`: the update is older than `maximum_age_hours`.

Domain casing and trailing dots are normalized and do not change condition IDs.

## Reporting a problem

Include the Sentinel version, installation method, OS/architecture, AdGuard Home
version, exit code, and the relevant status/kind/reason. Add a minimal synthetic
configuration or reproduction when possible.

Do not attach live reports, state databases, API responses, or debug logs.
Replace resolver names, domains, addresses, paths, counts, and policy evidence
with synthetic values before sharing an excerpt; removing credentials alone is
insufficient. Follow the [fixture and reporting rules](../CONTRIBUTING.md#fixtures-and-reports).
Report suspected vulnerabilities privately through [SECURITY](../SECURITY.md).
