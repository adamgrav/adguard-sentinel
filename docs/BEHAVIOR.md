# Behavior contract

This document owns evaluation and latch semantics. Configuration defaults are in
[config.example.toml](../config.example.toml); report fields are described in
[SCHEMAS](SCHEMAS.md). Update this contract when behavior changes.

## Operational and policy conditions

- Authentication rejection uses the configured sustain count and retry cooldown:
  one observation and 900 seconds by default. No request reaches that target
  during its cooldown; a complete observation clears the recorded rejection.
- API availability, invalid responses, unsupported versions, protection, latency,
  and policy drift use their respective configured sustain counts. Recovery has
  its own count.
- Processing latency is active only above its threshold. Upstream latency uses
  the maximum validated per-upstream average, also with a strict comparison.
- Only declared policy fields create policy evaluations. Omitted fields are
  absent from `evaluations[]`, rather than clear or not evaluated. Extra filters
  and undeclared rewrites do not cause policy findings.
- A required enabled rewrite must match its domain and answer, be enabled, and
  have the global rewrite switch on. This dependency applies even when the
  policy does not declare the global switch. See [ADR 0011](decisions/0011-omitted-policy-is-not-evaluated.md).
- Missing or invalid required AdGuard data makes the affected target incomplete.
  This includes wrong JSON types, invalid counters or metrics, duplicate
  normalized values, blocked counts above query counts, and unsupported versions.

## Behavioral conditions

`[behavioral_baseline]` enables query rate, blocked-ratio deviation, and blocking
collapse for each named target and the group total. A complete target can be
evaluated independently while another member is unavailable. Group evaluation
requires every declared member to be complete. Omitting the section produces no
behavioral conditions and no aggregate observation.

### Measurement windows

A window differences two consecutive readings of integer query and blocked
counts. Query rate is the query difference divided by elapsed seconds; blocked
ratio is the blocked difference divided by the query difference. AdGuard's
hourly counter resets make a raw reading unsuitable as a traffic rate.

A pair yields no window if either counter decreases, the blocked difference
exceeds the query difference, or elapsed time is nonpositive or exceeds 600
seconds. An unavailable window leaves that subject's behavioral conditions not
evaluated. Group readings sum exact counts from distinct declared members for
complete runs; missing members or overflowing sums make the aggregate
unavailable.

Every valid window carries a query rate, including zero. Blocked-ratio and
collapse comparisons require at least 100 queries in the window.

### Learning and thresholds

Each comparison needs both the configured history age and the configured count
of windows ending in the current local-hour bucket. The configured IANA zone
owns hour classification. Rate and ratio populations are separate because
low-traffic windows contribute only to the rate population.

For each population, let `m` be its median and `d` its scaled median absolute
deviation: `max(1.4826 * MAD, 1e-9)`.

| Condition | Active when | Severity |
| --- | --- | --- |
| Query rate | Rate exceeds `max(3 * m, m + 4 * d)` | Warning |
| Blocked ratio | Absolute difference from `m` exceeds `max(0.04, 6 * d)` | Warning |
| Blocking collapse | Ratio is below `0.25 * m` | Critical |

Equality is clear. Blocking collapse measures a large relative decrease in the
blocked ratio; it does not establish that filtering stopped or identify its
cause. It is independent of declared policy, so it can fire while policy matches
or while policy conditions are active. A persistently low-traffic resolver may
never accumulate enough eligible ratio windows to evaluate it.

| Not-evaluated reason | Meaning |
| --- | --- |
| `baseline_learning` | History age or that population's window count is insufficient |
| `rate_window_unavailable` | A trained condition has no valid latest window |
| `window_too_small` | A trained ratio condition's latest window has fewer than 100 queries |

`aggregate.baseline_ready` tracks the group's rate population. It does not prove
that either ratio condition, or any individual target, is ready. Inspect each
condition's outcome and reason. [ADR 0012](decisions/0012-behavioral-conditions-measure-rates.md)
records the design rationale.

## Latches, time, and retention

- Active evaluations advance sustain counts; clear evaluations advance recovery
  counts. Not-evaluated conditions leave both counters and the latch unchanged.
- Removing a policy declaration or the behavioral section retains existing
  latches. Restoring the same condition ID resumes that state. Withdrawal is
  not observed recovery and emits no resolution.
- Stored timestamps are UTC. A regressed wall clock does not advance or prune
  state. Repeated DST hours share a wall-hour bucket; skipped hours have none.
- Retention includes samples at the cutoff. Only complete target observations
  become target samples; aggregate rows require a complete group.

## Notifications

Transitions are grouped into alert and resolution batches, with summaries only;
structured evidence stays in reports and state. Pending delivery is ordered by
creation time, with alerts before resolutions at the same time. Message ID
breaks remaining ties.

An ambiguous attempt is quarantined and never resent automatically. A real
resolution is eligible only after confirmed alert delivery. Dry-run and disabled
notifications record suppressed transitions, including simulated resolutions,
without loading notification credentials. See [ADR 0006](decisions/0006-pushover-delivery-ambiguity.md).
