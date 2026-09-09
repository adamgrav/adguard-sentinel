# ADR 0012: Behavioral conditions measure rates over windows

Status: accepted. Extends ADR 0007 and ADR 0010.

## Problem

AdGuard Home statistics are hourly counters. A reading's size depends on its
position within the hour, so comparing raw readings mixes traffic changes with
sampling phase. The old query-volume threshold did not detect anomalies in the
maintainer's replay. The blocked-ratio rule had a separate problem: its floor
and dispersion threshold hid downward changes in that dataset.

## Decision

Compare windows derived from consecutive integer query and blocked counts.
Use query differences per elapsed second for rate and blocked differences per
query difference for ratio. Do not reconstruct blocked counts from floating
point ratios: subtracting reconstructed totals can turn rounding error into an
apparent zero-blocking window.

Reject pairs with decreasing counters, invalid differences, or gaps above 600
seconds. These windows are unavailable, not estimated. Group readings require
every declared member and checked sums. Each member also gets independent
conditions because aggregation can hide a change on one resolver.

Use separate rate and ratio baseline populations. Every valid window carries a
rate; only windows with enough queries carry a comparable ratio. A sparse ratio
population must neither suppress a trained rate condition nor inherit its
readiness.

Keep blocked-ratio deviation and blocking collapse separate. The first detects
large deviations in either direction; the second detects a large relative fall
and is critical. Their thresholds are in [BEHAVIOR](../BEHAVIOR.md). Neither
condition proves a filtering failure, and neither depends on policy matching.

## Evidence and limits

Thresholds were selected using a replay of one deployment's history, with
synthetic failures injected for detection checks, followed by a live soak.
The replay enforced same-hour population counts but omitted the production
learning-age gate. These results support the selected thresholds on that
history; they do not establish detection or false-positive rates for other
traffic patterns. Low-traffic windows can leave ratio conditions unevaluated.

## Identity and state

Replace `aggregate:query-spike` / `combined_query_volume` with
`aggregate:query-rate` / `combined_query_rate`: a rate names a different
quantity. Keep `aggregate:blocked-ratio` because its kind still names the
quantity being compared. No latch is transferred to the new query-rate ID;
retired conditions retain their stored state under the withdrawal rule.

Raw counters remain persisted and windows are derived on read. SQLite v1 and its
checksum are unchanged. Existing samples remain usable, while historical
readiness fields retain their earlier meaning; see
[SCHEMAS](../SCHEMAS.md#historical-reports). The report changes use the intentional
[pre-1.0 compatibility policy](../../RELEASING.md#compatibility).
