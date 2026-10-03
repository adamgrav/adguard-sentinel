# ADR 0013: Upstream latency measures pooled response windows

Status: accepted. Extends ADR 0012.

## Problem

`AdGuard Home` reports each upstream's average over the current hourly
statistics unit; `recent=3600000` returns that partial unit only. Early in the
hour, an average rests on a few responses, which dominate it until enough
others arrive or the unit ends. Load balancing sends few queries to a slow
upstream, so its average had the fewest samples and decided the condition,
producing alerts that resolved at hour boundaries. The alert also did not name
the upstream.

## Decision

Retain each upstream's response count from `top_upstreams_responses` and
recover its summed duration from the average. Difference consecutive readings,
as ADR 0012 does for queries, and pool the windows ending within the last 30
minutes. Compare the slowest upstream with at least 20 pooled responses against
the configured threshold, and name it, with its average and count, in the
active summary.

A window is unavailable when its readings lie in different statistics units,
any count or duration decreases, or they are more than 600 seconds apart.
Counters alone do not reveal a reset: a rarely used upstream can answer more
queries just after the hour than before it. A reading's unit is known only when
its run started and completed within it, because the statistics were read at
an unrecorded moment between the two. `AdGuard Home` truncates the response and
duration lists independently at 100 entries, so a response list at that limit
makes the reading's counts unknown. No valid window, or no upstream with enough
responses, leaves the condition not evaluated; its latch is unchanged.

Both values are fixed rather than configured. Configuration v1 has no field for
them, and a new configuration schema is not justified before deployment
evidence shows that either value needs per-site tuning.

## Evidence and limits

The values were chosen from one deployment's traffic and incident, not from a
replay. Pooling delays detection: the pooled average crosses the threshold only
once slow windows dominate the lookback, and the sustain count applies after
that. The two overlap: one burst of 20 slow responses keeps the pooled average
above the threshold until it leaves the lookback, so it alone can satisfy the
sustain count. An upstream that answers fewer than 20 uncached queries in 30
minutes is not compared; a low-traffic resolver can leave the condition not
evaluated overnight. Failed upstream attempts are excluded from `AdGuard Home`
statistics, so a failing upstream shows fewer responses rather than higher
latency; this condition does not detect it.

## Identity and state

The condition keeps `target:<id>:upstream-latency` and kind `upstream_latency`,
so existing latches continue. State v3 adds a nullable count column. Readings
stored before v3 have no count and cannot start a window, so the first
evaluation after migration follows two complete v3 readings.
