# ADR 0007: Time and baselines

Status: accepted.

Wall and monotonic time are injectable. V2 normalizes stored timestamps to UTC
RFC3339 with nine fractional digits, making lexical ordering chronological
across fractional seconds and equivalent offsets. Observation commits and
delivery attempts check for clock regression.

Baseline hour classification uses the configured IANA zone. Repeated DST hours
share their wall-hour bucket and skipped hours produce no samples.
[BEHAVIOR](../BEHAVIOR.md#latches-time-and-retention) owns the time and retention
rules.
