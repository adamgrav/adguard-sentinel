# ADR 0007: Time and baselines

Status: accepted.

Wall and monotonic time are injectable. Stored timestamps are UTC RFC3339;
baseline hour classification uses the configured IANA zone. A regressed wall
clock does not advance or prune state. Repeated DST hours share their wall-hour
bucket and skipped hours produce no samples, matching the Python contract.
