# ADR 0008: Legacy import and shadow cutover

Status: accepted.

Legacy JSON v1 import is explicit, read-only toward its source, hash-deduplicated,
strictly validated, and all-or-nothing. It preserves valid samples, cooldowns,
counters, and confirmed notification latches. Deployment requires an eight-day
notification-disabled shadow gate and leaves the Python state available for
rollback.
