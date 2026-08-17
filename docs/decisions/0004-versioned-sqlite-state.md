# ADR 0004: Versioned SQLite state

Status: accepted.

SQLite schema v1 is private state. Completed observations, latch changes,
retention pruning, and outbox intents share one transaction. Explicit migrations
carry checksums and refuse newer schemas. WAL is not required for the single
oneshot writer; foreign keys and full synchronous durability are enabled.
