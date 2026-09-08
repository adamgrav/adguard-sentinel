# ADR 0004: Versioned SQLite state

Status: accepted.

SQLite is private state. Completed observations, latch changes, pruning, and
outbox intents share one transaction. V2 preserves unsigned counters as decimal
text and stores run-mode identity independently of retained history. Its
checksummed, explicit v1 migration preserves a private backup; the released v1
SQL remains frozen. [MIGRATION](../MIGRATION.md) owns the upgrade procedure.

A canonical sidecar lock protects the whole observation/delivery operation;
SQLite transactions alone cannot exclude a second process between network
requests. Reports use read-only snapshots. Foreign keys and full synchronous
durability remain enabled; WAL is not required.
