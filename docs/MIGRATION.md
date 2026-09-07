# State migration

`check` creates new SQLite v1 state but never upgrades an existing schema.
`migrate-state --state PATH` currently creates or validates v1 and refuses other
versions. There is no older Sentinel schema to migrate, and the command does not
convert external monitor state.

Future SQLite upgrades must be transactional, preserve a pre-migration backup,
and have fixtures from every supported predecessor. Before replacing a binary,
read [CHANGELOG](../CHANGELOG.md) for upgrade and rollback requirements.

Behavioral windows are derived from stored target counters, so 0.3.0 reuses
existing samples without a state migration. Historical report interpretation
and pre-1.0 compatibility are described in [SCHEMAS](SCHEMAS.md#historical-reports)
and [RELEASING](../RELEASING.md#compatibility).
