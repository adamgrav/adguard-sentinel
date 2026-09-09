# State migration

`check` creates new SQLite v2 state but never upgrades an existing schema.
`check` and `report` reject v1 until `migrate-state` succeeds. The migration
command creates an absent v2 database, validates existing v2, or upgrades v1;
it does not convert external monitor state or downgrade v2.

## Upgrade v1 to v2

Stop scheduled and manual writers, retain the old binary, and run as the state
owner with write access to the database's directory:

```sh
adguard-sentinel migrate-state --state /var/lib/adguard-sentinel/state.sqlite
adguard-sentinel report --state /var/lib/adguard-sentinel/state.sqlite --limit 1
```

Use the actual service state path; [DEPLOYMENT](DEPLOYMENT.md#upgrade-state)
describes the systemd workflow. Reporting an empty database returns no matching
runs, which does not mean migration failed.

Before changing v1, the command creates and validates an adjacent private
`state.sqlite.v1-UUID.bak` with SQLite `VACUUM INTO`. Success prints its path.
The schema/data migration is transactional: an invalid timestamp, broken
reference, conflicting run modes, or failed write rolls back the upgrade.
Insufficient disk space can prevent backup or migration; keep enough room for
the backup and SQLite's transaction work. A failed attempt can leave a backup
file; do not assume it is complete unless it was validated.

V2 changes two interpretations of legacy state:

- V1 saturated oversized counters at `9223372036854775807`. Target observations
  containing that value are marked `counters_exact = false` and excluded from
  rate-window endpoints. Learning for that target uses only readings after its
  latest ambiguous observation, preventing windows across an unknown reset.
  Normal retention preserves that latest ambiguity marker for each target.
  Historical values remain visible; lost precision cannot be reconstructed.
  New v2 counters preserve the full unsigned range.
- V1 pending/retryable messages become `unknown`, since v1 recorded no durable
  pre-send claim. A delivered batch also becomes `unknown` unless its complete
  payload and membership are provable and a completed HTTP-200 attempt records
  the same nonempty request ID. Only that confirmed alert delivery for the
  current episode preserves eligibility for a real resolution. These
  decisions prevent an upgrade from replaying ambiguous messages or inventing
  delivery evidence.

Legacy state with mixed live/dry-run history is rejected. So is state with
latches but no history establishing its mode. Keep that state for diagnosis;
do not delete history to force migration.

## Rollback

Stop all writers and preserve the v2 database before restoring the validated
v1 backup and old binary together. Do not point the old binary at v2 or merge
post-upgrade state into the backup. Restoring a backup discards later history
and can reintroduce old pending notifications; review that delivery risk before
resuming the old scheduler.

[SCHEMAS](SCHEMAS.md#historical-reports) describes historical reports;
[RELEASING](../RELEASING.md#compatibility) defines compatibility.
