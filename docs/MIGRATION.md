# State migration

## SQLite

Migrations are explicit and transactional. The running `check` command never
upgrades an existing schema. Each future released schema must include forward
fixtures from every prior version and preserve a pre-migration backup.

Schema v1 has no predecessor. `migrate-state --state PATH` creates or validates
the current database and refuses unsupported versions. It does not infer,
convert, or delete external state.

The first deployment starts a fresh behavioral baseline. This is intentional:
operational and policy findings are immediately active, while query-volume and
blocked-ratio findings wait for their configured learning window.
