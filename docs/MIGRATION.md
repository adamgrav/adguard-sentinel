# State migration

## SQLite

Migrations are explicit and transactional. The running `check` command never
upgrades an existing schema. Each future released schema must include forward
fixtures from every prior version and preserve a pre-migration backup.

Schema v1 has no predecessor. `migrate-state --state PATH` creates or validates
the current database and refuses unsupported versions. It does not infer,
convert, or delete external state.

A first deployment with `[behavioral_baseline]` configured starts a fresh
baseline. This is intentional: operational and declared-policy findings are
immediately active, while query-volume and blocked-ratio findings wait for their
configured learning window. Omitting the section disables those aggregate
observations and conditions entirely.
