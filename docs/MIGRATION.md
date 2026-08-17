# State migration

## SQLite

Migrations are explicit and transactional. The running `check` command never
upgrades an existing schema. Each future released schema must include forward
fixtures from every prior version and preserve a pre-migration backup.

## Python JSON v1

```sh
adguard-sentinel migrate-state \
  --legacy-json /path/to/state.json \
  --state /path/to/state.sqlite \
  --config /path/to/config.toml
```

The importer reads and hashes the JSON, validates every record and target
mapping, creates a private temporary SQLite sibling, imports samples, latest
observations, cooldowns, counters, and delivery latches in one transaction, then
atomically renames the new database. Any invalid or unknown record rejects the
whole import. The source is never renamed, rewritten, or removed.

Legacy `notified=true` means assumed delivered because Python only writes that
flag after successful Pushover return. Unknown first-observed timestamps remain
null rather than being fabricated.
