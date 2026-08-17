# Versioned formats

## Configuration v1

`schemas/config-v1.schema.json` is generated from the strict Rust configuration
types and has a schema-version constant. Semantic validation additionally owns
cross-references, uniqueness, absolute paths, HTTPS policy, bounds, whole-hour
lookback, filter freshness, and secret-file checks.

## Run report v1

`schemas/run-report-v1.schema.json` is the public automation contract. JSON
contains finite normalized values, explicit nulls for absent observations,
deterministically sorted collections, and no credentials or client/query
identity. JSONL is a sequence of complete v1 report objects.

## SQLite v1

`schemas/state-v1.sql` is canonical private state. `PRAGMA user_version` and a
checksummed migration row must both equal one. `check` creates a new v1 database
but refuses other existing versions; `migrate-state` owns explicit upgrades and
legacy import.

Run `tools/update-schemas.sh` after an intentional public type change and commit
the corresponding schema/version/ADR change together. `just schema-check`
detects drift.
