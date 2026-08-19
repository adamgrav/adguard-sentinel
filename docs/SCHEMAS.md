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

### Condition evaluations

`evaluations[]` records every condition that was checked. `findings[]` is the
subset whose outcome is active. Both use one vocabulary:

| Field | Contract |
| --- | --- |
| `kind` | What was checked. Stable for a given `id` across runs and outcomes, so grouping by it is safe |
| `reason` | What the check found this time. Varies with the outcome, and carries the specific divergence |
| `summary` | A sentence chosen from the outcome: a clear row reads as the pass, an active row reads as the failure |
| `consecutive_active`, `consecutive_clear` | Consecutive runs counted toward `sustain_runs` and `recovery_runs` |

The counters are persisted under the `active_count` and `clear_count` column
names, which the versioned state schema pins. The report is the interface, so it
uses the clearer names; the private columns keep theirs.

Every kind, and the reasons it can report:

| `kind` | Reasons |
| --- | --- |
| `api` | `available`, `unavailable`, `authentication_rejected`, `invalid_response`, `unsupported_version` |
| `protection` | `enabled`, `disabled` |
| `processing_latency`, `upstream_latency` | `within_threshold`, `above_threshold` |
| `upstream_mode`, `upstream_set`, `rewrite_settings` | `matches_policy`, `drift` |
| `required_filter` | `matches_policy`, `missing`, `state_drift`, `stale` |
| `required_rewrite` | `matches_policy`, `missing_or_disabled` |
| `combined_query_volume` | `within_baseline`, `above_baseline`, `baseline_learning` |
| `combined_blocked_ratio` | `within_baseline`, `outside_baseline`, `baseline_learning` |

`reason` is absent from reports persisted by 0.1.0 and reads back as
`unrecorded`. Historical rows keep the `kind` and `summary` they were written
with: the report records what was evaluated at the time rather than a view
recomputed by whichever binary reads it.

## SQLite v1

`schemas/state-v1.sql` is canonical private state. `PRAGMA user_version` and a
checksummed migration row must both equal one. `check` creates a new v1 database
but refuses other existing versions; `migrate-state` owns explicit upgrades.

Run `tools/update-schemas.sh` after an intentional public type change and commit
the corresponding schema/version/ADR change together. `just schema-check`
detects drift.
