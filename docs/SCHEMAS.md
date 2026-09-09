# Configuration, reports, and state

Generate the current formats with:

```sh
adguard-sentinel print-schema config --version 1
adguard-sentinel print-schema run-report --version 1
adguard-sentinel print-schema state --version 2
```

The checked-in [schemas](../schemas/) come from the Rust types and canonical SQL.
`just schema-check` detects generator drift. Run `tools/update-schemas.sh` after
an intentional public type change. Compatibility follows [RELEASING](../RELEASING.md).

## Configuration v1

Only `schema_version` and `targets` are required at the root. Semantic validation
also checks references, uniqueness, paths, URL policy, durations, and bounds.
`validate-config` checks that referenced secrets are nonempty regular files; it
does not authenticate them or contact a service.

| Section | When omitted | When supplied |
| --- | --- | --- |
| `[state]` | Default path and 21-day retention | Both fields required |
| `[observation]` | Operational defaults | All fields required except `allow_untested_adguard_version`, which defaults to false |
| `[condition_profiles]` | The default `current` profile | Replaces the profile map; each profile requires all thirteen fields |
| `[notifications]` | Disabled | Requires `provider`; Pushover also requires its credential table |
| `[behavioral_baseline]` | Disabled | All fields required |
| `[policies.*]` | No policy checks | Each policy field is independently optional |
| `[[targets]]` | Invalid configuration | Requires `id`, `name`, and `base_url`; authentication rules apply below |

A target defaults to the `current` condition profile, Basic authentication, and
`allow_insecure_local_http = false`. Basic authentication requires `username`
and `password_file`; explicit `auth = "none"` requires both to be absent. Policy
selection is optional.

Defaults generally apply to whole tables, not their fields. For example,
`[state]` with only `path` fails because `retention_days` is missing. The
observation flag and optional policy fields above are exceptions. A concurrency
cap of two is valid for one target; it is not a minimum target count.

[config.minimal.toml](../config.minimal.toml) is the smallest example.
[config.example.toml](../config.example.toml) records defaults and optional
settings, including Pushover. [DEPLOYMENT](DEPLOYMENT.md) explains credential
paths inside and outside systemd.

## Run report v1

JSON contains normalized observations, condition evaluations, findings,
transitions, delivery activity, and execution health. JSONL emits one complete
report object per line. `--format json` accepts a single report; use JSONL for
multiple historical reports.

Counts remain JSON integers across the full `u64` range. Consumers must preserve
integer precision when parsing them.

Reports exclude credentials and client/query identities, but retain resolver
names, upstreams, filter URLs, rewrite tuples, counters, and policy evidence.
They are private operational data; follow the [reporting instructions](TROUBLESHOOTING.md#reporting-a-problem).

### Condition evaluations

`evaluations[]` contains produced conditions; `findings[]` contains the active
subset. An omitted policy declaration creates no condition. Incomplete targets
produce their API failure evaluation without claiming that unavailable checks
passed.

| Field | Meaning |
| --- | --- |
| `id` | Condition identity used for its persisted latch |
| `kind` | What the condition checks; stable for its identity |
| `reason` | What was found in this evaluation |
| `summary` | Human sentence describing the outcome |
| `severity` | Importance of the current outcome; authentication rejection can be critical under an otherwise warning API condition |
| `consecutive_active`, `consecutive_clear` | Runs counted toward sustain and recovery |

[ADR 0010](decisions/0010-condition-identity-and-phrasing.md) explains identity
and phrasing. Current kinds and reasons are:

| `kind` | Reasons |
| --- | --- |
| `api` | `available`, `unavailable`, `authentication_rejected`, `invalid_response`, `unsupported_version` |
| `protection` | `enabled`, `disabled` |
| `processing_latency`, `upstream_latency` | `within_threshold`, `above_threshold` |
| `upstream_mode`, `upstream_set`, `rewrite_settings` | `matches_policy`, `drift` |
| `required_filter` | `matches_policy`, `missing`, `state_drift`, `stale` |
| `required_rewrite` | `matches_policy`, `missing_or_disabled`, `globally_disabled` |
| `combined_query_rate`, `query_rate` | `within_baseline`, `above_baseline`, `baseline_learning`, `rate_window_unavailable` |
| `combined_blocked_ratio`, `blocked_ratio` | `within_baseline`, `outside_baseline`, `baseline_learning`, `rate_window_unavailable`, `window_too_small` |
| `combined_blocking_collapse`, `blocking_collapse` | `blocking_sustained`, `blocking_collapsed`, `baseline_learning`, `rate_window_unavailable`, `window_too_small` |

### Aggregate observations

`aggregate` is null when the baseline is omitted or the group is unavailable.
`combined_queries` and `combined_blocked_ratio` describe the current cumulative
reading. Rate-window measurements and applied limits live in each behavioral
condition's `observed` and `expected` evidence.

From 0.3.0, `same_hour_samples` counts valid rate windows and `baseline_ready`
indicates rate-population readiness. Neither establishes ratio readiness; use
the individual outcomes and reasons described in [BEHAVIOR](BEHAVIOR.md).

### Delivery records

`notifications[]` belongs to transitions originating in that run. Its statuses
can change after later delivery attempts. `transitions[]` retains the original
condition membership and summaries.

`delivery_activity[]` records attempts and interrupted-attempt recovery performed
by the run being reported, including work originating in older runs. Each entry
has an `attempt_id`, `origin_run_id`, `action` (`attempt` or `recovered`), and a
`notification` snapshot containing the original notification ID, condition IDs,
status, and error class. These snapshots preserve the executing run's result
even if an origin-owned notification later changes status. Inspect them when
exit `4` accompanies no new transitions.

### Historical reports

Reports preserve stored evaluations instead of recomputing past findings.
Evaluations from 0.1.0 supply `reason = "unrecorded"` when read, and their older
counter names deserialize into the current names.

Older exports without `delivery_activity` read as an empty array. Delivery
fields can reflect later attempts or conservative migration decisions; stored
observation outcomes are not re-evaluated. `state_schema_version` identifies the
database schema used to read the report, so migrated history reports version
`2`; it does not identify the original producer.

Before 0.3.0, aggregate readiness fields counted raw readings. Those historical
values retain that meaning; they are not recalculated as windows. The current
reader omits the retired `volume_limit` and `ratio_limit` fields for old and new
reports. Report version 1 alone therefore does not identify the producer's
pre-1.0 semantics. Keep the producing release alongside exports when comparing
history across upgrades.

## SQLite v2

[schemas/state-v2.sql](../schemas/state-v2.sql) defines current private state.
`PRAGMA user_version` and checksummed migration rows identify its version.
The released [v1 schema](../schemas/state-v1.sql) remains frozen and available
through `print-schema state --version 1`.

V2 stores unsigned counters as validated decimal text, avoiding SQLite's signed
integer limit. Live/dry-run identity persists independently of retained runs.
Delivery attempts, original batch membership, and episode identity support
recovery without silently replaying possibly transmitted messages.

`check` creates new v2 state. Both `check` and `report` refuse v1 until an
explicit [migration](MIGRATION.md), including its pre-upgrade backup, succeeds.
