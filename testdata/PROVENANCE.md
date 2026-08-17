# Fixture provenance

All API fixtures are synthetic and use RFC 5737 addresses and reserved
`.invalid` names. Their shapes were authored against AdGuard Home v0.107.78's
tagged OpenAPI specification and the fields this crate actually requires. They
are not captured API output, so they contain no query-log records, real client
identities, credentials, private hostnames, or copied UI content.

## Reference instant

Tests that consume a fixture with a timestamp use `1800000000`, which is
`2027-01-15T08:00:00Z`. Fixture timestamps are chosen relative to that instant.

## Golden set

These six files together describe one healthy AdGuard Home instance and match
the declared `home` policy in `config.example.toml`, so a complete observation
of them produces no findings.

| File | Notes |
| --- | --- |
| `api/status.json` | Supported version, running, protection enabled |
| `api/stats.json` | 5000 queries, 1250 blocked, three upstreams |
| `api/dns-info.json` | Legacy `upstream_mode: ""`, as v0.107.78 reports load balancing |
| `api/filtering-status.json` | One fresh required filter, one declared-disabled filter, one filter outside declared policy |
| `api/rewrite-list.json` | One required rewrite plus unrelated entries needing normalization |
| `api/rewrite-settings.json` | Global rewrite handling enabled |

Fields beyond those this crate requires are present deliberately. They prove the
decoder tolerates unknown response fields, as ADR 0003 permits for
forward-compatible patch releases.

## Compatibility set

| File | Asserts |
| --- | --- |
| `api/dns-info-explicit-mode.json` | An explicit `load_balance` mode is preserved unchanged |
| `api/dns-info-parallel-mode.json` | A declared mode other than the golden one, used to drive a resolution after an alert |

## Fail-closed set

Every file below must make an observation incomplete rather than produce a
healthy default.

| File | Asserts |
| --- | --- |
| `api/malformed-negative-stats.json` | Negative `avg_processing_time` is rejected |
| `api/malformed-blocked-exceeds-queries.json` | Blocked count above query count is rejected |
| `api/malformed-duplicate-top-client.json` | A repeated client identity is rejected |
| `api/malformed-dns-info-missing-mode.json` | A missing required field is rejected |
| `api/malformed-whitespace-upstream-mode.json` | Whitespace is not the legacy empty-string alias |
| `api/malformed-duplicate-rewrites.json` | Entries that collide after normalization are rejected |
| `api/malformed-empty-rewrite-domain.json` | An empty rewrite domain is rejected |
| `api/malformed-future-filter-update.json` | A required filter updated in the future is rejected |
| `api/malformed-enabled-filter-without-update.json` | An enabled required filter with no update time is rejected |
