# Troubleshooting

Sentinel writes diagnostics to stderr and its structured result to stdout. Set
`RUST_LOG=debug` for more detail; the default is `info`.

Two ideas explain most confusing behaviour:

- **A finding is a statement about your resolvers. An exit code is a statement
  about Sentinel's own execution.** They are deliberately separate, which is why
  `--fail-on` defaults to `never`.
- **Missing or invalid data never becomes a healthy value.** An observation that
  cannot be trusted is marked incomplete instead of being reported as zero,
  false, or empty.

## Exit codes

| Code | Meaning | Usual cause |
| --- | --- | --- |
| `0` | Observation completed | Normal, including when findings exist and `--fail-on` is `never` |
| `1` | A finding met the `--fail-on` threshold | You raised `--fail-on` above `never` |
| `2` | Invocation or configuration error | Bad configuration, bad flag, unreadable secret file |
| `3` | Minimum complete target count was not met | Resolvers unreachable, rejecting authentication, or returning data that failed validation |
| `4` | Notification delivery was not confirmed | Pushover rejected, was unreachable, or the outcome is ambiguous |
| `5` | State persistence failed | State path, permissions, schema version, or a regressed clock |

Exit `1` is the only code that depends on your resolvers' condition. Everything
else reports Sentinel's own health, which is what a service manager should act
on.

## A target is incomplete

Run with `--format json` and read `targets[].status` and `targets[].error_kind`.

| Status | What happened | What to do |
| --- | --- | --- |
| `unavailable` | Connection refused, timed out, or a non-success HTTP status | Check reachability and `observation.request_timeout_ms`. A redirect also lands here: Sentinel does not follow redirects, so a proxy that redirects the API will fail |
| `authentication_rejected` | The API returned 401 or 403 | Check the username and the contents of `password_file`. See the cooldown section below |
| `authentication_cooldown` | A previous rejection is still being backed off | Expected after a rejection. See below |
| `unsupported_version` | The server is outside the configured `observation.adguard_version_requirement` | Only `>=0.107.78,<0.108.0` has recorded evidence. A different range can be configured, but it needs `observation.allow_untested_adguard_version = true` and it is untested. See below |
| `invalid_response` | A response failed strict validation | See below |
| `response_too_large` | A body exceeded `observation.max_response_bytes` | Raise the limit only if you understand why the response is that large |

If enough targets are incomplete that `observation.minimum_complete_targets` is
not met, the run exits `3`. With independent resolvers, setting
`minimum_complete_targets = 1` lets monitoring continue when one is down.

## Authentication cooldown

After a rejected password, Sentinel records a cooldown of
`condition_profiles.<name>.authentication_retry_seconds` and makes **no request
at all** to that target until it expires. You will see:

```text
authentication retry is paused for 840 seconds
```

This is deliberate: repeatedly retrying a bad credential can trip rate limits or
account lockouts. The cooldown is cleared by the first complete observation, not
by time alone, so after fixing the credential the next run past the window will
resume and clear it.

To resume immediately, fix the credential and either wait out the window or start
from a fresh state database.

## An invalid response

`invalid_response` means the data would have been misleading, so it was rejected.
The `error_detail` field names the specific check. Common ones:

- `num_blocked_filtering exceeds num_dns_queries`
- `avg_processing_time must be finite and nonnegative`
- `top_clients contains invalid or duplicate data`
- `upstream set must be nonempty`
- `upstream set contains empty or duplicate values`
- `upstream mode must not contain only whitespace`
- `rewrite list contains empty or duplicate normalized entries`
- `required filter last_updated is in the future`
- `enabled required filter has no last_updated value`
- `running must be true for a complete observation`
- `JSON decoding failed: ...`

Two of these deserve explanation. A required filter timestamped in the future
usually means clock skew between the monitor host and the resolver. An enabled
required filter with no update time usually means the filter has never
successfully downloaded.

Unknown *extra* fields are not an error. Sentinel ignores response fields it does
not recognise so that AdGuard Home patch releases do not break it.

## State database problems

| Message | Cause | Fix |
| --- | --- | --- |
| `state parent directory does not exist` | The directory holding `state.path` is missing | Create it, or use `StateDirectory=` under systemd |
| `cannot open or use state database` | Permissions, or the path is not writable by the service user | Under `DynamicUser=yes`, only `StateDirectory` is writable |
| `state schema version N is unsupported; expected 1` | The database was written by a different version | Run `migrate-state`, or start from a fresh path |
| `unversioned nonempty SQLite state is not supported` | `state.path` points at some other SQLite file | Point it at a dedicated path |
| `state database is bound to "live" runs and cannot be used for "dry_run"` | Mixing modes on one database | See below |
| `wall clock regressed behind the latest completed run` | System time moved backwards | See below |

Sentinel creates the database with `0600` permissions. `check` creates a new
version-1 database but never upgrades an existing one; `migrate-state` owns
upgrades explicitly, so a new binary cannot silently rewrite old state.

### Live and dry-run state cannot mix

A database is permanently bound to live or dry-run use on its first run. This
stops a dry run from advancing live latches, which would suppress a real alert.
Give dry runs their own path:

```sh
adguard-sentinel check --config /etc/adguard-sentinel/config.toml --dry-run
# with state.path pointed at a dedicated dry-run database
```

### A regressed wall clock

If system time moves backwards past the latest completed run, Sentinel refuses to
proceed and exits `5` **without recording the run**. Retention pruning and
baseline history depend on monotonically advancing timestamps, so advancing state
under a regressed clock could discard real history. Let NTP settle, then run
again.

## Notifications

### Nothing was sent

Expected in all of these cases:

- `notifications.provider = "disabled"`, the default in `config.example.toml`.
- `--dry-run`, which never loads or sends notification credentials.
- No condition crossed a transition this run. Sentinel notifies on *transitions*,
  not on every run in which a finding is present. A condition must stay active for
  its `*_sustain_runs` count before it alerts, and it alerts once, not repeatedly.

### Exit 4 with a `retryable` status

The message was definitely not delivered — a refused connection, or a Pushover 5xx.
It stays queued and the next run retries it after a short backoff.

### Exit 4 with an `unknown` status

The outcome is ambiguous: the request may have been delivered. A timeout after
transmission, an interrupted response, an oversized response body, or a success
response with no request identifier all land here.

**Sentinel never retries these automatically.** Retrying a possibly-delivered
alert risks duplicate pages, and for a monitor that is worse than a missed
resend. Check the Pushover app to see whether the message arrived. The queued
entry stays in the `unknown` state and will not be sent again.

### Exit 4 with a `failed` status

Pushover permanently rejected the request, usually a bad application token or user
key. Check both credential files. Note the tokens are read only when a message is
actually pending, so a bad token produces no error on healthy runs.

### A resolution never arrived

A resolution is only eligible after a **confirmed delivered** alert. If the alert
was ambiguous or failed, no resolution is sent, because "resolved" is meaningless
to someone who never received the alert.

## Behavioural findings never fire

Query-volume and blocked-ratio findings need a learned baseline:
`behavioral_baseline.learning_days` of history **and**
`behavioral_baseline.minimum_same_hour_samples` samples in the current local hour.
Until then those conditions report as not-evaluated rather than clear, which is
visible in `aggregate.baseline_ready` in the JSON report.

A first deployment therefore has operational and policy findings active
immediately, while behavioural findings wait out the learning window. Every
member of `behavioral_baseline.target_ids` must have a complete observation for
the aggregate to advance at all.

## Policy findings you did not expect

Only *declared* policy is compared. Extra filters and rewrites that your
configuration does not mention are ignored by design.

Findings are identified by a stable `kind` plus the `reason` that fired, so
`upstream_mode` with `reason: "drift"` is one condition rather than a separate
kind per failure mode.

- `upstream_mode` / `drift`: AdGuard Home `0.107.78` reports load balancing as an
  empty string, which Sentinel normalises to `load_balance`. Declare
  `load_balance`, not `""`.
- `required_rewrite` / `missing_or_disabled` with `observed: null`: no rewrite
  matches that exact domain **and** answer pair. A rewrite for the same domain
  with a different answer does not satisfy the requirement.
- `required_filter` / `stale`: the filter's last update is older than
  `maximum_age_hours`. Check that AdGuard Home is actually refreshing lists.

Domains and rewrite answers are compared after normalisation, so casing and a
trailing dot do not matter, and reformatting your configuration will not reset a
latch.

## An AdGuard Home version outside the tested range

`>=0.107.78,<0.108.0` is the only range with recorded evidence behind it, and it
is the default. Configuring any other range is refused unless the choice is
explicit:

```text
- observation.adguard_version_requirement is ">=0.108.0,<0.109.0", but only
  ">=0.107.78,<0.108.0" has recorded evidence; set
  observation.allow_untested_adguard_version = true to accept an untested range
```

Setting `observation.allow_untested_adguard_version = true` accepts the range you
configured. It changes nothing else: the requirement is still enforced at the
request boundary before any other endpoint is read, responses are still validated
strictly, and a server outside your range is still an incomplete observation.
What you lose is the evidence, so every run says so:

```text
WARN accepting an AdGuard Home version requirement with no recorded evidence behind it
```

Treat a widened range as a local experiment rather than a supported
configuration, and read `docs/SUPPORT.md` for what that distinction means.

## Reporting a problem

Include the `--format json` output with any credential removed, the exit code, the
AdGuard Home version, and how Sentinel was installed. Reports never contain
credentials or query-log data, but check before pasting. For a suspected
vulnerability, follow `SECURITY.md` instead of opening a public issue.
