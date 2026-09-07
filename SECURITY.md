# Security policy

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/adamgrav/adguard-sentinel/security/advisories/new),
not a public issue or pull request. Include the affected version or commit,
installation method, required attacker access, impact, and a synthetic
reproduction or proposed fix.

Do not attach live reports, API responses, databases, credentials, or client
activity. Apply the [reporting privacy rules](CONTRIBUTING.md#fixtures-and-reports)
to excerpts too; removing credentials does not remove private operational data.

This is maintained by one person without paid support or a bug bounty. Aim for
an initial response within two weeks, but there is no guaranteed response window.

## Supported versions

The latest tagged release receives security fixes through a new release. Older
versions have no backports or long-term support branches. `main` between releases
is best effort. Platform and installation coverage is in [SUPPORT](docs/SUPPORT.md).

## In scope

- Widening the fixed [AdGuard request surface](docs/API_ALLOWLIST.md), including
  mutation or query-log access.
- Leaking passwords or notification secrets into reports, logs, state, or
  notification summaries. Pushover receives its own authentication credentials
  as required by the provider protocol.
- External data causing a panic, healthy default, or silently skipped required
  check. See the [panic policy](docs/ARCHITECTURE.md#panic-policy).
- Bypassing redirect, proxy, timeout, or response-size restrictions.
- Widening private state-file permissions or exposing state through another path.
- Dependency vulnerabilities reachable through Sentinel's code paths.

Sentinel retrieves aggregate statistics, including a transient top-client map,
but retains only a top-client ratio and no client identities. Reports retain
resolver names and declared-policy evidence and must be treated as private.

## Out of scope

- Hardening AdGuard Home itself or an operator's network.
- Exposure through an explicitly configured insecure HTTP path. HTTPS is required
  unless the target is loopback or `allow_insecure_local_http` is enabled.
- Attacks requiring existing read access to secret files or the state database.
  Sentinel trusts the local filesystem.
- Operator-selected timeouts and schedules, or features outside the documented
  [product scope](docs/SUPPORT.md#scope).

## Secrets

Passwords and notification secrets come from files, not command-line arguments
or environment variables. `SecretString` redacts values from debug output.
Notification values are loaded only when a message is pending; dry-run never
loads them. `validate-config` inspects referenced file metadata, not credential
validity at the provider.

The deployment guide supplies private configuration and secrets through
[systemd credentials](docs/DEPLOYMENT.md#configure). Outbound alert text contains
condition summaries; structured expected/observed evidence remains local.
