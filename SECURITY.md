# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not as a public issue or pull
request.

Use GitHub's private vulnerability reporting on this repository:
<https://github.com/adamgrav/adguard-sentinel/security/advisories/new>. That
opens a private advisory visible only to the maintainers.

Please include what you can of the following:

- What an attacker gains, and what access they need first.
- Affected version or commit, and how Sentinel was installed.
- Reproduction steps or a proof of concept.
- Any suggested fix.

This is a small project maintained by one person in their own time. There is no
paid support, no bug bounty, and no guaranteed response window. Expect a first
response within about two weeks. If a report turns out to be valid and severe, a
fix takes priority over anything else in the roadmap.

Please do not include real credentials, live API output, or resolver client
activity in a report. A synthetic reproduction is more useful and safer for both
of us.

## Supported versions

| Version | Status |
| --- | --- |
| Latest tagged release | Supported |
| Anything older | Not supported |
| `main` between releases | Best effort |

Sentinel is pre-1.0 and maintained by one person, so there are no long-term
support branches and no backports. A security fix ships as a new release, and
upgrading is the remedy.

`docs/SUPPORT.md` records which platforms and installation methods have evidence
behind them. A vulnerability report against an unsupported platform is still
welcome; it may simply be resolved by documenting the platform as unsupported.

## What is in scope

Sentinel's security posture rests on a few deliberate properties. A report that
breaks one of these is in scope and will be treated seriously:

- **The AdGuard API surface is read-only.** The client exposes exactly six typed
  GET operations, listed in `docs/API_ALLOWLIST.md`. It cannot express an
  arbitrary path, an arbitrary method, or a request body. Any way to make
  Sentinel mutate an AdGuard Home instance is a vulnerability.
- **No query-log or client-activity retrieval.** Sentinel must not be able to
  read query logs, per-client history, or resolver client identities beyond the
  single aggregate top-client ratio it records.
- **Credentials stay local.** The AdGuard password and Pushover credentials must
  never appear in reports, logs, error messages, notification payloads, or state.
  Outbound notification payloads carry condition summaries only; structured
  evidence stays in the local database and the versioned report.
- **External data fails closed.** No AdGuard or Pushover response should be able
  to cause a panic, a healthy default, or a silently skipped check. See the panic
  policy in `docs/ARCHITECTURE.md`.
- **No telemetry.** Sentinel contacts only the resolvers you configure and, if
  enabled, Pushover.
- **Transport hardening.** Requests use rustls, follow no redirects, inherit no
  proxy from the environment, and enforce timeouts and response-size limits.

Also in scope: dependency vulnerabilities that are reachable in Sentinel's own
code paths, and anything that widens the state database's `0600` permissions or
leaks state through a world-readable path.

## What is out of scope

- Hardening of your AdGuard Home instances themselves.
- Exposure caused by your own configuration, such as pointing `base_url` at a
  plaintext HTTP endpoint over an untrusted network. Sentinel requires HTTPS
  unless the target is loopback or you explicitly set
  `allow_insecure_local_http`.
- Anything requiring an attacker who already has read access to your secret files
  or the state database. Sentinel trusts the local filesystem.
- Denial of service caused by your own configured timeouts and intervals.
- The absence of a feature that `docs/SUPPORT.md` lists as not offered.
- A dependency advisory with no reachable path in this project. `just
  supply-chain` runs `cargo deny check advisories` and these are triaged there.

## Handling of secrets

Sentinel reads secrets from files, never from command-line arguments or
environment variables, so they do not appear in a process listing. Notification
credentials are read only when a message is actually pending, which is why a dry
run never touches them. Secret values are held in `secrecy::SecretString`, which
redacts them from debug output.

The recommended deployment supplies secrets through systemd `LoadCredential`, so
they live in a per-service `tmpfs` rather than on disk with broad permissions.
See `docs/DEPLOYMENT.md`.
