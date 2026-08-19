# AdGuard Sentinel

A read-only monitor for one or more independent AdGuard Home resolvers. This is
a complete configuration for one resolver with no authentication:

```toml
schema_version = 1

[[targets]]
id = "resolver"
name = "Home resolver"
base_url = "https://resolver.example.invalid"
auth = "none"
```

Save it as `config.toml`, replace the synthetic URL, and validate it without
contacting the resolver:

```sh
adguard-sentinel validate-config --config config.toml
```

The omitted sections use the documented operational defaults, notifications are
disabled, and policy and behavioural checks are off until you declare them. The
complete reference remains [`config.example.toml`](config.example.toml), while
[`config.minimal.toml`](config.minimal.toml) is the block above as a file.

Sentinel has no AdGuard mutation API, never reads query logs, and sends no
telemetry.

## The problem it solves

Resolvers fail quietly. Protection can be disabled "just for a minute", a filter
can stop updating, or an upstream can change without anything breaking loudly.
A naive poller creates the opposite problem by paging on every transient failure
until its alerts are ignored.

Sentinel observes each resolver independently, lets you declare only the policy
you care about, requires a condition to persist before it alerts, alerts
**once**, and resolves quietly when the condition clears. One resolver is enough;
an explicit group can add cross-resolver behavioural analysis when wanted.

## What it watches

**Operational**, per resolver: API reachability, authentication rejection,
whether the server version is supported, DNS processing latency, and
per-upstream latency.

**Declared policy**, per resolver and entirely optional: protection state,
upstream mode, upstream set, required filter lists including whether they are
enabled and how stale they are, required DNS rewrites, and the global rewrite
setting. Each field is independent. Anything you omit produces no policy
evaluation, rather than a misleading `clear` one.

**Behaviour**, across an explicitly configured group: combined query volume and
blocked ratio compared against a learned same-hour baseline, using a median and
scaled median absolute deviation so one busy evening does not become the new
normal.

## Safety boundaries

These are the design, not a disclaimer. They are why the project is small.

- **Read-only by construction.** The AdGuard client exposes exactly six typed GET
  operations ([the allowlist](docs/API_ALLOWLIST.md)). It cannot express an
  arbitrary path, an arbitrary method, or a request body. There is no code path
  that mutates a resolver.
- **No query logs, ever.** Sentinel never retrieves query logs, per-client
  history, or client identities beyond a single aggregate top-client ratio.
- **Invalid data fails closed.** A response that cannot be trusted makes the
  observation *incomplete*. It never becomes a healthy zero, `false`, or empty
  value — the failure mode that makes a monitor worse than useless.
- **Credentials stay local.** Basic-auth and notification secrets are read from
  files, never arguments or the environment. With `auth = "none"`, no
  `Authorization` header is sent. Outbound notifications carry condition
  summaries only; structured evidence stays in local state.
- **Resolvers stay independent.** Observations, cooldowns, latches, and history
  are per resolver and never copied between them.
- **No telemetry.** It contacts the resolvers you configure and, if enabled,
  Pushover.

## Support

Sentinel builds from source on `x86_64` Linux with Rust 1.97.1, and Nix provides
the reproducible packaging path for `x86_64-linux` and `aarch64-linux`. ARM Linux
CI is configured but remains pending until it has a recorded green run. Pushover
is the only notification provider, and a systemd timer is the only supported
scheduling method. AdGuard Home
`>=0.107.78,<0.108.0` is the supported API range; another range can be
configured deliberately, but nothing here is claimed for it.

There are no prebuilt binaries, no musl build, no container image, and no
reusable NixOS service module.

**[`docs/SUPPORT.md`](docs/SUPPORT.md) is authoritative** and records the evidence
level behind every claim above, and what none of that evidence proves. Read it
before relying on this.

## Install

With Nix, which is the first-class path:

```sh
nix build github:adamgrav/adguard-sentinel
./result/bin/adguard-sentinel --help
```

From source on Linux, needing Rust 1.97.1 and a C compiler:

```sh
git clone https://github.com/adamgrav/adguard-sentinel
cd adguard-sentinel
cargo build --locked --release
install -Dm755 target/release/adguard-sentinel /usr/local/bin/adguard-sentinel
```

Or install a tagged release directly from Git without a crates.io publication:

```sh
cargo install --locked --git https://github.com/adamgrav/adguard-sentinel --tag vX.Y.Z adguard-sentinel
```

A built binary needs no system SQLite, OpenSSL, or `tzdata` — all three are
linked in. See [the deployment guide](docs/DEPLOYMENT.md) for details.

## Five-minute start

```sh
# 1. Start minimal. The URL is synthetic and must be replaced.
install -Dm600 config.minimal.toml /etc/adguard-sentinel/config.toml

# 2. Check the configuration. Touches no network service.
adguard-sentinel validate-config --config /etc/adguard-sentinel/config.toml

# 3. Give the dry run its own configuration and state database.
cp /etc/adguard-sentinel/config.toml /tmp/adguard-sentinel-dry-run.toml
printf '\n[state]\npath = "/tmp/adguard-sentinel-dry-run.sqlite"\nretention_days = 21\n' >> /tmp/adguard-sentinel-dry-run.toml

# 4. Take one observation, with notifications never loaded.
adguard-sentinel check --config /tmp/adguard-sentinel-dry-run.toml --dry-run

# 5. Read what it found.
adguard-sentinel report --state /tmp/adguard-sentinel-dry-run.sqlite --limit 1
```

Step 4 should exit `0` with every target complete and no unexpected findings. If
it does not, [the troubleshooting guide](docs/TROUBLESHOOTING.md) is organised by
exactly what you will see. The production configuration still uses the default
`/var/lib/adguard-sentinel/state.sqlite`, so the dry-run database cannot advance
live latches.

Then add only the policy, behavioural baseline, Basic authentication, or
Pushover settings you want. Install a systemd timer to run it every five minutes;
the deployment guide has a hardened unit pair with optional `LoadCredential`
entries and a private state directory.

## Configure

One TOML file, `schema_version = 1`. Start from
[`config.minimal.toml`](config.minimal.toml); use
[`config.example.toml`](config.example.toml) when you need the complete reference.
Omitting state, observation, condition profiles, or notifications selects the
exact values shown in the complete example. Policy and behavioural analysis are
opt-in.

| Section | Omission | Purpose |
| --- | --- | --- |
| `[state]` | Reference defaults | Database path and retention |
| `[observation]` | Reference defaults | Timeouts, response-size limit, concurrency, and how many targets must be complete for the run to be healthy |
| `[behavioral_baseline]` | Disabled | Optional behaviour group, time zone, and learning window |
| `[condition_profiles.*]` | `current` reference profile | Sustain and recovery counts plus latency thresholds |
| `[notifications]` | Disabled | `disabled` or `pushover` |
| `[policies.*]` | No policy checks | Independently optional protection, upstream, filter, and rewrite declarations |
| `[[targets]]` | Required | Resolver identity, base URL, auth mode, and optional policy/profile selection |

`adguard-sentinel print-schema config --version 1` emits the JSON Schema, which
is generated from the Rust types rather than hand-written.

## Output and exit codes

Human-readable by default; `--format json` or `--format jsonl` for automation,
validated against [checked-in schemas](schemas/). SQLite is private state; the
versioned JSON is the interface.

| Code | Meaning |
| --- | --- |
| `0` | Observation completed |
| `1` | A finding met the `--fail-on` threshold |
| `2` | Invocation or configuration error |
| `3` | Minimum complete target count not met |
| `4` | Notification delivery not confirmed |
| `5` | State persistence failed |

`--fail-on` defaults to `never`, which is deliberate: a finding is a statement
about your resolvers, while an exit code is a statement about Sentinel's own
execution. Keeping them separate is what stops a service manager from flapping on
ordinary findings.

## Operating it

```text
adguard-sentinel validate-config --config PATH
adguard-sentinel check --config PATH [--dry-run] [--format FORMAT] [--fail-on LEVEL]
adguard-sentinel report --state PATH [--limit N] [--since TIMESTAMP] [--format FORMAT]
adguard-sentinel migrate-state --state PATH
adguard-sentinel print-schema <config|run-report|state> --version 1
```

Two behaviours worth knowing before you run it:

- `--dry-run` still makes real read-only requests to your resolvers, and still
  writes to the state database it is pointed at. What it never does is load or
  send notification credentials. Give dry runs their own state path.
- `check` never migrates state. A newer binary meeting older state exits `5` and
  asks you to run `migrate-state`, so an upgrade cannot silently rewrite history.

## Documentation

| Document | What it covers |
| --- | --- |
| [SUPPORT](docs/SUPPORT.md) | What is supported, and the evidence behind each claim |
| [DEPLOYMENT](docs/DEPLOYMENT.md) | Install, configure, systemd, inspect, remove |
| [TROUBLESHOOTING](docs/TROUBLESHOOTING.md) | Organised by the message or exit code you saw |
| [PRODUCT](docs/PRODUCT.md) | The product contract and its invariants |
| [BEHAVIOR](docs/BEHAVIOR.md) | Exact thresholds, formulas, and latch rules |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Crate layout, data flow, panic policy, evidence boundaries |
| [API_ALLOWLIST](docs/API_ALLOWLIST.md) | The six permitted requests and what is kept from each |
| [SCHEMAS](docs/SCHEMAS.md) | The versioned configuration, report, and state formats |
| [TEST_PLAN](docs/TEST_PLAN.md) | Real coverage per boundary, with gaps marked |
| [DEPENDENCIES](docs/DEPENDENCIES.md) | Every direct dependency and why it is there |
| [decisions/](docs/decisions/) | ADRs for the choices that constrain the design |

At the repository root: [CHANGELOG](CHANGELOG.md) for what changed in each
release, [RELEASING](RELEASING.md) for how versioning works across the binary and
the three schemas, [CONTRIBUTING](CONTRIBUTING.md), and [SECURITY](SECURITY.md).

## Development

Inspect [`.envrc`](.envrc), then:

```sh
direnv allow
just check
```

Without direnv:

```sh
nix flake check
nix develop -c just check
```

The test suite contacts no live AdGuard Home or Pushover service. `just check`
needs network access only for its `supply-chain` step, which refreshes the RustSec
advisory database.

[CONTRIBUTING.md](CONTRIBUTING.md) covers the boundaries a change must not cross
and the privacy rules for test fixtures. Please open an issue before writing
anything beyond a bug fix.

## Security

Report suspected vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

Third-party dependency licenses are registered in
[`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md) and enforced by `just
supply-chain`, which checks licenses alongside RustSec advisories, banned crates,
and permitted sources.
