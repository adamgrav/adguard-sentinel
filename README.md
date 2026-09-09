# AdGuard Sentinel

A read-only monitor for one or more independent AdGuard Home resolvers. It
checks operational health and declared policy, learns traffic baselines when
configured, and sends one Pushover alert after a condition persists.

- **Operational checks:** API availability, authentication, supported version,
  DNS processing latency, and per-upstream latency.
- **Optional policy checks:** protection, upstream mode and set, required filter
  state and freshness, required rewrites, and the global rewrite switch.
- **Optional behavioural checks:** query rate, blocked-ratio deviation, and
  blocking collapse for each member of a configured group and the group total.

Sentinel uses [six fixed GET operations](docs/API_ALLOWLIST.md), never retrieves
query logs, and has no mutation API or telemetry. Invalid required data makes
an observation incomplete. Resolvers retain independent histories and latches;
only the declared behaviour group aggregates observations.

## Install

Install v0.4.0 with Nix:

```sh
nix build github:adamgrav/adguard-sentinel/v0.4.0
./result/bin/adguard-sentinel --help
```

With Rust 1.97.1 and a C compiler:

```sh
cargo install --locked --git https://github.com/adamgrav/adguard-sentinel --tag v0.4.0 sentinel-cli
adguard-sentinel --help
```

The package is `sentinel-cli`; the installed command is `adguard-sentinel`.
Linux `x86_64` source builds and Nix builds on `x86_64-linux` and
`aarch64-linux` are tested in CI. macOS `aarch64` is a development platform.
See [SUPPORT](docs/SUPPORT.md) for the platform and AdGuard Home version limits,
and [DEPLOYMENT](docs/DEPLOYMENT.md) for source builds and systemd installation.

## First observation

Save this as `config.toml`, replacing the synthetic URL with your resolver's
API URL. This example assumes the API needs no authentication; see
[Basic authentication](docs/DEPLOYMENT.md#basic-authentication) otherwise.

```toml
schema_version = 1

[[targets]]
id = "resolver"
name = "Home resolver"
base_url = "https://resolver.example.invalid"
auth = "none"
```

Notifications are disabled. Policy and behavioural analysis remain off until
configured. If you built with Nix, use `./result/bin/adguard-sentinel` in place
of `adguard-sentinel` below.

Run these commands in a POSIX shell:

```sh
adguard-sentinel validate-config --config config.toml
scratch_dir=$(mktemp -d)
chmod 700 "$scratch_dir"
cp config.toml "$scratch_dir/config.toml"
printf '\n[state]\npath = "%s/state.sqlite"\nretention_days = 21\n' "$scratch_dir" >> "$scratch_dir/config.toml"
adguard-sentinel check --config "$scratch_dir/config.toml" --dry-run
adguard-sentinel report --state "$scratch_dir/state.sqlite" --limit 1
```

`validate-config` contacts no service. `--dry-run` makes real read-only requests
and writes its selected database, but never loads or sends notification
credentials. The private scratch directory keeps those runs separate from
production state. Appending `[state]` works for the minimal example above; if
your configuration already has that table, edit its `path` in the copy instead.

Expect every target to be complete and no unexpected findings. Exit zero alone
is not a clean bill of health: `--fail-on` defaults to `never`, so findings do
not fail a service run. See [exit codes and diagnostics](docs/TROUBLESHOOTING.md).

## Configure and operate

[config.example.toml](config.example.toml) lists operational defaults, optional
policy and baseline settings, Basic authentication, and a commented Pushover
configuration. Defaults apply to omitted tables; most fields in a table you
supply remain required. [SCHEMAS](docs/SCHEMAS.md) explains the exceptions.

[DEPLOYMENT](docs/DEPLOYMENT.md) covers credentials, notifications, a five-minute
systemd timer, acceptance, and removal. Reports are human-readable by default;
`report --explain` adds per-condition measurements, thresholds, learning gates,
and sustain/recovery progress. Delivery activity identifies retries and recovered
attempts from earlier runs. `--format json` and `--format jsonl` provide the automation interface. Report
compatibility is flexible before 1.0; consult [RELEASING](RELEASING.md) and the
[CHANGELOG](CHANGELOG.md) when upgrading.

The current checkout uses SQLite v2. Existing v1 state requires explicit
`migrate-state`; [MIGRATION](docs/MIGRATION.md) describes the automatic private
backup, conservative treatment of old delivery records, and rollback.

## Documentation

| Document | Use it to |
| --- | --- |
| [PRODUCT](docs/PRODUCT.md) | Understand the product boundaries |
| [BEHAVIOR](docs/BEHAVIOR.md) | Check formulas, learning gates, and latch rules |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Trace crates, transactions, and error boundaries |
| [API_ALLOWLIST](docs/API_ALLOWLIST.md) | Inspect the permitted requests and retained data |
| [SCHEMAS](docs/SCHEMAS.md) | Interpret configuration, reports, and private state |
| [MIGRATION](docs/MIGRATION.md) | Check state-upgrade requirements |
| [TEST_PLAN](docs/TEST_PLAN.md) | Locate coverage and remaining gaps |
| [DEPENDENCIES](docs/DEPENDENCIES.md) | Review dependency purposes |
| [decisions/](docs/decisions/) | Read the rationale behind design constraints |

## Development

```sh
nix develop -c just check
```

This runs formatting, Clippy, tests, build, schema drift, documentation, and supply-chain
checks. The suite uses synthetic fixtures and local mock servers; it contacts
no live AdGuard Home or Pushover service. Dependency fetching and the RustSec
advisory refresh require network access. See [CONTRIBUTING](CONTRIBUTING.md)
for individual commands and fixture rules.

## Security and license

Report vulnerabilities privately through [SECURITY.md](SECURITY.md). For other
problems, follow the [reporting instructions](docs/TROUBLESHOOTING.md#reporting-a-problem).

Licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
Unless explicitly stated otherwise, contributions are dual-licensed on the
same terms. Dependency licenses are checked by `just supply-chain`.
