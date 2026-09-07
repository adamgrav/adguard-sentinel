# Contributing

Open an issue before work beyond a bug fix or documentation correction. Read
[PRODUCT](docs/PRODUCT.md), [SUPPORT](docs/SUPPORT.md),
[ARCHITECTURE](docs/ARCHITECTURE.md), and the relevant [ADRs](docs/decisions/)
before changing behavior.

## Boundaries

The [product invariants](docs/PRODUCT.md#invariants) apply to every change:
read-only AdGuard access, strict external-data handling, independent resolver
state, private credentials, and no telemetry. The [allowlist](docs/API_ALLOWLIST.md)
is the entire AdGuard surface. Follow the architecture's panic policy and
[ADR 0006](docs/decisions/0006-pushover-delivery-ambiguity.md) for notification
ambiguity. Changing a design decision requires updating its ADR with rationale.

## Development

Nix supplies the pinned toolchain and check tools:

```sh
nix develop -c just check
```

With direnv, inspect `.envrc`, run `direnv allow`, then use `just check`.
Without Nix, install Rust 1.97.1 and a C compiler/linker, then run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

| Recipe | Purpose |
| --- | --- |
| `just fmt` / `just fmt-check` | Format or check Rust and Nix |
| `just lint` | Clippy with warnings denied |
| `just test` | Workspace tests |
| `just build` | Debug build of all targets and features |
| `just schema-check` | Compare generated schemas with committed files |
| `just supply-chain` | Check advisories, licenses, bans, and sources |
| `just check` | All checks above, without formatting files |

Dependency fetching and the RustSec advisory refresh need network access.
Tests use synthetic fixtures and local mock servers, never live AdGuard Home or
Pushover services. [TEST_PLAN](docs/TEST_PLAN.md) maps coverage and gaps.

## Changes and review

- Work on a feature branch and preserve unrelated changes.
- Run `nix develop -c just check` and report actual results, including limitations.
- Add regression coverage for behavior changes. Verify that a regression test
  fails for the defect it is intended to catch.
- Follow [RELEASING](RELEASING.md) for compatibility and update
  [BEHAVIOR](docs/BEHAVIOR.md) when evaluation or latch semantics change.
- Generate lockfiles and schemas with their real tools. For public type changes,
  run `tools/update-schemas.sh`; never hand-edit generated files.
- Justify new dependencies and update [DEPENDENCIES](docs/DEPENDENCIES.md).
- Support claims require recorded evidence for the stated platform and method.
- Every word in documentation must help the reader act, understand behavior, or
  assess a decision. Remove filler and duplication, link to each rule's
  authoritative home, and read the whole affected document after editing.

A pull request should state the problem, resulting behavior, and validation.
Keep private deployment details out of its text and diff.

## Fixtures and reports

Use synthetic reproductions. Do not publish live reports, API responses, state
files, credentials, client activity, private names, addresses, paths, or counts.
Reports can contain operational and policy data even when they contain no
credentials. Replace those values before sharing an excerpt.

- Use RFC 5737 addresses (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`), `2001:db8::/32` for IPv6, and reserved `.invalid` names.
- Record fixtures and their assertions in [PROVENANCE](testdata/PROVENANCE.md).
  Timestamped fixtures use its reference instant.
- The existing public upstream identifiers in the golden set are documented
  there; they are not permission to copy deployment data into new fixtures.

For bug reports, include versions, installation method, platform, exit code,
and a synthetic reproduction. Send vulnerability reports through
[SECURITY](SECURITY.md).

## License

Contributions are dual-licensed under Apache-2.0 or MIT, matching the project.
