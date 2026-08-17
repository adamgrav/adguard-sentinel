# Contributing

Thanks for looking. Please read this before opening a pull request, because
Sentinel deliberately refuses some features and a change that crosses one of its
boundaries cannot be merged however well written it is.

For a suspected vulnerability, follow `SECURITY.md` rather than opening an issue.

## Before you start

Open an issue first for anything beyond a bug fix or a documentation
correction. This project has a narrow, documented scope, and it is better to find
out that a change is out of scope before you write it than after.

Read these first:

- `docs/PRODUCT.md` — the product contract and its invariants.
- `docs/MVP_SCOPE.md` — what is deliberately excluded.
- `docs/ARCHITECTURE.md` — the crate layout, data flow, and panic policy.
- `docs/decisions/` — the ADRs. If your change contradicts one, the ADR has to
  change too, in the same pull request, with reasoning.

## Boundaries that will not move

These are the point of the project, not incidental restrictions.

- **The AdGuard client stays read-only.** Six typed GET operations, listed in
  `docs/API_ALLOWLIST.md`. No arbitrary path, no arbitrary method, no request
  body, no mutation, no query-log retrieval, no remediation, and no
  synchronisation between resolvers. See ADR 0001.
- **External data fails closed.** Missing or invalid required data makes an
  observation incomplete. It must never become a healthy zero, `false`, or empty
  value. See ADR 0003.
- **No panic reachable from external data.** `docs/ARCHITECTURE.md` lists the only
  categories in which a non-test `expect` is acceptable. Adding one outside those
  categories needs a typed error instead.
- **No telemetry, ever.** Sentinel contacts the resolvers you configure and, if
  enabled, Pushover. Nothing else.
- **Ambiguous notification delivery is never retried automatically.** See ADR
  0006. Duplicate alerts are worse than a missed resend for a monitor.
- **Targets stay independent.** Observations, cooldowns, latches, and history are
  keyed per target and never copied between them. Only the explicitly configured
  behaviour group aggregates anything. See ADR 0002.

## Development setup

With Nix, which supplies the pinned toolchain, `just`, `nixfmt`, and
`cargo-deny`:

```sh
nix develop -c just check
```

With direnv, inspect `.envrc` first, then:

```sh
direnv allow
just check
```

Without Nix you need Rust `1.97.1` — `rustup` reads `rust-toolchain.toml`
automatically — plus a C compiler, because SQLite is built from source. Then:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

`just check` additionally verifies generated-schema drift and runs `cargo deny`,
which needs network access to refresh the advisory database.

## Individual recipes

```text
just fmt            format Rust and Nix sources
just fmt-check      check formatting
just lint           clippy with -D warnings
just test           the whole suite
just build          debug build, all targets and features
just schema-check   verify schemas/ matches its generator
just supply-chain   cargo-deny advisories, licenses, bans, sources
just check          all of the above
```

## Requirements for a pull request

- `nix develop -c just check` passes.
- New behaviour has a test. `docs/TEST_PLAN.md` describes the suite per boundary
  and marks rows that are still thin or absent; those are good places to start.
- Behaviour changes update `docs/BEHAVIOR.md`, which is a contract rather than a
  description.
- Generated files come from their real tools. Never hand-edit `Cargo.lock`,
  `flake.lock`, or anything in `schemas/`. Run `tools/update-schemas.sh` after an
  intentional public type change and commit the schema alongside it.
- A new dependency needs justification in the pull request and a row in
  `docs/DEPENDENCIES.md`. Sentinel runs unattended with credentials, so the
  dependency tree is kept deliberately small.
- Support claims match evidence. If you add a platform or installation method,
  add it to `docs/SUPPORT.md` with an honest evidence level, and do not mark
  anything **Verified** that has not actually been built and tested.

## Test fixture privacy

This is the rule most likely to trip up a well-meaning change. Fixtures in
`testdata/` must be **synthetic**. Never paste captured output from a real
AdGuard Home instance, even your own.

- Addresses must be in an RFC 5737 documentation range: `192.0.2.0/24`,
  `198.51.100.0/24`, or `203.0.113.0/24`. For IPv6 use `2001:db8::/32`.
- Service and domain names must use the reserved `.invalid` suffix.
- No real client identities, query-log records, credentials, private hostnames, or
  copied UI content.
- Record every new fixture in `testdata/PROVENANCE.md`, including what it asserts.
- Fixtures with timestamps are relative to a single reference instant documented
  in that file. Keep new ones consistent with it.

The same applies to documentation, issues, and pull request descriptions. Do not
paste real resolver hostnames, addresses, or API output.

## Commit and pull request style

- Work on a branch and keep unrelated changes out of it.
- Explain *why* in the commit message, not just what. The diff already says what.
- Report what you actually verified. If something is untested or unproven, say so
  rather than leaving it implied.

## Licence

Contributions are dual-licensed under Apache-2.0 or MIT, matching the project. By
opening a pull request you agree your contribution may be distributed under both.
