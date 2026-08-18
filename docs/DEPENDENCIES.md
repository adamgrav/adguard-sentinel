# Direct dependency register

Exact resolved versions are authoritative in `Cargo.lock` and `flake.lock`. This
register explains why each direct dependency is present; it is a convenience, not
a source of truth.

The licence column reproduces the SPDX expression each crate declares in its own
manifest. `OR` means the crate's author grants a choice of either licence, which
is the prevailing Rust convention. These values are checkable rather than
estimated, and `just supply-chain` enforces them on every run through
`cargo deny check licenses` against the allowlist in `deny.toml`. If this table
and that check ever disagree, the check is right.

| Dependency | Purpose | Role | Declared license |
| --- | --- | --- | --- |
| anyhow | CLI error context | runtime | MIT OR Apache-2.0 |
| async-trait | injectable async client/sink traits | runtime | MIT OR Apache-2.0 |
| base64 | HTTP Basic authentication | runtime | MIT OR Apache-2.0 |
| clap | CLI parsing | runtime | MIT OR Apache-2.0 |
| futures | bounded concurrent observation | runtime | MIT OR Apache-2.0 |
| jiff | timestamps and bundled IANA time zones | runtime | Unlicense OR MIT |
| reqwest | bounded rustls HTTP client | runtime | MIT OR Apache-2.0 |
| rusqlite | transactional SQLite state | runtime | MIT |
| schemars | versioned JSON Schema generation | build/runtime CLI | MIT |
| secrecy | redaction-safe secret values | runtime | Apache-2.0 OR MIT |
| semver | AdGuard compatibility gate | runtime | MIT OR Apache-2.0 |
| serde, serde_json, toml | strict formats | runtime | MIT OR Apache-2.0 |
| sha2 | config/import fingerprints | runtime | MIT OR Apache-2.0 |
| thiserror | typed library failures | runtime | MIT OR Apache-2.0 |
| tokio | bounded asynchronous orchestration | runtime | MIT |
| tracing, tracing-subscriber | redacted diagnostics | runtime | MIT |
| url | target URL validation | runtime | MIT OR Apache-2.0 |
| uuid | opaque run and outbox identifiers | runtime | Apache-2.0 OR MIT |

Nix supplies the exact compiler, Cargo, Just, formatter, and cargo-deny. SQLite
is built through rusqlite's bundled feature. Because the binary statically links
these crates, anyone redistributing a build must carry the license notices of
these dependencies and their transitive dependencies.

`webpki-roots`, reached through reqwest/rustls, includes Mozilla's public root
certificate data under CDLA-Permissive-2.0. This is accepted for runtime TLS
verification and does not contain application code or private trust material.

Jiff's IANA database is embedded so named-zone behavior is hermetic in Nix build
sandboxes and systemd services. Dependency updates must review the bundled tzdb
release as well as the Jiff code version.

## Accepted duplicate versions

`cargo deny` reports `multiple-versions = "warn"` rather than `deny`, so the
following transitive duplicates are accepted rather than forced into a single
version. Each pair exists because two independent upstream crates depend on
different major versions; resolving them would require patching or pinning
dependencies away from their published requirements, which is a larger risk than
carrying the duplicate. Review this table whenever `Cargo.lock` changes.

| Crate | Versions | Reason |
| --- | --- | --- |
| getrandom | 0.2, 0.4 | Two generations of the randomness API are pulled in by separate dependents |
| hashbrown | 0.15, 0.17 | Interior map dependency of crates that upgraded on different schedules |
| syn | 2, 3 | Proc-macro dependency; build-time only, absent from the binary |
| windows-sys | 0.52, 0.61 | Platform bindings; not reached in the Linux or macOS builds this project targets |
| winnow | 0.7, 1.0 | `toml` and its own `toml_parser` currently resolve to different majors |

None of these is a security advisory. `just supply-chain` enforces advisories,
licenses, bans, and sources, and would fail on a real vulnerability.
