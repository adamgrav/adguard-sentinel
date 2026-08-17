# Direct dependency register

Exact resolved versions are authoritative in `Cargo.lock` and `flake.lock`.
This register must be refreshed when either lock changes.

| Dependency | Purpose | Role | Expected license |
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
| secrecy | redaction-safe secret values | runtime | MIT OR Apache-2.0 |
| semver | AdGuard compatibility gate | runtime | MIT OR Apache-2.0 |
| serde, serde_json, toml | strict formats | runtime | MIT OR Apache-2.0 |
| sha2 | config/import fingerprints | runtime | MIT OR Apache-2.0 |
| thiserror | typed library failures | runtime | MIT OR Apache-2.0 |
| tokio | bounded asynchronous orchestration | runtime | MIT |
| tracing, tracing-subscriber | redacted diagnostics | runtime | MIT |
| url | target URL validation | runtime | MIT OR Apache-2.0 |
| uuid | opaque run and outbox identifiers | runtime | MIT OR Apache-2.0 |

Nix supplies the exact compiler, Cargo, Just, formatter, and cargo-deny. SQLite
is built through rusqlite's bundled feature. A generated
transitive notice report remains required before public release.

`webpki-roots`, reached through reqwest/rustls, includes Mozilla's public root
certificate data under CDLA-Permissive-2.0. This is accepted for runtime TLS
verification and does not contain application code or private trust material.

Jiff's IANA database is embedded so named-zone behavior is hermetic in Nix build
sandboxes and systemd services. Dependency updates must review the bundled tzdb
release as well as the Jiff code version.
