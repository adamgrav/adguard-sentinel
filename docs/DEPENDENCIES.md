# Direct dependency register

Resolved versions are in `Cargo.lock` and `flake.lock`. The table records direct
crate purposes and declared SPDX licenses; `just supply-chain` checks the graph
against `deny.toml` and known RustSec advisories.

| Dependency | Purpose | Role | Declared license |
| --- | --- | --- | --- |
| anyhow | CLI error context | runtime | MIT OR Apache-2.0 |
| async-trait | injectable AdGuard reader trait | runtime | MIT OR Apache-2.0 |
| base64 | Declared but unused directly; reqwest owns Basic encoding | declared runtime | MIT OR Apache-2.0 |
| clap | CLI parsing | runtime | MIT OR Apache-2.0 |
| futures | bounded concurrent observation | runtime | MIT OR Apache-2.0 |
| jiff | timestamps and bundled IANA time zones | runtime | Unlicense OR MIT |
| reqwest | bounded rustls HTTP client | runtime | MIT OR Apache-2.0 |
| rusqlite | transactional SQLite state | runtime | MIT |
| rustls | TLS with the ring provider | runtime | Apache-2.0 OR ISC OR MIT |
| schemars | versioned JSON Schema generation | build/runtime CLI | MIT |
| secrecy | redaction-safe secret values | runtime | Apache-2.0 OR MIT |
| semver | AdGuard compatibility gate | runtime | MIT OR Apache-2.0 |
| serde, serde_json, toml | strict formats | runtime | MIT OR Apache-2.0 |
| sha2 | configuration/condition fingerprints and state checksum | runtime | MIT OR Apache-2.0 |
| thiserror | typed library failures | runtime | MIT OR Apache-2.0 |
| tokio | bounded asynchronous orchestration | runtime | MIT |
| tracing, tracing-subscriber | redacted diagnostics | runtime | MIT |
| url | target URL validation | runtime | MIT OR Apache-2.0 |
| uuid | opaque run and outbox identifiers | runtime | Apache-2.0 OR MIT |
| webpki-roots | bundled public TLS trust roots | runtime | CDLA-Permissive-2.0 |
| httpmock | local HTTP and HTTPS test servers | test | MIT |
| jsonschema | recursive validation of produced reports against the public schema | test | MIT |
| tempfile | isolated test configuration and state | test | MIT OR Apache-2.0 |

The report contract tests disable `jsonschema`'s default HTTP/file resolvers and
use its offline validator. Schema references cannot fetch network or local files.
The validator is a development dependency and is absent from the shipped binary.

Nix supplies the compiler and check tools. SQLite is bundled through rusqlite;
Jiff embeds the IANA database. Review the tzdb release when updating Jiff.
Both HTTP adapters configure rustls with bundled `webpki-roots` and ring;
reqwest's platform certificate verifier is not used.

Before distributing binaries, assemble the applicable direct and transitive
license notices. This register is not an artifact notice bundle.

## Accepted duplicate versions

`deny.toml` allows duplicate versions with warnings. Review the following
upstream splits when `Cargo.lock` changes; do not override dependency requirements
just to silence them.

| Crate | Versions | Reason |
| --- | --- | --- |
| base64 | 0.22, 0.23 | Runtime encoding uses 0.23; test-only `headers` still requires 0.22 |
| bit-vec | 0.8, 0.9 | The schema validator's regex engine and HTTPS test certificate tooling use different versions |
| block-buffer, crypto-common, digest, cpufeatures | two release lines each | Runtime SHA-256 and test-only `headers` SHA-1 require different crypto dependency lines |
| getrandom | 0.2, 0.3, 0.4 | Runtime dependents use 0.2 and 0.4; the test-only schema validator adds 0.3 |
| hashbrown | 0.16, 0.17 | Interior map dependency of crates that upgraded on different schedules |
| syn, synstructure | 2/3 and 0.13/0.14 | Proc-macro dependencies; build-time only, absent from the binary |
| bitflags, r-efi | 1/2 and 5/6 | Upstream optional-feature and platform dependencies require different versions |
| windows-sys | 0.52, 0.61 | Platform bindings; not reached in the Linux or macOS builds this project targets |

Inspect the complete target-specific graph with
`cargo tree --locked --target all --duplicates`.

`generic-array` remains at 0.14.7 because `crypto-common` 0.1.7 requires that
exact version.
