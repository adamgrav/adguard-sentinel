# Support matrix

This page states what is supported and what evidence stands behind each claim. It
distinguishes a configuration that has been built and tested from one that has
been run against live resolvers over time. No claim here is inferred from a
different configuration working.

## Evidence levels

| Level | Meaning |
| --- | --- |
| **Verified** | The package builds and the full test suite passes in this configuration, in a recorded run |
| **Pending** | An automated check for this configuration exists but has not run yet. Treat as unverified |
| **Expected** | Should work by construction, with no recorded run. Treat as untested |
| **Unsupported** | Explicitly out of scope for this release. Not tested, not claimed |

## Platforms

| OS | Architecture | Role | Install method | Evidence |
| --- | --- | --- | --- | --- |
| macOS | `aarch64` | Development only | Nix flake | **Verified**: package built and full suite run |
| Linux | `x86_64` | Deployment and development | Nix flake | **Verified** in CI |
| Linux | `x86_64` | Deployment and development | Source build with rustup | **Verified** in CI |
| Linux | `aarch64` | Deployment and development | Nix flake | **Verified** in CI |
| macOS | any | Deployment | — | **Unsupported**: no systemd, so no supported scheduling path |
| Windows | any | — | — | **Unsupported** |

macOS is a development platform only. The package builds and the whole suite runs
there, which is why it is listed, but there is no supported way to schedule
Sentinel on it.

Every Linux row is re-established on every push to `main`. Two native Nix jobs
build the flake package and run the full suite, on `ubuntu-24.04` and
`ubuntu-24.04-arm`, and a separate job builds `x86_64` from source with rustup.
A row is marked **Verified** only for that exact configuration, never by
inference from a related one passing, which is why `aarch64` has no rustup row:
that build has never been run.

## Toolchain

| Item | Value | Notes |
| --- | --- | --- |
| Rust | `1.97.1` | Pinned in `rust-toolchain.toml`; every Rust CI job uses exactly this version |
| Edition | 2024 | |
| Build inputs | C compiler and linker | SQLite is compiled from source through `rusqlite`'s bundled feature |
| Nix | flake with `nixpkgs` `nixos-26.05` | Pinned in `flake.lock` |

Only the pinned Rust version is supported. Newer versions will often work; none
is tested.

## AdGuard Home

| Item | Value |
| --- | --- |
| Supported API range | `>=0.107.78,<0.108.0` |
| Enforcement | An unsupported version is rejected at the request boundary before any other endpoint is read, and the range is fixed by configuration validation |
| Live verification | Read-only observation of live AdGuard Home `0.107.78` instances, performed by the maintainer. The request boundary and response normalisation are unchanged since that run |

The range is deliberately narrow. Sentinel reads a fixed set of endpoints and
fails closed on anything it does not recognise, so a wider range would be a claim
without evidence. Patch releases inside the range are tolerated because unknown
response fields are ignored.

Since 0.1.1 a different range can be configured, but only deliberately:
`observation.allow_untested_adguard_version = true` is required alongside it, and
every run then warns. That configuration is **Unsupported** in the sense this
page uses the word — it is not tested and nothing here is claimed for it. The
switch exists so that a new AdGuard Home minor release does not leave you with no
option but to stop monitoring, and so that the untested choice is recorded in the
configuration rather than made silently.

## API authentication

| Mode | Status |
| --- | --- |
| `none` | Supported. No username or password file is loaded, and no `Authorization` header is sent |
| `basic` | Supported. Username plus a non-empty password file are required; credentials never come from arguments or environment variables |

Omitting `auth` retains the pre-0.2 behavior and selects `basic`. Explicitly use
`auth = "none"` for an unauthenticated resolver or for a trusted proxy or VPN
boundary that does not need an AdGuard credential.

## Runtime dependencies

A built binary has none beyond libc. Specifically:

| Concern | How it is removed | Evidence |
| --- | --- | --- |
| System SQLite | Compiled into the binary via `rusqlite`'s bundled feature | Confirmed on the macOS release binary, which links only `libSystem` and `libiconv`. The CI job asserts the same for Linux with `ldd` |
| OpenSSL | TLS is rustls; `reqwest` is built with `default-features = false` | Same as above. The binary does contain `ring`'s OpenSSL-derived assembly, statically compiled and clarified in `deny.toml`, but links no `libssl` or `libcrypto` |
| System `tzdata` | The IANA database is embedded, and the code calls the bundled database explicitly rather than the system one | `TimeZoneDatabase::bundled()` in `sentinel-core`, plus a test covering both Amsterdam DST edges |

## Notifications

| Provider | Status |
| --- | --- |
| Pushover | Supported, and the only provider in this release |
| Anything else | **Unsupported** |

Notifications can also be disabled entirely, which is the configuration default.

## Scheduling

| Method | Status |
| --- | --- |
| systemd timer | Supported. An example unit pair is in `docs/DEPLOYMENT.md` |
| Cron, runit, s6, container schedulers, manual invocation | **Unsupported** for this release |

Sentinel is an ordinary oneshot process, so it will probably run under any
scheduler. Nothing in this repository establishes credential handling, state
directory permissions, or timing behaviour on those paths, so they are not
claimed.

## Deliberately not offered

Sentinel is a scheduled, read-only observer. Most of the list below follows from
that shape rather than from a lack of time.

| Item | Decision |
| --- | --- |
| A web UI or HTTP server | Out of scope. Sentinel has no interface to serve; the run report is its output |
| A long-running daemon | Out of scope. It is a oneshot process driven by a timer, so there is no process to keep alive and no in-memory state to lose |
| Prometheus metrics or HTML output | Out of scope. Versioned JSON and JSONL are the automation interface; see `docs/SCHEMAS.md` |
| Notification providers other than Pushover | Out of scope for this release |
| Any AdGuard `POST`, `PUT`, `PATCH`, or `DELETE` | Never. The client cannot express a mutation; see ADR 0001 |
| Query logs, top domains, client identities, caches, sessions, or persistent clients | Never. Reading them is outside the allowlist in `docs/API_ALLOWLIST.md` |
| DNS canary probes | Out of scope. Sentinel observes an instance's own reported state, it does not generate traffic |
| Prebuilt release binaries | Post-release. Shipping one makes this project the distributor of a linked artifact, which brings third-party notice obligations that are not yet discharged |
| musl static builds | Post-release, and dependent on the above |
| Signed binaries or artifacts | Post-release |
| crates.io publication | Not planned; `publish = false` |
| A reusable NixOS service module | Out of scope by ADR 0009. Host integration belongs to the operator's own configuration |
| Container images | Out of scope |

## What no amount of green CI proves

CI proves the package builds and the suite passes. It does not prove live AdGuard
Home compatibility for a version outside the tested one, network reachability,
credential handling on your host, timer behaviour, real notification delivery, or
job-health integration. Those are properties of a deployment, and
`docs/DEPLOYMENT.md` describes how to establish them on yours.
