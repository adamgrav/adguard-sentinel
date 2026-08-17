# Support matrix

This page states what is actually supported and what evidence stands behind each
claim. It deliberately distinguishes "we built it and ran the suite" from "we ran
it against live resolvers for a sustained period". Nothing here is inferred from
something else working.

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
| Linux | `x86_64` | Deployment and development | Nix flake | **Pending**: flake outputs evaluate; the CI job that builds them has not run yet |
| Linux | `x86_64` | Deployment and development | Source build with rustup | **Pending**: the CI job exists but has not run yet |
| Linux | `aarch64` | — | — | **Unsupported** |
| macOS | any | Deployment | — | **Unsupported**: no systemd, so no supported scheduling path |
| Windows | any | — | — | **Unsupported** |

macOS is a development platform only. The package builds and the whole suite runs
there, which is why it is listed, but there is no supported way to schedule
Sentinel on it.

The two **Pending** rows become **Verified** on the first green CI run for a
given commit, and not before. Until then this project makes no supported-platform
claim for Linux, even though Linux is its intended deployment target and the
`x86_64-linux` flake outputs are known to evaluate.

## Toolchain

| Item | Value | Notes |
| --- | --- | --- |
| Rust | `1.97.1` | Pinned in `rust-toolchain.toml`; both CI jobs use exactly this version |
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

Notifications can also be disabled entirely, which is the default in
`config.example.toml`.

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

| Item | Decision |
| --- | --- |
| Prebuilt release binaries | Post-MVP. Shipping one makes this project the distributor of a linked artifact, which brings third-party notice obligations that are not yet discharged |
| musl static builds | Post-MVP, and dependent on the above |
| Signed binaries or artifacts | Post-MVP |
| crates.io publication | Not planned; `publish = false` |
| A reusable NixOS service module | Out of scope by ADR 0009. Host integration belongs to the operator's own configuration |
| Container images | Out of scope |

## What no amount of green CI proves

CI proves the package builds and the suite passes. It does not prove live AdGuard
Home compatibility for a version outside the tested one, network reachability,
credential handling on your host, timer behaviour, real notification delivery, or
job-health integration. Those are properties of a deployment, and
`docs/DEPLOYMENT.md` describes how to establish them on yours.
