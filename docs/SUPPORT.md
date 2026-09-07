# Support and evidence

## Platforms

| Platform | Role | Installation | Recorded evidence |
| --- | --- | --- | --- |
| Linux `x86_64` | Deployment and development | Nix | Native Ubuntu CI build and full checks |
| Linux `aarch64` | Deployment and development | Nix | Native Ubuntu ARM CI build and full checks |
| Linux `x86_64` | Deployment and development | rustup source build | Ubuntu CI build, lint, and tests |
| macOS `aarch64` | Development | Nix | Maintainer-recorded package builds and checks |

[CI for 0.3.0's documentation commit](https://github.com/adamgrav/adguard-sentinel/actions/runs/33100163327)
records all three Linux jobs. [ci.yml](../.github/workflows/ci.yml) runs them on
pull requests and pushes to `main`; consult the result for the commit you use.
macOS deployment and Windows are unsupported. ARM source builds outside Nix
have no recorded verification.

Builds use Rust `1.97.1`, edition 2024. Nix pins `nixpkgs` and the Rust overlay in
`flake.lock`; source builds need a C compiler/linker for bundled SQLite. Only
the pinned Rust version is tested.

## AdGuard Home

The default supported range is `>=0.107.78,<0.108.0`. Maintainer live observations
were against `0.107.78`; synthetic fixtures and mock-server tests cover the
request and decoder boundaries. Patch versions within the range are accepted,
but have not each been tested live. Unknown extra response fields are ignored;
required fields remain strict.

A different range requires
`observation.allow_untested_adguard_version = true` alongside
`adguard_version_requirement`. Each run then warns. The configured range is
still enforced before later endpoints are requested. An override is an untested
operator choice, not an extension of support.

Both `auth = "none"` and `auth = "basic"` are supported. Omitting `auth` selects
Basic for compatibility. No-auth sends no `Authorization` header; Basic reads
its password from a file. [DEPLOYMENT](DEPLOYMENT.md) documents both modes.

## Runtime and scheduling

SQLite and IANA time-zone data are embedded; TLS uses rustls. No system SQLite,
OpenSSL, or `tzdata` installation is required. The source-build CI job inspects
Linux linkage with `ldd` for SQLite and OpenSSL dependencies; the bundled
Amsterdam DST test covers time-zone lookup. These checks do not claim a fully
static binary or enumerate every platform runtime library.

A systemd timer is the supported recurring deployment. Manual validation,
observation, and reporting are supported operator commands. Other schedulers
have no documented deployment acceptance. The [example units](DEPLOYMENT.md#run-with-systemd)
require systemd credential support and must be validated on the target host.

Pushover is the only notification provider. Notifications default to disabled;
JSON/JSONL reports and exit codes are available for operator-owned integrations.

## Scope

- No mutation, query-log retrieval, synchronization, remediation, or telemetry.
  [API_ALLOWLIST](API_ALLOWLIST.md) defines the complete AdGuard surface.
- No web UI, HTTP server, daemon, Prometheus endpoint, or HTML output.
- No DNS canary probes. Sentinel observes reported API state; a behavioral
  finding does not prove the cause of a traffic change.
- No prebuilt binaries, signed artifacts, musl releases, or container images.
- No crates.io publication or reusable NixOS service module. Host integration
  belongs to the operator; see [ADR 0009](decisions/0009-nix-package-boundary.md).

## Deployment evidence

CI does not verify the operator's resolver version, credentials, network path,
timer, job-health integration, or real notification delivery. Establish those
through [deployment acceptance](DEPLOYMENT.md#inspect-and-accept).
