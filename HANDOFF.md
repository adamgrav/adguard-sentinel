# AdGuard Sentinel MVP handoff

## Outcome

The standalone MVP is implemented on `feat/mvp`. The dotfiles repository was
not edited. No remote, live AdGuard request, real Pushover message, NixOS module,
rebuild, switch, or deployment was created.

Implemented:

- Four-crate Rust 2024 workspace pinned to Rust 1.97.1.
- Strict version-1 TOML configuration and generated JSON Schema.
- Six-method private AdGuard GET allowlist with rustls, no redirects/proxy,
  Basic Auth redaction, timeouts, and response-size enforcement.
- Strict operational parsing, declared policy checks, documented behavior
  formulas, independent target state, and bounded concurrency.
- SQLite v1 with checksummed schema, transactions, retention, latches, auth
  cooldowns, detailed observations, transactional outbox, and read-only reports.
- Pushover delivery classification for delivered, retryable, permanent, and
  ambiguous outcomes. Ambiguous outcomes are never resent automatically.
- Dry/live state separation and dry-run proof that Pushover credentials are not
  loaded.
- Generated schemas, synthetic API fixtures, package/dev-shell flake, licenses,
  dependency policy, pinned CI actions, and operator documentation.

Privacy hardening: external Pushover payloads contain condition summaries only.
Structured expected/observed values and error detail remain local in SQLite and
the versioned report. This preserves batching, priorities, latching, and
resolution rules without exporting structured evidence.

## Validation executed

The local checkout path is redacted below; each `path:<checkout>` command was
run against the full uncommitted repository rather than Git's tracked-file view.

- `nix develop path:<checkout> -c just check` — passed.
  - `cargo fmt --all -- --check`
  - `nixfmt --check flake.nix`
  - Clippy for workspace/all targets/all features with `-D warnings`
  - Rust unit/integration tests and doc tests
  - workspace build for all targets/features
  - generated schema drift check
  - cargo-deny license, ban, and source checks
- `nix flake check path:<checkout>` — passed and built the native
  aarch64-Darwin package derivation.
- `nix flake check --all-systems --no-build path:<checkout>` — passed;
  x86_64-Linux package/check/dev-shell/formatter derivations evaluated.
- `nix run path:<checkout> -- --help` — passed; packaged CLI entrypoint launched.
- Static audits found no private HomeLab addresses/domains, absolute home paths,
  unsafe project code, or AdGuard mutation/query-log endpoint.

Cargo-deny reports warning-only duplicate transitive versions for `getrandom`,
`hashbrown`, `syn`, `windows-sys`, and `winnow`; enforced bans, licenses, and
sources pass. CDLA-Permissive-2.0 is documented and allowed solely for the
public webpki root-data dependency.

## Not proven

- x86_64-Linux was evaluated but not built on this Mac. CI or a Linux builder
  must supply that acceptance evidence.
- GitHub Actions has not run remotely.
- `direnv allow` was not run.
- Live AdGuard version/response compatibility, TLS, credentials, network
  reachability, timing, and zero-mutation traffic are not proven.
- Real Pushover delivery, Healthchecks, systemd sandboxing/timer behavior,
  direct deployment, cutover, and rollback are not proven.
- No transitive notices artifact or public-release legal review has been done.

## Required next task

Run the normal tracked-clone commands and obtain a real x86_64-Linux build on
the monitor host. Then follow `docs/DEPLOYMENT.md` and prepare the separate
dotfiles integration. That task still requires Adam's authorization for source
pinning, dotfiles edits, test-notification credentials, build/switch, and
cutover.
