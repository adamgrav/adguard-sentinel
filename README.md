# AdGuard Sentinel

AdGuard Sentinel is a read-only operational and declared-policy monitor for
independent AdGuard Home resolvers. It has no AdGuard mutation API and never
retrieves query logs.

Read [the product contract](docs/PRODUCT.md), [MVP scope](docs/MVP_SCOPE.md),
[behavior contract](docs/BEHAVIOR.md), [architecture](docs/ARCHITECTURE.md), and
[deployment guide](docs/DEPLOYMENT.md) before using it.

## Support

Sentinel builds from source on `x86_64` Linux with Rust 1.97.1, and Nix provides
the reproducible packaging path. Pushover is the only notification provider, and
a systemd timer is the only supported scheduling method. AdGuard Home
`>=0.107.78,<0.108.0` is the supported API range.

There are no prebuilt binaries, no musl build, no container image, and no
reusable NixOS service module.

[`docs/SUPPORT.md`](docs/SUPPORT.md) is the authoritative matrix and records the
evidence level behind every one of those claims, including which are still
unverified.

## Development

Inspect [`.envrc`](.envrc), then:

```sh
direnv allow
just check
```

Without direnv:

```sh
nix flake check
nix develop -c just check
```

No live AdGuard Home or Pushover service is contacted by the test suite. The
`supply-chain` step refreshes the RustSec advisory database, so `just check`
needs network access; every other step is offline.

## CLI

```text
adguard-sentinel validate-config --config PATH
adguard-sentinel check --config PATH
adguard-sentinel check --config PATH --dry-run
adguard-sentinel report --state PATH
adguard-sentinel migrate-state --state PATH
adguard-sentinel print-schema config --version 1
```

Use `--help` for the complete option surface. The default `--fail-on never`
keeps ordinary findings separate from execution health, which is usually what a
service manager should see.

`--dry-run` still performs real read-only requests against your resolvers and
still writes to the state database it is pointed at. What it never does is load
or send notification credentials. A state database is permanently bound to live
or dry-run use after its first run, so give a dry run its own path.

## License

Licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at
your option. Third-party dependency licenses are registered in
[`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md) and enforced by `just
supply-chain`, which also checks RustSec advisories, banned crates, and
permitted sources.
