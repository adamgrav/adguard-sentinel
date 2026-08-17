# AdGuard Sentinel

AdGuard Sentinel is a read-only operational and declared-policy monitor for
independent AdGuard Home resolvers. It has no AdGuard mutation API and never
retrieves query logs.

Read [the product contract](docs/PRODUCT.md), [MVP scope](docs/MVP_SCOPE.md),
[behavior contract](docs/BEHAVIOR.md), [architecture](docs/ARCHITECTURE.md), and
[deployment guide](docs/DEPLOYMENT.md) before using it.

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
keeps ordinary findings separate from execution health.

## License

Licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at
your option. Third-party dependency licenses are registered in
[`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md) and enforced by `just
supply-chain`, which also checks RustSec advisories, banned crates, and
permitted sources.
