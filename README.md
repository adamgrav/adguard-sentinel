# AdGuard Sentinel

AdGuard Sentinel is a read-only operational and declared-policy monitor for
independent AdGuard Home resolvers. It has no AdGuard mutation API and never
retrieves query logs.

The project is pre-release. Read [the product contract](docs/PRODUCT.md),
[MVP scope](docs/MVP_SCOPE.md), and [architecture](docs/ARCHITECTURE.md) before
using it.

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

No live AdGuard Home or Pushover service is contacted by the test suite.

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

Provisionally licensed under either Apache-2.0 or MIT, at your option. A final
dependency and notice review is required before public release.
