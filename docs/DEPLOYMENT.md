# Direct deployment and acceptance

AdGuard Sentinel runs on one monitor host and observes every configured resolver
over the read-only API. Target resolver hosts do not need the binary installed.

## Host build

From the monitor host checkout:

```sh
nix flake check
nix develop -c just check
nix build .#packages.x86_64-linux.default
./result/bin/adguard-sentinel --help
```

These commands prove the Linux build and deterministic checks on that host, not
service deployment.

## Manual read-only smoke test

1. Create a root-readable TOML based on `config.example.toml`.
2. Use the actual resolver HTTPS URLs and declared policy.
3. Point each target at an existing protected password file.
4. Keep notifications disabled.
5. Use a dedicated dry-run SQLite path in a `0700` directory.

Run:

```sh
sudo ./result/bin/adguard-sentinel validate-config --config /run/adguard-sentinel-smoke.toml
sudo ./result/bin/adguard-sentinel check \
  --config /run/adguard-sentinel-smoke.toml \
  --dry-run \
  --format json
sudo ./result/bin/adguard-sentinel report \
  --state /var/lib/adguard-sentinel-smoke/state.sqlite \
  --limit 1 \
  --format json
```

Acceptance requires exit zero, every target complete, supported server versions,
expected policy, no unexpected findings, and a readable persisted report.

## Isolated alert and recovery

Use a second dry-run state database and a one-target configuration. Set API
availability sustain to one, point the target at an unused loopback port, and
run once. Expect an incomplete target, API-unavailable finding, suppressed alert
transition, and exit three. Restore the same target ID to a real read-only API
URL and run again. Expect a complete observation and suppressed resolution.

This exercises the packaged state machine without changing a resolver. Real
notification delivery requires a separately authorized test route.

## NixOS service acceptance

The host integration should use a `DynamicUser`, a `0700` `StateDirectory`,
secrets supplied through `LoadCredential`, a restrictive sandbox, and a oneshot
service driven by a persistent timer. Start the service manually before enabling
the timer. Require twelve consecutive successful timer runs, one service
restart, growing SQLite history, clean journald output, and successful external
job-health events if a job-health monitor is configured.

If Sentinel replaces an existing monitor, keep that monitor's definition and
state available but disabled for an initial rollback window, and never run two
notification-producing monitors against the same targets at the same time.
Rollback stops the Sentinel timer, restores the previous declarative unit
selection and job-health target, and verifies one successful run.
