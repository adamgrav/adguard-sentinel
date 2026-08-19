# Deployment and acceptance

AdGuard Sentinel runs on one monitor host and observes every configured resolver
over the read-only API. Target resolver hosts do not need the binary installed.

Read `docs/SUPPORT.md` first. It states which platforms and installation methods
have real evidence behind them and which do not.

## Build prerequisites

Sentinel links SQLite, TLS, and the IANA time zone database into the binary, so a
built binary needs no system SQLite, OpenSSL, or `tzdata`. Building it needs:

- Rust `1.97.1`, the version pinned in `rust-toolchain.toml`. `rustup` reads that
  file automatically inside the checkout.
- A C compiler and linker, because SQLite is compiled from source through
  `rusqlite`'s bundled feature. On Debian and Ubuntu, `build-essential` is
  sufficient.

No `pkg-config` module, system library, or network service is required at build
time beyond fetching crates.

## Install with Nix

This is the first-class path and the only one with reproducibility guarantees.

```sh
nix build github:adamgrav/adguard-sentinel
./result/bin/adguard-sentinel --help
```

From a checkout, to reproduce the full check suite as well:

```sh
nix flake check
nix develop -c just check
nix build
./result/bin/adguard-sentinel --help
```

## Install on generic Linux from source

```sh
git clone https://github.com/adamgrav/adguard-sentinel
cd adguard-sentinel
cargo build --locked --release
install -Dm755 target/release/adguard-sentinel /usr/local/bin/adguard-sentinel
adguard-sentinel --help
```

Keep `--locked`. It makes the build use the committed `Cargo.lock` instead of
resolving newer dependency versions.

To install a tagged release directly without keeping a checkout:

```sh
cargo install --locked --git https://github.com/adamgrav/adguard-sentinel --tag vX.Y.Z adguard-sentinel
```

This is a Git installation; Sentinel is not published to crates.io.

## Configure

Start with `config.minimal.toml` for one resolver without authentication. Its URL
is synthetic and must be replaced. Use `config.example.toml` as the complete
reference when adding Basic authentication, policy, behavioural analysis, or
Pushover; every `.invalid` name and RFC 5737 address in it is synthetic.

```sh
install -Dm600 config.minimal.toml /etc/adguard-sentinel/config.toml
adguard-sentinel validate-config --config /etc/adguard-sentinel/config.toml
```

`validate-config` checks the schema, cross-references, URLs, bounds, and that
every referenced Basic-auth or Pushover secret file exists and is non-empty. It
contacts no network service. With `auth = "none"`, omit both `username` and
`password_file`; Sentinel sends no `Authorization` header. Basic authentication
keeps credentials file-only:

```toml
auth = "basic"
username = "admin"
password_file = "/run/credentials/adguard-sentinel.service/resolver-password"
```

The omitted state, observation, condition-profile, and notification sections use
the values in `config.example.toml`. The behavioural baseline and every policy
field are opt-in. A missing policy field creates no condition rather than a
`clear` condition.

Then take one real observation before installing any service. Use a **separate**
state path for this, because a state database is permanently bound to live or
dry-run use after its first run. Keep the production configuration untouched and
append a temporary state section to a copy:

```sh
cp /etc/adguard-sentinel/config.toml /tmp/adguard-sentinel-dry-run.toml
printf '\n[state]\npath = "/tmp/adguard-sentinel-dry-run.sqlite"\nretention_days = 21\n' >> /tmp/adguard-sentinel-dry-run.toml
```

```sh
adguard-sentinel check \
  --config /tmp/adguard-sentinel-dry-run.toml \
  --dry-run \
  --format json
```

Note that `--dry-run` still performs real read-only requests against your
resolvers and still writes to the state database it is pointed at. What it never
does is load or send notification credentials. The untouched production
configuration continues to default to `/var/lib/adguard-sentinel/state.sqlite`.

Acceptance for this step is exit zero, every target complete, supported server
versions, every configured policy condition matching, no unexpected findings,
and a readable persisted report.

## Run on a schedule with systemd

Sentinel is a oneshot process, not a daemon. It is designed to be driven by a
timer. This repository ships a binary package, not a service unit, so the units
below are an example to adapt rather than a supported interface.

`/etc/systemd/system/adguard-sentinel.service`:

```ini
[Unit]
Description=AdGuard Sentinel read-only resolver observation
Documentation=https://github.com/adamgrav/adguard-sentinel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/adguard-sentinel check --config /etc/adguard-sentinel/config.toml
DynamicUser=yes
StateDirectory=adguard-sentinel
StateDirectoryMode=0700
UMask=0077
TimeoutStartSec=120

CapabilityBoundingSet=
NoNewPrivileges=yes
PrivateDevices=yes
PrivateTmp=yes
ProtectClock=yes
ProtectControlGroups=yes
ProtectHome=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectProc=invisible
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
LockPersonality=yes
MemoryDenyWriteExecute=yes
```

`/etc/systemd/system/adguard-sentinel.timer`:

```ini
[Unit]
Description=Run AdGuard Sentinel every five minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true
AccuracySec=30s

[Install]
WantedBy=timers.target
```

The unit above matches `config.minimal.toml`: no resolver or notification
credentials are loaded. When Basic authentication or Pushover is configured,
add one `LoadCredential` line per secret. `LoadCredential` exposes each secret
read-only under `/run/credentials/adguard-sentinel.service/<id>`, so the
configuration should point there rather than at the file on disk:

```ini
LoadCredential=resolver-password:/etc/adguard-sentinel/secrets/resolver-password
```

```toml
password_file = "/run/credentials/adguard-sentinel.service/resolver-password"
```

`StateDirectory=adguard-sentinel` gives the service a private
`/var/lib/adguard-sentinel`, matching the default
`state.path = "/var/lib/adguard-sentinel/state.sqlite"`. Sentinel creates the
database with `0600` permissions.

Install and verify:

```sh
systemctl daemon-reload
systemctl start adguard-sentinel.service
systemctl status adguard-sentinel.service
journalctl -u adguard-sentinel.service -n 50
systemctl enable --now adguard-sentinel.timer
```

Start the service manually and inspect one run before enabling the timer.

Leave `--fail-on` at its default. A finding is a statement about your resolvers,
not about whether Sentinel executed correctly, and raising `--fail-on` makes the
unit fail on ordinary findings.

### Other schedulers

Only the systemd path above has been exercised. Cron, runit, s6, container
schedulers, and manual invocation are **not supported for the MVP**. Sentinel
itself is an ordinary oneshot process, so it will probably work under any of
them, but nothing in this repository establishes the credential handling, state
directory permissions, or timing behaviour on those paths.

## Inspect and remove

```sh
adguard-sentinel report --state /var/lib/adguard-sentinel/state.sqlite --limit 5
adguard-sentinel report --state /var/lib/adguard-sentinel/state.sqlite \
  --limit 1 --format json
```

To remove Sentinel completely:

```sh
systemctl disable --now adguard-sentinel.timer
systemctl stop adguard-sentinel.service
rm /etc/systemd/system/adguard-sentinel.service /etc/systemd/system/adguard-sentinel.timer
systemctl daemon-reload
rm -rf /var/lib/adguard-sentinel /etc/adguard-sentinel
rm /usr/local/bin/adguard-sentinel
```

Removing the state directory discards observation history and every latch, so a
reinstall starts a fresh behavioural baseline.

## Isolated alert and recovery exercise

Use a second dry-run state database and a one-target configuration. Set API
availability sustain to one, point the target at an unused loopback port, and run
once. Expect an incomplete target, an API-unavailable finding, a suppressed
alert transition, and exit three. Restore the same target ID to a real read-only
API URL and run again. Expect a complete observation and a suppressed
resolution.

This exercises the packaged state machine without changing a resolver. Real
notification delivery requires a separately arranged test route.

## Service acceptance

Require twelve consecutive successful timer runs, one service restart, growing
SQLite history, clean journald output, and successful external job-health events
if a job-health monitor is configured.

If Sentinel replaces an existing monitor, keep that monitor's definition and
state available but disabled for an initial rollback window, and never run two
notification-producing monitors against the same targets at the same time.
Rollback stops the Sentinel timer, restores the previous unit selection and
job-health target, and verifies one successful run.
