# Deployment and acceptance

Install Sentinel on one monitor host. Resolver hosts need only expose their
AdGuard Home API. [SUPPORT](SUPPORT.md) records supported platforms and evidence.
Commands below use a POSIX shell on Linux; `sudo` marks host-level installation.

## Install

### Nix

Build from a checkout with `nix build`, or pin a released source:

```sh
nix build github:adamgrav/adguard-sentinel/v0.3.0
./result/bin/adguard-sentinel --help
```

For a persistent systemd installation, keep the output rooted:

```sh
sudo nix build github:adamgrav/adguard-sentinel/v0.3.0 --out-link /opt/adguard-sentinel
/opt/adguard-sentinel/bin/adguard-sentinel --help
```

Use `/opt/adguard-sentinel/bin/adguard-sentinel` for both binary paths in the
unit below. An operator-owned NixOS configuration can reference the package
directly instead; this repository exports no service module.

### Source or Cargo

Building requires Rust 1.97.1 and a C compiler/linker. `rustup` reads the pinned
version inside the checkout. SQLite, TLS, and time-zone data are bundled; no
system SQLite or OpenSSL development package is needed.

```sh
git clone https://github.com/adamgrav/adguard-sentinel
cd adguard-sentinel
cargo build --locked --release
sudo install -Dm755 target/release/adguard-sentinel /usr/local/bin/adguard-sentinel
```

Alternatively, install a tag into your Cargo bin directory:

```sh
cargo install --locked --git https://github.com/adamgrav/adguard-sentinel --tag v0.3.0 sentinel-cli
adguard-sentinel --help
```

`sentinel-cli` is the package name; `adguard-sentinel` is its binary. To use a
Cargo-installed binary with the unit below, install that binary at
`/usr/local/bin/adguard-sentinel` first. `ProtectHome=yes` prevents the service
from using a binary under a home directory.

## Configure

Start with [config.minimal.toml](../config.minimal.toml), replace its URL, and
follow the [first-observation walkthrough](../README.md#first-observation).
For manual Basic-auth observations, use a password file readable by your user
and keep notifications disabled. Dry-run still contacts resolvers and writes
state; use a dedicated database.

For the service, copy your configuration into a root-owned file:

```sh
sudo install -d -m755 /etc/adguard-sentinel
sudo install -m600 config.toml /etc/adguard-sentinel/config.toml
```

The unit loads this private file with `LoadCredential=config:...` and reads its
service-local copy through `%d/config`. A dynamic user cannot read the original
root-owned `0600` file directly.

### Basic authentication

For each authenticated target, use these fields inside its `[[targets]]` table:

```toml
auth = "basic"
username = "admin"
password_file = "/run/credentials/adguard-sentinel.service/resolver-password"
```

Store the password in `/etc/adguard-sentinel/secrets/resolver-password` and add
this line to the unit's `[Service]` section:

```ini
LoadCredential=resolver-password:/etc/adguard-sentinel/secrets/resolver-password
```

Use a distinct credential ID and file for each resolver. With `auth = "none"`,
omit both `username` and `password_file`, and omit the corresponding credential
line.

### Pushover

Replace `[notifications]` with this complete configuration when you are ready
for real alerts:

```toml
[notifications]
provider = "pushover"

[notifications.pushover]
application_token_file = "/run/credentials/adguard-sentinel.service/pushover-application-token"
user_key_file = "/run/credentials/adguard-sentinel.service/pushover-user-key"
```

Add both credential lines to `[Service]`:

```ini
LoadCredential=pushover-application-token:/etc/adguard-sentinel/secrets/pushover-application-token
LoadCredential=pushover-user-key:/etc/adguard-sentinel/secrets/pushover-user-key
```

Create the secret directory with mode `0700` and each root-owned secret file
with mode `0600`. Enter values through an editor or your secret manager; do not
put them in command arguments or the TOML. Each file contains only its credential
value. The application token and user key are separate Pushover credentials.

[Systemd credentials](https://systemd.io/CREDENTIALS/) exist only while the unit
runs. Manual `validate-config` against the service configuration can therefore
fail outside the unit. The unit's `ExecStartPre` validates it after credentials
are loaded. Validation checks file metadata; Pushover accepts or rejects the
values only when a message is sent. For manual runs, use readable absolute secret
paths instead of `/run/credentials/...`.

To disable notifications, use `provider = "disabled"`, remove the
`[notifications.pushover]` table, and remove its two credential lines. A disabled
run suppresses transitions; enabling delivery later does not replay suppressed
alerts.

## Run with systemd

First check credential access on the Linux host:

```sh
bash tools/check-systemd-credentials.sh /usr/local/bin/adguard-sentinel
```

Use your Nix binary path instead if needed. The helper starts a transient unit
with a dynamic user, private synthetic configuration, and three dummy credential
files. It runs only `validate-config`: no resolver requests, state writes, or
notifications. Expect `configuration is valid`, a successful unit exit, and
`PASS`. If it fails, stop before installing the real service and inspect the
diagnostic. This check requires Linux/systemd and is not exercised by local
macOS checks or the Rust suite.

Create `/etc/systemd/system/adguard-sentinel.service` with mode `0644`:

```ini
[Unit]
Description=AdGuard Sentinel read-only resolver observation
Documentation=https://github.com/adamgrav/adguard-sentinel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
LoadCredential=config:/etc/adguard-sentinel/config.toml
ExecStartPre=/usr/local/bin/adguard-sentinel validate-config --config %d/config
ExecStart=/usr/local/bin/adguard-sentinel check --config %d/config
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

Add the credential lines needed by your configuration. The default state path
matches `StateDirectory`, which supplies private writable storage. Leave
`--fail-on` at `never`; ordinary findings should not fail the unit. Adjust
`TimeoutStartSec` if your target count and timeouts require more than 120 seconds.

Create `/etc/systemd/system/adguard-sentinel.timer` with mode `0644`:

```ini
[Unit]
Description=Run AdGuard Sentinel every five minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
```

This monotonic timer runs after boot and then relative to the previous
activation. It does not replay checks missed while the host was off.

Validate the units, then start one observation before enabling the timer:

```sh
sudo systemd-analyze verify /etc/systemd/system/adguard-sentinel.service /etc/systemd/system/adguard-sentinel.timer
sudo systemctl daemon-reload
sudo systemctl start adguard-sentinel.service
sudo systemctl show adguard-sentinel.service -p Result -p ExecMainStatus
sudo journalctl -u adguard-sentinel.service -n 50 --no-pager
```

Expect `Result=success`, `ExecMainStatus=0`, and a complete observation of each
target with no unexpected findings. A successful oneshot normally becomes
`inactive (dead)`; that alone is not failure. Once the first run is accepted:

```sh
sudo systemctl enable --now adguard-sentinel.timer
systemctl list-timers adguard-sentinel.timer --all
```

## Inspect and accept

Use your installed binary path; the source-install example is:

```sh
sudo /usr/local/bin/adguard-sentinel report --state /var/lib/adguard-sentinel/state.sqlite --limit 5
```

For a new deployment, require twelve successful timer runs, one service restart,
growing history, and any configured external job-health events. A five-minute
timer includes scheduling slack; allow for it in the job-health grace period.
Build and fixture tests cannot establish these host properties.

For an isolated alert/recovery exercise, use a separate dry-run configuration
and database with one target. Copy the full condition profile from the example,
set `api_unavailable_sustain_runs = 1` and `recovery_runs = 1`, and point the
target at an unused loopback port. Run `check --dry-run`: expect exit `3`, an
API-unavailable finding, and a suppressed alert transition. Restore the same
target ID to its working read-only API URL and run again: expect exit `0` and a
suppressed resolution. This does not establish real Pushover delivery; test that
only on a separately authorized route.

When replacing an existing monitor, disable its notifications before enabling
Sentinel's. Keep its definition and state during a rollback window. Rollback
stops Sentinel's timer, restores the previous monitor and job-health target, and
verifies one successful run. For binary upgrades, read the changelog before
assuming an older binary can read newly written state.

## Remove

The following removes a source or Cargo installation, its configuration, and
all history and latches:

```sh
sudo systemctl disable --now adguard-sentinel.timer
sudo systemctl stop adguard-sentinel.service
sudo rm /etc/systemd/system/adguard-sentinel.service /etc/systemd/system/adguard-sentinel.timer
sudo systemctl daemon-reload
sudo rm -rf /var/lib/adguard-sentinel /etc/adguard-sentinel
sudo rm /usr/local/bin/adguard-sentinel
```

With `DynamicUser`, the state may live under `/var/lib/private/adguard-sentinel`;
remove that directory too when discarding the history. For the Nix installation,
remove the `/opt/adguard-sentinel` output link instead of the binary; Nix garbage
collection can later reclaim the package. A reinstall without state starts new
latches and a new behavioral baseline.
