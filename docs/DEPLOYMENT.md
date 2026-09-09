# Deployment and acceptance

Install Sentinel on one monitor host. Resolver hosts need only expose their
AdGuard Home API. [SUPPORT](SUPPORT.md) records supported platforms and evidence.
Commands below use a POSIX shell on Linux; `sudo` marks host-level installation.

## Install

### Nix

Build from the checkout containing the units and instructions you are using:

```sh
nix build
./result/bin/adguard-sentinel --help
```

For a persistent systemd installation, keep the output rooted:

```sh
sudo nix build . --out-link /opt/adguard-sentinel
/opt/adguard-sentinel/bin/adguard-sentinel --help
```

Use `/opt/adguard-sentinel/bin/adguard-sentinel` for both binary paths through
the override below. The package includes the canonical units under
`share/adguard-sentinel/systemd`. An operator-owned NixOS configuration can
reference the package directly; this repository exports no service module.

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

Alternatively, install from that checkout into your Cargo bin directory:

```sh
cargo install --locked --path apps/sentinel-cli
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

Install the [canonical service](../deploy/systemd/adguard-sentinel.service) and
[timer](../deploy/systemd/adguard-sentinel.timer) from the same checkout as the
binary:

```sh
sudo install -m644 deploy/systemd/adguard-sentinel.service /etc/systemd/system/
sudo install -m644 deploy/systemd/adguard-sentinel.timer /etc/systemd/system/
```

For a rooted Nix package without a checkout, use
`/opt/adguard-sentinel/share/adguard-sentinel/systemd/` as the source directory.
The service uses `/usr/local/bin/adguard-sentinel` by default. For Nix, create
`/etc/systemd/system/adguard-sentinel.service.d/binary.conf`:

```ini
[Service]
ExecStartPre=
ExecStartPre=/opt/adguard-sentinel/bin/adguard-sentinel validate-config --config %d/config
ExecStart=
ExecStart=/opt/adguard-sentinel/bin/adguard-sentinel check --config %d/config
```

Create the drop-in directory with mode `0755` and files with mode `0644`. Add
any Basic or Pushover `LoadCredential` lines described above in a separate
`credentials.conf` drop-in with a `[Service]` section. The default state path
matches `StateDirectory`, which supplies private writable storage. The service
uses a dynamic user, mode `0700` state storage, umask `0077`, a read-only system,
restricted system calls and capabilities, and a 120-second start deadline.
Leave `--fail-on` at `never`; ordinary findings should not fail the unit. Set
`TimeoutStartSec` in a drop-in if your target count and request/notification
timeouts require more than 120 seconds.

This monotonic timer runs after boot and then relative to the previous
activation. It does not replay checks missed while the host was off. Systemd
does not start a second instance of an already active oneshot. A manual `check`
against the same database is also refused while a writer holds it, with exit `5` and
`state database is already in use`. Read-only `report` remains available.

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

## Automated synthetic acceptance

The [acceptance harness](../tools/check-linux-deployment.py) creates a loopback
mock with synthetic responses and temporary state. It accepts a binary path;
there is no option for a real resolver or notification destination:

```sh
python3 tools/check-linux-deployment.py --binary target/debug/adguard-sentinel
```

This portable mode checks Basic authentication, all six allowlisted GETs,
private state and repeated runs, malformed data, HTTP failure, request timeout,
suppressed alert/recovery, and concurrent writer refusal while reports remain
readable. It does not test systemd.

On a **disposable Linux host with systemd**, run the complete service suite:

```sh
sudo python3 tools/check-linux-deployment.py --binary target/debug/adguard-sentinel --systemd --disposable
```

It copies the canonical units unchanged, then uses drop-ins for unique temporary
paths, the test binary, synthetic credentials, and accelerated timing. It checks
credential access under `DynamicUser`, read-only system mounts, effective
capabilities, syscall/address-family restrictions, state permissions, a missing
credential, validation of both Pushover credential files without delivery,
process termination at the systemd deadline, restart after termination, and two
recurring timer activations. It also migrates v1 state under the service user,
checks private backup/lock ownership, and uses that state through the canonical
service. Runtime units and isolated state are removed on exit. Do not run this
root-level suite on a production monitor.

[CI](../.github/workflows/ci.yml) runs this suite against both native Linux Nix
packages and the source-built Ubuntu binary. A configured job is not a passing
result: inspect CI for the exact commit. These synthetic checks do not establish
real credentials, resolver reachability, five-minute scheduling, job-health
integration, or Pushover delivery.

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

## Upgrade state

Read the changelog for the installed and target versions. A binary that requires
a newer state schema refuses an older database until an explicit migration;
`check` never performs that upgrade. Stop scheduling and wait for the active
writer before copying or migrating state:

```sh
sudo systemctl stop adguard-sentinel.timer adguard-sentinel.service
sudo cp -a /var/lib/adguard-sentinel/state.sqlite /var/lib/adguard-sentinel/state.sqlite.before-upgrade
sudo systemd-run --unit=adguard-sentinel-migration --wait --pipe --collect \
  --property=DynamicUser=yes --property=User=adguard-sentinel \
  --property=StateDirectory=adguard-sentinel --property=StateDirectoryMode=0700 \
  --property=UMask=0077 --property=PrivateNetwork=yes \
  /usr/local/bin/adguard-sentinel migrate-state --state /var/lib/adguard-sentinel/state.sqlite
sudo systemctl start adguard-sentinel.service
sudo systemctl show adguard-sentinel.service -p Result -p ExecMainStatus
```

Use the new binary's path for migration, including the Nix path when applicable.
The transient unit uses the canonical service's user and state directory, so the
new lock and backup have the correct ownership. If the service overrides `User`
or `StateDirectory`, use those values. Running migration directly as root can
leave a root-owned lock that the dynamic service user cannot open.
Keep the backup private. Accept the first run before restarting the timer. A
failed migration must leave the original database usable; retain the backup
until the rollback window ends. Binary rollback may also require restoring its
matching state backup while the timer and service are stopped.

## Remove

The following removes a source or Cargo installation, its configuration, and
all history and latches:

```sh
sudo systemctl disable --now adguard-sentinel.timer
sudo systemctl stop adguard-sentinel.service
sudo rm /etc/systemd/system/adguard-sentinel.service /etc/systemd/system/adguard-sentinel.timer
sudo rm -rf /etc/systemd/system/adguard-sentinel.service.d
sudo systemctl daemon-reload
sudo rm -rf /var/lib/adguard-sentinel /etc/adguard-sentinel
sudo rm /usr/local/bin/adguard-sentinel
```

With `DynamicUser`, the state may live under `/var/lib/private/adguard-sentinel`;
remove that directory too when discarding the history. For the Nix installation,
remove the `/opt/adguard-sentinel` output link instead of the binary; Nix garbage
collection can later reclaim the package. A reinstall without state starts new
latches and a new behavioral baseline.
