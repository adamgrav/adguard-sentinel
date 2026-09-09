#!/usr/bin/env python3
"""Synthetic CLI and disposable-systemd acceptance; no live service inputs."""

import argparse
import base64
import contextlib
import http.server
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid


ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "synthetic-resolver-password"
AUTHORIZATION = "Basic " + base64.b64encode(
    f"synthetic-user:{PASSWORD}".encode()
).decode()
BODIES = {
    "/control/status": {
        "protection_enabled": True, "running": True, "version": "v0.107.78",
    },
    "/control/stats": {
        "num_dns_queries": 5000, "num_blocked_filtering": 1250,
        "avg_processing_time": 0.018,
        "top_upstreams_avg_time": [{"https://dns.example.invalid/dns-query": 0.024}],
        "top_clients": [{"192.0.2.10": 5000}],
    },
    "/control/dns_info": {
        "upstream_dns": ["https://dns.example.invalid/dns-query"],
        "upstream_mode": "load_balance",
    },
    "/control/filtering/status": {"enabled": True, "filters": []},
    "/control/rewrite/list": [],
    "/control/rewrite/settings": {"enabled": True},
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def command(*args, expected=0, timeout=30):
    result = subprocess.run(
        [str(arg) for arg in args], capture_output=True, text=True, timeout=timeout,
    )
    if expected is not None:
        require(result.returncode == expected,
                f"{args[0]} exited {result.returncode}, expected {expected}:\n"
                f"{result.stdout}{result.stderr}")
    return result


def wait_until(predicate, message, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(message)


def private_file(path, content):
    path.write_text(content)
    path.chmod(0o600)


class Resolver(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.mode = "healthy"
        self.requests = []
        self.unexpected = []
        self.holding = threading.Event()
        self.release = threading.Event()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        self.server.requests.append(parsed.path)
        if parsed.path not in BODIES or (
            parsed.query and not (
                parsed.path == "/control/stats" and parsed.query == "recent=3600000"
            )
        ):
            self.server.unexpected.append(self.path)
            self.reply(404, {})
            return
        if self.headers.get("Authorization") != AUTHORIZATION:
            self.reply(401, {})
            return
        mode = self.server.mode
        if mode == "hold" and parsed.path == "/control/status":
            self.server.holding.set()
            self.server.release.wait(30)
        if mode == "timeout" and parsed.path == "/control/status":
            time.sleep(1)
        if mode == "unavailable":
            self.reply(503, {})
        elif mode == "authentication-rejected":
            self.reply(401, {})
        elif mode == "malformed" and parsed.path == "/control/status":
            self.reply(200, {"version": "v0.107.78"})
        else:
            self.reply(200, BODIES[parsed.path])

    def do_POST(self):
        self.server.unexpected.append("POST " + self.path)
        self.reply(405, {})

    def reply(self, status, body):
        encoded = json.dumps(body).encode()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)


def config_text(state, password, port, request_timeout=300, pushover=False):
    notifications = '[notifications]\nprovider = "disabled"'
    if pushover:
        notifications = f'''[notifications]
provider = "pushover"
[notifications.pushover]
application_token_file = "{password.parent}/pushover-application-token"
user_key_file = "{password.parent}/pushover-user-key"'''
    return f'''schema_version = 1
[state]
path = "{state}"
retention_days = 21
[observation]
request_timeout_ms = {request_timeout}
notification_timeout_ms = 300
max_response_bytes = 4194304
stats_lookback_ms = 3600000
target_concurrency = 1
minimum_complete_targets = 1
adguard_version_requirement = ">=0.107.78,<0.108.0"
[condition_profiles.current]
authentication_rejected_sustain_runs = 1
api_unavailable_sustain_runs = 1
invalid_response_sustain_runs = 1
unsupported_version_sustain_runs = 1
protection_disabled_sustain_runs = 1
processing_latency_sustain_runs = 4
upstream_latency_sustain_runs = 4
policy_drift_sustain_runs = 4
behavioral_anomaly_sustain_runs = 4
recovery_runs = 1
authentication_retry_seconds = 1
processing_latency_ms = 500
upstream_latency_ms = 750
{notifications}
[[targets]]
id = "synthetic-resolver"
name = "Synthetic resolver"
base_url = "http://127.0.0.1:{port}"
auth = "basic"
username = "synthetic-user"
password_file = "{password}"
'''


class LocalRun:
    def __init__(self, binary, directory, resolver):
        self.binary = binary
        self.directory = directory
        self.resolver = resolver
        self.state = directory / "state.sqlite"
        self.config = directory / "config.toml"
        self.password = directory / "resolver-password"
        private_file(self.password, PASSWORD + "\n")
        self.configure()

    def configure(self, request_timeout=300, pushover=False):
        private_file(self.config, config_text(
            self.state, self.password, self.resolver.server_port, request_timeout, pushover,
        ))

    def start(self, expected=0, restart=False):
        command(self.binary, "check", "--config", self.config, expected=expected)

    def history(self):
        result = command(self.binary, "report", "--state", self.state,
                         "--format", "jsonl", "--limit", "100")
        return [json.loads(line) for line in result.stdout.splitlines()]

    def hold(self):
        return subprocess.Popen(
            [str(self.binary), "check", "--config", str(self.config)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )

    def assert_private(self):
        require(stat.S_IMODE(self.state.stat().st_mode) == 0o600,
                "SQLite state must have mode 0600")


class SystemdRun(LocalRun):
    def __init__(self, binary, directory, resolver, name):
        self.name = name
        self.transient_units = []
        self.unit = name + ".service"
        self.timer = name + ".timer"
        self.unit_root = Path("/run/systemd/system")
        self.dropin = self.unit_root / (self.unit + ".d")
        self.timer_dropin = self.unit_root / (self.timer + ".d")
        self.state = Path("/var/lib") / name / "state.sqlite"
        self.directory = directory
        self.resolver = resolver
        self.binary = directory / "adguard-sentinel"
        shutil.copy2(binary, self.binary)
        self.binary.chmod(0o755)
        directory.chmod(0o755)
        self.secret_dir = directory / "secrets"
        self.secret_dir.mkdir(mode=0o700)
        self.config = self.secret_dir / "config.toml"
        self.password_source = self.secret_dir / "resolver-password"
        self.password = Path("/run/credentials") / self.unit / "resolver-password"
        private_file(self.password_source, PASSWORD + "\n")
        for credential in ("pushover-application-token", "pushover-user-key"):
            private_file(self.secret_dir / credential, "synthetic-unused-token\n")
        self.configure()
        self.dropin.mkdir()
        self.timer_dropin.mkdir()
        for suffix in ("service", "timer"):
            source = ROOT / "deploy/systemd" / f"adguard-sentinel.{suffix}"
            destination = self.unit_root / f"{name}.{suffix}"
            shutil.copyfile(source, destination)
            destination.chmod(0o644)
            require(source.read_bytes() == destination.read_bytes(), "unit copy changed")
        # Preserve the shipped CLI arguments; only move the executable into the
        # disposable runtime directory. A change to the shipped command is tested.
        service = (self.unit_root / self.unit).read_text().splitlines()
        starts = [line.replace("/usr/local/bin/adguard-sentinel", str(self.binary))
                  for line in service if line.startswith("ExecStart=")]
        prestarts = [line.replace("/usr/local/bin/adguard-sentinel", str(self.binary))
                     for line in service if line.startswith("ExecStartPre=")]
        require(len(starts) == 1 and prestarts, "shipped service has no check/validation command")
        state_modes = [line for line in service if line.startswith("StateDirectoryMode=")]
        require(len(state_modes) == 1, "shipped service has no private state directory mode")
        probe = directory / "probe.py"
        probe.write_text(HARDENING_PROBE)
        probe.chmod(0o644)
        self.overrides = f'''[Service]
LoadCredential=
LoadCredential=config:{self.config}
LoadCredential=resolver-password:{self.password_source}
LoadCredential=pushover-application-token:{self.secret_dir}/pushover-application-token
LoadCredential=pushover-user-key:{self.secret_dir}/pushover-user-key
StateDirectory=
StateDirectory={name}
{state_modes[0]}
ExecStartPre=
{chr(10).join(prestarts)}
ExecStartPre=/usr/bin/python3 {probe} {self.state.parent} {self.config}
ExecStart=
{starts[0]}
'''
        self.set_overrides()
        (self.timer_dropin / "acceptance.conf").write_text('''[Timer]
OnBootSec=
OnUnitActiveSec=
OnActiveSec=1s
OnUnitActiveSec=2s
AccuracySec=100ms
''')
        command("systemd-analyze", "verify", self.unit_root / self.unit,
                self.unit_root / self.timer)
        command("systemctl", "daemon-reload")

    def set_overrides(self, extra=""):
        (self.dropin / "acceptance.conf").write_text(self.overrides + extra)
        command("systemctl", "daemon-reload")

    def properties(self):
        result = command("systemctl", "show", self.unit,
                         "-p", "Result", "-p", "ExecMainStatus", "-p", "ActiveState")
        return dict(line.split("=", 1) for line in result.stdout.splitlines())

    def start(self, expected=0, restart=False):
        command("systemctl", "reset-failed", self.unit, expected=None)
        result = command("systemctl", "restart" if restart else "start", self.unit,
                         expected=None)
        properties = self.properties()
        require(properties["ExecMainStatus"] == str(expected),
                f"unexpected unit status: {properties}\n{result.stderr}\n{self.journal()}")
        require(properties["Result"] == ("success" if expected == 0 else "exit-code"),
                f"unexpected unit result: {properties}\n{self.journal()}")
        require((result.returncode == 0) == (expected == 0), "systemctl disagrees with unit")

    def hold(self):
        command("systemctl", "reset-failed", self.unit, expected=None)
        return subprocess.Popen(
            ["systemctl", "start", self.unit], stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True,
        )

    def assert_private(self):
        super().assert_private()
        require(stat.S_IMODE(self.state.parent.stat().st_mode) == 0o700,
                "StateDirectory must have mode 0700")
        require(not (self.state.parent / "probe-file").exists(), "probe did not finish")

    def journal(self):
        return command("journalctl", "-u", self.unit, "--no-pager", "-n", "80").stdout

    def extra_checks(self):
        before = len(self.history())
        requests = len(self.resolver.requests)
        self.password_source.rename(self.secret_dir / "saved-password")
        try:
            failed = command("systemctl", "start", self.unit, expected=None)
            require(failed.returncode != 0, "missing credential must prevent start")
            require(len(self.history()) == before, "missing credential wrote history")
            require(len(self.resolver.requests) == requests, "missing credential made requests")
        finally:
            (self.secret_dir / "saved-password").rename(self.password_source)

        # Real Pushover is never contacted: this invocation only validates files.
        self.configure(pushover=True)
        self.set_overrides(f"ExecStart=\nExecStart={self.binary} validate-config --config %d/config\n")
        self.start()
        require(len(self.resolver.requests) == requests, "validation contacted resolver")
        require(len(self.history()) == before, "validation wrote state")
        self.configure(request_timeout=10000)
        self.set_overrides("TimeoutStartSec=2s\n")
        self.resolver.mode = "hold"
        self.resolver.holding.clear()
        self.resolver.release.clear()
        timed = command("systemctl", "start", self.unit, expected=None, timeout=15)
        require(timed.returncode != 0 and self.properties()["Result"] == "timeout",
                "systemd deadline did not terminate the held observation")
        require(len(self.history()) == before, "killed observation committed a partial run")
        self.resolver.release.set()
        self.resolver.mode = "healthy"
        self.configure()
        self.set_overrides()
        self.start(restart=True)
        require(len(self.history()) == before + 1, "restart did not release the killed writer")
        print("PASS: missing credentials, validation-only Pushover credentials, systemd timeout/restart")

        before = len(self.history())
        command("systemctl", "start", self.timer)
        try:
            wait_until(lambda: len(self.history()) >= before + 2,
                       "timer did not create two recurring observations", timeout=20)
        finally:
            command("systemctl", "stop", self.timer)
        wait_until(lambda: self.properties()["ActiveState"] != "activating",
                   "last timer observation did not finish")
        require(all(row["targets"][0]["complete"] for row in self.history()[:2]),
                "timer observations were incomplete")
        print("PASS: shipped timer schedules repeated successful service activations (accelerated)")
        self.migrate_as_service_user()

    def migrate_as_service_user(self):
        original_history = self.history()
        legacy_state = self.state.parent / "legacy.sqlite"
        seed = self.directory / "seed-legacy.py"
        seed.write_text(LEGACY_SEED)
        seed.chmod(0o644)
        # The dynamic user cannot necessarily traverse the runner's checkout.
        legacy_schema = self.directory / "state-v1.sql"
        shutil.copyfile(ROOT / "schemas/state-v1.sql", legacy_schema)
        legacy_schema.chmod(0o644)

        def transient(suffix, *args):
            unit = f"{self.name}-{suffix}.service"
            self.transient_units.append(unit)
            return command(
                "systemd-run", f"--unit={unit}", "--wait", "--pipe", "--collect",
                "--property=DynamicUser=yes", f"--property=User={self.name}",
                f"--property=StateDirectory={self.name}",
                "--property=StateDirectoryMode=0700", "--property=UMask=0077",
                "--property=PrivateNetwork=yes", "--", *args,
            )

        transient("legacy-seed", "/usr/bin/python3", seed,
                  legacy_schema, legacy_state)
        require(legacy_state.stat().st_uid != 0, "legacy state was created as root")
        transient("migration", self.binary, "migrate-state", "--state", legacy_state)
        with sqlite3.connect(f"file:{legacy_state}?mode=ro", uri=True) as database:
            require(database.execute("PRAGMA user_version").fetchone()[0] == 2,
                    "service-user migration did not produce v2 state")
        backups = list(legacy_state.parent.glob("legacy.sqlite.v1-*.bak"))
        require(len(backups) == 1, "migration did not create one v1 backup")
        with sqlite3.connect(f"file:{backups[0]}?mode=ro", uri=True) as database:
            require(database.execute("PRAGMA user_version").fetchone()[0] == 1,
                    "migration backup is not the original v1 state")
        lock = legacy_state.resolve().with_name("legacy.sqlite.lock")
        for private in (legacy_state, backups[0], lock):
            require(stat.S_IMODE(private.stat().st_mode) == 0o600,
                    f"migration artifact is not private: {private.name}")
            require(private.stat().st_uid != 0,
                    f"migration artifact is root-owned: {private.name}")

        original_config = self.config.read_text()
        try:
            private_file(self.config, config_text(
                legacy_state, self.password, self.resolver.server_port,
            ))
            self.start()
            migrated = json.loads(command(
                self.binary, "report", "--state", legacy_state,
                "--format", "json", "--limit", "1",
            ).stdout)
            require(migrated["targets"][0]["complete"],
                    "canonical DynamicUser service could not use migrated state and lock")
        finally:
            private_file(self.config, original_config)
        require(self.history() == original_history,
                "migration acceptance changed the ordinary state history")
        print("PASS: service-user v1 migration, private backup/lock, canonical service reuse")

    def cleanup(self):
        for unit in self.transient_units:
            command("systemctl", "stop", unit, expected=None)
            command("systemctl", "reset-failed", unit, expected=None)
        command("systemctl", "stop", self.timer, self.unit, expected=None)
        command("systemctl", "reset-failed", self.unit, expected=None)
        for suffix in ("service", "timer"):
            (self.unit_root / f"{self.name}.{suffix}").unlink(missing_ok=True)
        for directory in (self.dropin, self.timer_dropin):
            shutil.rmtree(directory, ignore_errors=True)
        command("systemctl", "daemon-reload")
        state_directory = self.state.parent
        if state_directory.is_symlink():
            state_directory.unlink()
        else:
            shutil.rmtree(state_directory, ignore_errors=True)
        shutil.rmtree(Path("/var/lib/private") / self.name, ignore_errors=True)


HARDENING_PROBE = '''import os, pathlib, socket, stat, sys
state = pathlib.Path(sys.argv[1])
source = pathlib.Path(sys.argv[2])
assert os.getuid() != 0, "DynamicUser did not drop root"
assert not os.access(source, os.R_OK), "original private config is readable"
credentials = pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])
assert (credentials / "resolver-password").read_text().strip() == "synthetic-resolver-password"
for name in ("pushover-application-token", "pushover-user-key"):
    assert (credentials / name).read_text().strip() == "synthetic-unused-token"
assert os.statvfs("/etc").f_flag & os.ST_RDONLY, "ProtectSystem is not read-only"
status = pathlib.Path("/proc/self/status").read_text()
assert "NoNewPrivs:\\t1" in status, "NoNewPrivileges is not active"
assert "CapEff:\\t0000000000000000" in status, "effective capabilities remain"
assert "Seccomp:\\t2" in status, "syscall filtering is not active"
try:
    socket.socket(socket.AF_UNIX)
except OSError:
    pass
else:
    raise AssertionError("AF_UNIX was not restricted")
assert stat.S_IMODE(state.stat().st_mode) == 0o700
probe = state / "probe-file"
probe.write_text("synthetic")
assert stat.S_IMODE(probe.stat().st_mode) == 0o600, "UMask is not private"
probe.unlink()
'''


LEGACY_SEED = '''import datetime, hashlib, os, pathlib, sqlite3, sys
assert os.getuid() != 0, "legacy fixture must be created by the dynamic service user"
schema = pathlib.Path(sys.argv[1]).read_bytes()
path = pathlib.Path(sys.argv[2])
assert not path.exists(), "legacy fixture path already exists"
timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
with sqlite3.connect(path) as database:
    database.executescript(schema.decode())
    database.execute(
        "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (1, 'initial', ?, ?)",
        ("sha256:" + hashlib.sha256(schema).hexdigest(), timestamp),
    )
    database.execute(
        "INSERT INTO runs(id, started_at, completed_at, mode, config_sha256, status, "
        "expected_targets, complete_targets, minimum_targets, exit_code) "
        "VALUES ('synthetic-legacy', ?, ?, 'live', 'sha256:synthetic', 'complete', 0, 0, 0, 0)",
        (timestamp, timestamp),
    )
'''


def scenarios(run):
    run.start()
    require(run.history()[0]["targets"][0]["complete"], "healthy target was incomplete")
    require(set(run.resolver.requests) == set(BODIES), "healthy run did not use all six GETs")
    run.assert_private()
    run.start(restart=True)
    require(len(run.history()) == 2, "state did not survive restart")
    print("PASS: Basic credentials, six read-only endpoints, private state, restart/history")

    for mode, expected_status in (("malformed", "invalid_response"),
                                  ("unavailable", "unavailable"), ("timeout", "unavailable")):
        run.resolver.mode = mode
        run.start(expected=3)
        report = run.history()[0]
        require(report["targets"][0]["status"] == expected_status,
                f"{mode} was not classified as {expected_status}")
        require(not report["targets"][0]["complete"], f"{mode} became healthy")
        require(any(item["status"] == "suppressed" for item in report["notifications"]),
                f"{mode} alert was not suppressed")
        run.resolver.mode = "healthy"
        run.start()
        recovered = run.history()[0]
        require(recovered["targets"][0]["complete"], f"{mode} did not recover")
        require(any(item["kind"] == "resolution" for item in recovered["transitions"]),
                f"{mode} did not produce a recovery transition")
    print("PASS: malformed response, HTTP failure, request timeout, suppressed alert/recovery")

    run.resolver.mode = "authentication-rejected"
    run.start(expected=3)
    require(run.history()[0]["targets"][0]["status"] == "authentication_rejected",
            "HTTP 401 was not classified as authentication rejection")
    run.resolver.mode = "healthy"
    # The synthetic profile uses a one-second authentication retry interval.
    time.sleep(1.1)
    run.start()
    require(run.history()[0]["targets"][0]["complete"], "authentication did not recover")
    print("PASS: authentication rejection and recovery after cooldown")

    # Hold an actual HTTP observation while another writer and a reader start.
    run.configure(request_timeout=10000)
    run.resolver.mode = "hold"
    run.resolver.holding.clear()
    run.resolver.release.clear()
    before = len(run.history())
    first = run.hold()
    try:
        require(run.resolver.holding.wait(10), "first writer did not reach the resolver")
        requests = len(run.resolver.requests)
        if isinstance(run, SystemdRun):
            command("systemctl", "start", "--no-block", run.unit)
        # A separate manual config uses the same DB and a locally readable secret.
        password = run.directory / "overlap-password"
        private_file(password, PASSWORD + "\n")
        config = run.directory / "overlap.toml"
        private_file(config, config_text(run.state, password, run.resolver.server_port))
        rejected = command(run.binary, "check", "--config", config, expected=5)
        require("state database is already in use" in rejected.stderr,
                "overlap did not report the writer lock")
        require(len(run.resolver.requests) == requests, "overlapping writer made an HTTP request")
        require(len(run.history()) == before, "read-only report changed while writer was held")
    finally:
        run.resolver.release.set()
        _stdout, stderr = first.communicate(timeout=20)
        require(first.returncode == 0, f"held writer failed: {stderr}")
        run.resolver.mode = "healthy"
        run.configure()
    require(len(run.history()) == before + 1, "overlap created an extra run")
    print("PASS: whole-run overlap refusal before HTTP, concurrent report, lock release")
    require(not run.resolver.unexpected, f"unexpected requests: {run.resolver.unexpected}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--systemd", action="store_true",
                        help="test the shipped units; requires root in a disposable Linux environment")
    parser.add_argument("--disposable", action="store_true",
                        help="acknowledge temporary runtime units and isolated state on this test host")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    require(os.access(binary, os.X_OK), "binary is not executable")
    if args.systemd:
        require(sys.platform == "linux" and os.geteuid() == 0 and args.disposable,
                "--systemd requires Linux, root, and --disposable")
        require(Path("/run/systemd/system").is_dir(), "systemd is not running")
        command("systemctl", "show", "--property", "Version")
    os.umask(0o077)
    resolver = Resolver()
    thread = threading.Thread(target=resolver.serve_forever, daemon=True)
    thread.start()
    name = "sentinel-test-" + uuid.uuid4().hex[:10]
    run = None
    try:
        with tempfile.TemporaryDirectory(prefix=name + "-", dir="/run" if args.systemd else None) as tmp:
            try:
                if args.systemd:
                    # Assign before setup so a failed assertion still cleans runtime units/state.
                    run = SystemdRun.__new__(SystemdRun)
                    run.__init__(binary, Path(tmp), resolver, name)
                else:
                    run = LocalRun(binary, Path(tmp), resolver)
                scenarios(run)
                if args.systemd:
                    run.extra_checks()
                    print("PASS: Linux systemd credentials and hardening probe")
            except Exception:
                if args.systemd and run is not None:
                    print(run.journal(), file=sys.stderr)
                raise
            finally:
                if args.systemd and run is not None:
                    run.cleanup()
    finally:
        resolver.release.set()
        resolver.shutdown()
        resolver.server_close()
        thread.join()
    print("PASS: synthetic acceptance complete; no real resolver or notification service used")


if __name__ == "__main__":
    main()
