#!/usr/bin/env python3

"""Exercise the frozen Python v1 oracle with synthetic I/O."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
from pathlib import Path
from typing import Any


REPOSITORY = Path(__file__).resolve().parent.parent
ORACLE = REPOSITORY / "testdata/legacy/python-v1/adguard-anomaly-monitor.py"
EXPECTED_GIT_BLOB = "47310b304371c81c6ba50248a097b8f7f4701b76"


def git_blob_sha1(path: Path) -> str:
    content = path.read_bytes()
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def load_oracle() -> Any:
    specification = importlib.util.spec_from_file_location("python_v1_oracle", ORACLE)
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load frozen Python oracle")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def run_healthy_sequence(module: Any) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        credentials = root / "credentials"
        state = root / "state"
        credentials.mkdir()
        state.mkdir()
        for name in (
            "adguard-password",
            "pushover-application-token",
            "pushover-user-key",
        ):
            (credentials / name).write_text("synthetic\n", encoding="utf-8")
        config = {
            "username": "admin",
            "lookback_milliseconds": 3_600_000,
            "failure_sustain_runs": 4,
            "learning_days": 7,
            "processing_latency_seconds": 0.5,
            "request_timeout_seconds": 5.0,
            "sample_retention_days": 21,
            "upstream_latency_seconds": 0.75,
            "targets": [
                {"name": "Resolver A", "url": "https://resolver-a.invalid"},
                {"name": "Resolver B", "url": "https://resolver-b.invalid"},
            ],
        }
        config_path = root / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        os.environ["ADGUARD_MONITOR_CONFIG"] = str(config_path)
        os.environ["CREDENTIALS_DIRECTORY"] = str(credentials)
        os.environ["STATE_DIRECTORY"] = str(state)

        def api_get(base_url: str, endpoint: str, *_args: Any) -> dict[str, Any]:
            if endpoint == "status":
                return {"protection_enabled": True}
            if endpoint.startswith("stats?"):
                if "resolver-a" in base_url:
                    return {
                        "num_dns_queries": 100,
                        "num_blocked_filtering": 10,
                        "avg_processing_time": 0.01,
                        "top_upstreams_avg_time": [{"tls://a.invalid": 0.02}],
                        "top_clients": [{"192.0.2.10": 20}],
                    }
                return {
                    "num_dns_queries": 200,
                    "num_blocked_filtering": 20,
                    "avg_processing_time": 0.02,
                    "top_upstreams_avg_time": [{"tls://b.invalid": 0.03}],
                    "top_clients": [{"192.0.2.20": 40}],
                }
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        notifications: list[tuple[Any, ...]] = []
        module.api_get = api_get
        module.send_pushover = lambda *arguments: notifications.append(arguments)
        module.time.time = lambda: 1_700_000_000
        if module.main() != 0:
            raise AssertionError("healthy oracle run did not return zero")
        persisted = json.loads((state / "state.json").read_text(encoding="utf-8"))
        latest = persisted["latest"]
        assert latest["combined_queries"] == 300
        assert abs(latest["combined_blocked_ratio"] - 0.1) < 1e-12
        assert latest["baseline_ready"] is False
        assert len(persisted["samples"]) == 1
        assert persisted["samples"][0]["local_hour"] in range(24)
        assert persisted["conditions"]["target:Resolver A:api"]["consecutive"] == 0
        assert notifications == []


def assert_intentional_invalid_data_divergence(module: Any) -> None:
    # Sentinel rejects these values; the oracle historically defaulted them.
    assert module.finite_number("not-a-number") == 0.0
    assert module.finite_number(float("inf")) == 0.0
    assert module.mapping_max([{"upstream": "not-a-number"}]) == 0.0


def main() -> int:
    actual = git_blob_sha1(ORACLE)
    if actual != EXPECTED_GIT_BLOB:
        raise RuntimeError(f"frozen Python oracle hash drifted: {actual}")
    module = load_oracle()
    run_healthy_sequence(module)
    assert_intentional_invalid_data_divergence(module)
    print("fixture parity oracle: healthy sequence and intentional divergences passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
