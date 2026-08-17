#!/usr/bin/env python3

"""Periodically inspect two AdGuard Home instances and send quiet alerts."""

from __future__ import annotations

import base64
import json
import math
import os
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


STATE_VERSION = 1
AUTH_RETRY_SECONDS = 15 * 60


class AuthenticationError(RuntimeError):
    pass


def read_secret(path: Path) -> str:
    return path.read_text(encoding="utf-8").rstrip("\r\n")


def load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError:
        return default

    if not isinstance(value, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return value


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def api_get(
    base_url: str,
    endpoint: str,
    username: str,
    password: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/control/{endpoint.lstrip('/')}"
    credentials = base64.b64encode(
        f"{username}:{password}".encode("utf-8")
    ).decode("ascii")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Basic {credentials}",
            "User-Agent": "homelab-adguard-anomaly-monitor/1",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            value = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            raise AuthenticationError(
                f"AdGuard API authentication failed with HTTP {error.code}"
            ) from error
        raise RuntimeError(f"AdGuard API returned HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise RuntimeError(f"AdGuard API request failed: {error}") from error

    if not isinstance(value, dict):
        raise RuntimeError("AdGuard API returned a non-object response")
    return value


def finite_number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def mapping_max(value: Any) -> float:
    values: list[float] = []
    mappings = value if isinstance(value, list) else [value]
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        values.extend(finite_number(item) for item in mapping.values())
    return max(values, default=0.0)


def inspect_target(
    target: dict[str, Any],
    username: str,
    password: str,
    timeout_seconds: float,
    lookback_milliseconds: int,
) -> dict[str, Any]:
    status = api_get(
        target["url"],
        "status",
        username,
        password,
        timeout_seconds,
    )
    stats = api_get(
        target["url"],
        f"stats?{urllib.parse.urlencode({'recent': lookback_milliseconds})}",
        username,
        password,
        timeout_seconds,
    )

    queries = max(0, int(finite_number(stats.get("num_dns_queries"))))
    blocked = max(0, int(finite_number(stats.get("num_blocked_filtering"))))
    return {
        "protection_enabled": status.get("protection_enabled") is True,
        "queries": queries,
        "blocked": blocked,
        "blocked_ratio": blocked / queries if queries else 0.0,
        "average_processing_seconds": finite_number(
            stats.get("avg_processing_time")
        ),
        "maximum_upstream_seconds": mapping_max(
            stats.get("top_upstreams_avg_time", [])
        ),
        "top_client_share": mapping_max(stats.get("top_clients", [])) / queries
        if queries
        else 0.0,
    }


def robust_bounds(values: list[float]) -> tuple[float, float]:
    median = statistics.median(values)
    deviations = [abs(value - median) for value in values]
    scaled_deviation = 1.4826 * statistics.median(deviations)
    return median, max(scaled_deviation, 1e-9)


def add_condition(
    evaluated: dict[str, dict[str, Any]],
    key: str,
    active: bool,
    summary: str,
    detail: str,
    threshold: int,
) -> None:
    evaluated[key] = {
        "active": active,
        "summary": summary,
        "detail": detail,
        "threshold": threshold,
    }


def update_condition_state(
    state: dict[str, Any],
    evaluated: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    condition_state = state.setdefault("conditions", {})
    new_alerts: list[dict[str, Any]] = []
    resolutions: list[dict[str, Any]] = []

    for key, condition in evaluated.items():
        previous = condition_state.setdefault(
            key,
            {
                "consecutive": 0,
                "notified": False,
            },
        )
        previous["summary"] = condition["summary"]
        previous["detail"] = condition["detail"]

        if condition["active"]:
            previous["consecutive"] = int(previous.get("consecutive", 0)) + 1
            if (
                previous["consecutive"] >= condition["threshold"]
                and not previous.get("notified", False)
            ):
                new_alerts.append({"key": key, **condition})
        else:
            if previous.get("notified", False):
                resolutions.append({"key": key, **condition})
            previous["consecutive"] = 0

    return new_alerts, resolutions


def send_pushover(
    application_token: str,
    user_key: str,
    title: str,
    lines: list[str],
    priority: int,
) -> None:
    message = "\n".join(f"- {line}" for line in lines)[:1024]
    body = urllib.parse.urlencode(
        {
            "token": application_token,
            "user": user_key,
            "title": title,
            "message": message,
            "priority": str(priority),
        }
    ).encode("ascii")
    request = urllib.request.Request(
        "https://api.pushover.net/1/messages.json",
        data=body,
        headers={"User-Agent": "homelab-adguard-anomaly-monitor/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError(f"Pushover returned HTTP {response.status}")
    except (urllib.error.URLError, TimeoutError) as error:
        raise RuntimeError(f"Pushover delivery failed: {error}") from error


def main() -> int:
    config_path = Path(os.environ["ADGUARD_MONITOR_CONFIG"])
    credentials_directory = Path(os.environ["CREDENTIALS_DIRECTORY"])
    state_directory = Path(os.environ["STATE_DIRECTORY"])
    state_path = state_directory / "state.json"

    config = load_json(config_path, {})
    state = load_json(
        state_path,
        {
            "version": STATE_VERSION,
            "samples": [],
            "conditions": {},
            "auth_failures": {},
        },
    )
    if state.get("version") != STATE_VERSION:
        raise ValueError("unsupported AdGuard anomaly monitor state version")

    username = str(config["username"])
    password = read_secret(credentials_directory / "adguard-password")
    application_token = read_secret(
        credentials_directory / "pushover-application-token"
    )
    user_key = read_secret(credentials_directory / "pushover-user-key")
    now = int(time.time())
    evaluated: dict[str, dict[str, Any]] = {}
    results: dict[str, dict[str, Any]] = {}
    auth_failures = state.setdefault("auth_failures", {})

    for target in config["targets"]:
        name = str(target["name"])
        retry_at = int(auth_failures.get(name, 0)) + AUTH_RETRY_SECONDS
        if retry_at > now:
            minutes = math.ceil((retry_at - now) / 60)
            add_condition(
                evaluated,
                f"target:{name}:api",
                True,
                f"{name} API authentication failed",
                f"Authentication retries are paused for another {minutes} minutes",
                1,
            )
            continue

        try:
            result = inspect_target(
                target,
                username,
                password,
                float(config["request_timeout_seconds"]),
                int(config["lookback_milliseconds"]),
            )
        except AuthenticationError as error:
            auth_failures[name] = now
            add_condition(
                evaluated,
                f"target:{name}:api",
                True,
                f"{name} API authentication failed",
                f"{error}; retries are paused for 15 minutes",
                1,
            )
            continue
        except (RuntimeError, ValueError) as error:
            add_condition(
                evaluated,
                f"target:{name}:api",
                True,
                f"{name} AdGuard API is unavailable",
                str(error),
                int(config["failure_sustain_runs"]),
            )
            continue

        auth_failures.pop(name, None)
        results[name] = result
        add_condition(
            evaluated,
            f"target:{name}:api",
            False,
            f"{name} AdGuard API is available",
            "The authenticated status and statistics requests succeeded",
            int(config["failure_sustain_runs"]),
        )
        add_condition(
            evaluated,
            f"target:{name}:protection",
            not result["protection_enabled"],
            f"{name} AdGuard protection is disabled",
            "Filtering protection must remain enabled",
            2,
        )
        add_condition(
            evaluated,
            f"target:{name}:processing-latency",
            result["average_processing_seconds"]
            > float(config["processing_latency_seconds"]),
            f"{name} DNS processing is persistently slow",
            (
                f"One-hour average is {result['average_processing_seconds'] * 1000:.0f} ms "
                f"(limit {float(config['processing_latency_seconds']) * 1000:.0f} ms)"
            ),
            int(config["failure_sustain_runs"]),
        )
        add_condition(
            evaluated,
            f"target:{name}:upstream-latency",
            result["maximum_upstream_seconds"]
            > float(config["upstream_latency_seconds"]),
            f"{name} has a persistently slow upstream",
            (
                f"Slowest one-hour upstream average is "
                f"{result['maximum_upstream_seconds'] * 1000:.0f} ms "
                f"(limit {float(config['upstream_latency_seconds']) * 1000:.0f} ms)"
            ),
            int(config["failure_sustain_runs"]),
        )

    samples = state.setdefault("samples", [])
    retention_cutoff = now - int(config["sample_retention_days"]) * 86400
    samples[:] = [sample for sample in samples if int(sample.get("timestamp", 0)) >= retention_cutoff]

    latest: dict[str, Any] = {
        "timestamp": now,
        "targets": results,
        "baseline_ready": False,
    }
    target_names = {str(target["name"]) for target in config["targets"]}
    if set(results) == target_names:
        combined_queries = sum(result["queries"] for result in results.values())
        combined_blocked = sum(result["blocked"] for result in results.values())
        combined_blocked_ratio = (
            combined_blocked / combined_queries if combined_queries else 0.0
        )
        current_hour = time.localtime(now).tm_hour
        baseline_age_seconds = now - min(
            [int(sample["timestamp"]) for sample in samples],
            default=now,
        )
        baseline_samples = [
            sample
            for sample in samples
            if int(sample.get("local_hour", -1)) == current_hour
        ]
        baseline_ready = (
            baseline_age_seconds >= int(config["learning_days"]) * 86400
            and len(baseline_samples) >= 36
        )

        latest.update(
            {
                "baseline_ready": baseline_ready,
                "learning_age_days": round(baseline_age_seconds / 86400, 2),
                "combined_queries": combined_queries,
                "combined_blocked_ratio": combined_blocked_ratio,
                # Resolver balance and client concentration are observations only.
                "resolver_query_share": {
                    name: result["queries"] / combined_queries
                    if combined_queries
                    else 0.0
                    for name, result in results.items()
                },
                "top_client_share": {
                    name: result["top_client_share"]
                    for name, result in results.items()
                },
            }
        )

        if baseline_ready:
            query_values = [
                finite_number(sample.get("combined_queries"))
                for sample in baseline_samples
            ]
            ratio_values = [
                finite_number(sample.get("combined_blocked_ratio"))
                for sample in baseline_samples
            ]
            query_median, query_deviation = robust_bounds(query_values)
            ratio_median, ratio_deviation = robust_bounds(ratio_values)
            volume_limit = max(
                query_median * 3,
                query_median + 8 * query_deviation,
                500,
            )
            ratio_limit = max(0.20, 8 * ratio_deviation)
            add_condition(
                evaluated,
                "aggregate:query-spike",
                combined_queries > volume_limit,
                "Combined AdGuard query volume is anomalously high",
                (
                    f"Last hour: {combined_queries} queries; "
                    f"same-hour baseline median: {query_median:.0f}"
                ),
                int(config["failure_sustain_runs"]),
            )
            add_condition(
                evaluated,
                "aggregate:blocked-ratio",
                combined_queries >= 100
                and abs(combined_blocked_ratio - ratio_median) > ratio_limit,
                "Combined AdGuard blocked-query ratio is anomalous",
                (
                    f"Last hour: {combined_blocked_ratio:.1%}; "
                    f"same-hour baseline median: {ratio_median:.1%}"
                ),
                int(config["failure_sustain_runs"]),
            )

        samples.append(
            {
                "timestamp": now,
                "local_hour": current_hour,
                "combined_queries": combined_queries,
                "combined_blocked_ratio": combined_blocked_ratio,
            }
        )

    state["latest"] = latest
    state["last_successful_run"] = now
    new_alerts, resolutions = update_condition_state(state, evaluated)

    try:
        if new_alerts:
            send_pushover(
                application_token,
                user_key,
                "AdGuard anomaly detected",
                [
                    f"{condition['summary']}: {condition['detail']}"
                    for condition in new_alerts
                ],
                priority=0,
            )
            for condition in new_alerts:
                state["conditions"][condition["key"]]["notified"] = True

        if resolutions:
            send_pushover(
                application_token,
                user_key,
                "AdGuard anomaly resolved",
                [condition["summary"] for condition in resolutions],
                priority=-1,
            )
            for condition in resolutions:
                state["conditions"][condition["key"]]["notified"] = False
    except RuntimeError:
        write_json_atomic(state_path, state)
        raise

    write_json_atomic(state_path, state)

    for name, result in results.items():
        print(
            f"{name}: queries_1h={result['queries']} "
            f"blocked={result['blocked_ratio']:.1%} "
            f"processing={result['average_processing_seconds'] * 1000:.0f}ms "
            f"upstream_max={result['maximum_upstream_seconds'] * 1000:.0f}ms"
        )
    if latest.get("baseline_ready"):
        print("behavioral baseline: active")
    else:
        print(
            "behavioral baseline: learning "
            f"({latest.get('learning_age_days', 0):.2f}/{config['learning_days']} days)"
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:  # The systemd/Healthchecks failure path owns this.
        print(f"adguard-anomaly-monitor: {error}", file=sys.stderr)
        sys.exit(1)
