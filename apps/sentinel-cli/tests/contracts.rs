//! Public CLI contracts exercised with synthetic loopback services and disposable state.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use httpmock::{Method::GET, Mock, MockServer};
use jsonschema::Validator;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const BINARY: &str = env!("CARGO_BIN_EXE_adguard-sentinel");
const REPORT_SCHEMA: &str = include_str!("../../../schemas/run-report-v1.schema.json");
const GOLDEN: [(&str, &str); 6] = [
    (
        "/control/status",
        include_str!("../../../testdata/api/status.json"),
    ),
    (
        "/control/stats",
        include_str!("../../../testdata/api/stats.json"),
    ),
    (
        "/control/dns_info",
        include_str!("../../../testdata/api/dns-info.json"),
    ),
    (
        "/control/filtering/status",
        include_str!("../../../testdata/api/filtering-status.json"),
    ),
    (
        "/control/rewrite/list",
        include_str!("../../../testdata/api/rewrite-list.json"),
    ),
    (
        "/control/rewrite/settings",
        include_str!("../../../testdata/api/rewrite-settings.json"),
    ),
];

fn golden(server: &MockServer) -> Vec<Mock<'_>> {
    GOLDEN
        .iter()
        .map(|(path, body)| {
            server.mock(|when, then| {
                when.method(GET).path(*path);
                then.status(200)
                    .header("content-type", "application/json")
                    .body(*body);
            })
        })
        .collect()
}

struct Harness {
    _directory: TempDir,
    config: PathBuf,
    state: PathBuf,
}

impl Harness {
    fn new(first: &str, second: &str) -> Self {
        let directory = tempdir().expect("temporary state directory");
        let state = directory.path().join("state.sqlite");
        let config = directory.path().join("config.toml");
        fs::write(
            &config,
            format!(
                r#"schema_version = 1
[state]
path = {state}
retention_days = 21
[observation]
request_timeout_ms = 500
notification_timeout_ms = 15000
max_response_bytes = 4194304
stats_lookback_ms = 3600000
target_concurrency = 2
minimum_complete_targets = 1
adguard_version_requirement = ">=0.107.78,<0.108.0"
[behavioral_baseline]
target_ids = ["resolver-a", "resolver-b"]
time_zone = "Europe/Amsterdam"
learning_days = 7
minimum_same_hour_samples = 36
[condition_profiles.contract]
authentication_rejected_sustain_runs = 1
api_unavailable_sustain_runs = 1
invalid_response_sustain_runs = 1
unsupported_version_sustain_runs = 1
protection_disabled_sustain_runs = 1
processing_latency_sustain_runs = 4
upstream_latency_sustain_runs = 4
policy_drift_sustain_runs = 1
behavioral_anomaly_sustain_runs = 4
recovery_runs = 1
authentication_retry_seconds = 900
processing_latency_ms = 500
upstream_latency_ms = 750
[policies.declared]
upstream_mode = "parallel"
filters = [{{ url = "https://filters.example.invalid/disabled.txt", enabled = false }}]
[[targets]]
id = "resolver-a"
name = "Resolver A"
base_url = "{first}"
auth = "none"
policy = "declared"
condition_profile = "contract"
[[targets]]
id = "resolver-b"
name = "Resolver B"
base_url = "{second}"
auth = "none"
condition_profile = "contract"
"#,
                state = serde_json::to_string(&state).expect("state path")
            ),
        )
        .expect("configuration");
        Self {
            _directory: directory,
            config,
            state,
        }
    }

    fn check(&self, format: &str) -> Output {
        command(&[
            "check",
            "--config",
            path(&self.config),
            "--dry-run",
            "--format",
            format,
        ])
    }

    fn report(&self, format: &str, limit: &str) -> Output {
        command(&[
            "report",
            "--state",
            path(&self.state),
            "--format",
            format,
            "--limit",
            limit,
        ])
    }
}

fn path(path: &Path) -> &str {
    path.to_str().expect("test path is UTF-8")
}

fn command(arguments: &[&str]) -> Output {
    let output = Command::new(BINARY)
        .args(arguments)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .output()
        .expect("run CLI");
    assert!(
        output.status.success(),
        "CLI {arguments:?}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn value(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("one JSON report")
}

fn validator(schema: &Value) -> Result<Validator, jsonschema::ValidationError<'static>> {
    jsonschema::options()
        .offline()
        .should_validate_formats(true)
        .build(schema)
}

fn report_validator() -> Validator {
    validator(&serde_json::from_str(REPORT_SCHEMA).expect("report schema JSON"))
        .expect("report schema compiles without external retrieval")
}

fn assert_valid(validator: &Validator, report: &Value) {
    let errors: Vec<_> = validator
        .iter_errors(report)
        .map(|error| format!("{}: {error}", error.instance_path()))
        .collect();
    assert!(errors.is_empty(), "report violates JSON Schema: {errors:?}");
}

#[test]
fn produced_reports_validate_recursively_and_json_jsonl_and_storage_agree() {
    let server = MockServer::start();
    let mocks = golden(&server);
    let harness = Harness::new(&server.base_url(), &server.base_url());
    let validator = report_validator();
    let first = value(&harness.check("json"));
    assert_valid(&validator, &first);
    assert_eq!(first["complete_targets"], 2);
    assert!(first["aggregate"].is_object());
    assert!(!first["findings"].as_array().unwrap().is_empty());
    assert_eq!(first["notifications"][0]["status"], "suppressed");
    assert_eq!(first, value(&harness.report("json", "1")));
    assert_eq!(first, value(&harness.report("jsonl", "1")));
    let explained = command(&[
        "report",
        "--state",
        path(&harness.state),
        "--limit",
        "1",
        "--explain",
    ]);
    let human = String::from_utf8(explained.stdout).expect("human report");
    assert!(human.contains("baseline [resolver-a]: rate=learning; ratio=learning"));
    assert!(human.contains("baseline [group]: rate=learning; ratio=learning"));
    assert!(human.contains("[Alert/Suppressed]"));
    assert!(human.contains("\"minimum_same_hour_windows\":36"));
    assert!(human.contains("(counters held)"));

    let second_output = harness.check("jsonl");
    assert_eq!(
        String::from_utf8_lossy(&second_output.stdout)
            .lines()
            .count(),
        1
    );
    let second = value(&second_output);
    assert_valid(&validator, &second);
    assert_eq!(second, value(&harness.report("json", "1")));
    let history = harness.report("jsonl", "2");
    let reports: Vec<Value> = String::from_utf8_lossy(&history.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSONL row"))
        .collect();
    assert_eq!(reports, vec![second, first.clone()]);
    for report in &reports {
        assert_valid(&validator, report);
    }
    for mock in mocks {
        mock.assert_calls(4);
    }

    // These values retain all valid top-level keys. Each must fail through nested schema rules.
    for (pointer, replacement) in [
        ("/targets/0/operational/queries", json!("1000")),
        ("/targets/0/dns/upstream_dns/0", json!(42)),
        ("/targets/0/filters/0/enabled", json!("true")),
        ("/targets/0/rewrites/0/domain", Value::Null),
        ("/evaluations/0/outcome", json!("healthy")),
        ("/findings/0/consecutive_active", json!(-1)),
        ("/notifications/0/condition_ids/0", json!(false)),
        ("/notifications/0/status", json!("confirmed-ish")),
        ("/aggregate/resolver_query_share/resolver-a", json!("half")),
        ("/health/met", json!("yes")),
    ] {
        let mut invalid = first.clone();
        *invalid
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("produced nested field {pointer} must exist")) = replacement;
        assert!(
            !validator.is_valid(&invalid),
            "schema accepted invalid field {pointer}"
        );
    }
    let mut extra = first;
    extra["targets"][0]["operational"]["invented_health"] = json!(true);
    assert!(
        !validator.is_valid(&extra),
        "nested unknown fields must be rejected"
    );
}

#[test]
fn incomplete_group_preserves_complete_members_independent_evaluations() {
    let healthy = MockServer::start();
    let mocks = golden(&healthy);
    let unavailable = MockServer::start();
    let failure = unavailable.mock(|when, then| {
        when.method(GET).path("/control/status");
        then.status(503);
    });
    let harness = Harness::new(&healthy.base_url(), &unavailable.base_url());
    let report = value(&harness.check("json"));
    assert_valid(&report_validator(), &report);
    assert_eq!(report["run_status"], "partial");
    assert_eq!(report["complete_targets"], 1);
    assert_eq!(report["health"]["met"], true);
    assert_eq!(report["exit"]["code"], 0);
    assert!(report["aggregate"].is_null());
    let targets = report["targets"].as_array().unwrap();
    let complete = targets
        .iter()
        .find(|target| target["id"] == "resolver-a")
        .unwrap();
    let incomplete = targets
        .iter()
        .find(|target| target["id"] == "resolver-b")
        .unwrap();
    assert_eq!(complete["complete"], true);
    assert_eq!(incomplete["status"], "unavailable");
    assert_eq!(incomplete["complete"], false);
    assert!(incomplete["operational"].is_null());
    let evaluations = report["evaluations"].as_array().unwrap();
    assert!(
        !evaluations
            .iter()
            .any(|evaluation| evaluation["target_id"].is_null())
    );
    for kind in ["query_rate", "blocked_ratio", "blocking_collapse"] {
        let evaluation = evaluations
            .iter()
            .find(|evaluation| {
                evaluation["target_id"] == "resolver-a" && evaluation["kind"] == kind
            })
            .expect("complete member's independent condition");
        assert_eq!(evaluation["outcome"], "not_evaluated");
        assert_eq!(evaluation["reason"], "baseline_learning");
        assert!(!evaluations.iter().any(
            |evaluation| evaluation["target_id"] == "resolver-b" && evaluation["kind"] == kind
        ));
    }
    for mock in mocks {
        mock.assert_calls(1);
    }
    failure.assert_calls(1);
}

#[test]
fn schema_validation_refuses_external_retrieval() {
    let server = MockServer::start();
    let remote = server.mock(|when, then| {
        when.method(GET).path("/schema");
        then.status(200).json_body(json!({"type": "string"}));
    });
    assert!(validator(&json!({"$ref": format!("{}/schema", server.base_url())})).is_err());
    remote.assert_calls(0);
    assert!(validator(&json!({"$ref": "file:///schema.json"})).is_err());
}
