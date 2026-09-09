use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use httpmock::{Method::GET, MockServer};
use jiff::Timestamp;
use sentinel_core::{AlertDeliveryState, Clock, Config, FixedClock, NotificationStatus, RunMode};
use sentinel_store::StateStore;
use tempfile::{TempDir, tempdir};

use super::{FailOn, OutputFormat, PushoverClient, check_with_sink, report};

const CHILD_TEST: &str = "crash_tests::subprocess_command";
const STARTED_AT: &str = "2027-01-15T08:00:00Z";
const RESTARTED_AT: &str = "2027-01-15T08:20:00Z";
const DEADLINE: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(10);
const SUCCESS_BODY: &str = r#"{"status":1,"request":"synthetic-request"}"#;

// Only this ignored test understands the child environment. Production command
// parsing and transports have no environment override or crash hook.
#[test]
#[ignore = "invoked only by the subprocess acceptance tests"]
fn subprocess_command() {
    let Ok(action) = std::env::var("SENTINEL_ACCEPTANCE_ACTION") else {
        return;
    };
    let path = PathBuf::from(std::env::var_os("SENTINEL_ACCEPTANCE_CONFIG").expect("config"));
    let config = Config::load(&path, false).expect("synthetic config");
    for target in &config.targets {
        assert_loopback(&target.base_url);
    }
    let result = if action == "report" {
        report(&config.state.path, OutputFormat::Json, 1, None, false)
    } else {
        assert_eq!(action, "check");
        let dry_run = std::env::var("SENTINEL_ACCEPTANCE_DRY_RUN").expect("mode") == "true";
        let sink = if dry_run {
            None
        } else {
            let endpoint = std::env::var("SENTINEL_ACCEPTANCE_PUSHOVER").expect("endpoint");
            assert_loopback(&endpoint);
            Some(PushoverClient::with_endpoint(&config, &endpoint).expect("synthetic sink"))
        };
        let instant = std::env::var("SENTINEL_ACCEPTANCE_INSTANT").expect("instant");
        let clock = FixedClock::new(instant.parse().expect("timestamp"));
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(check_with_sink(
                &path,
                dry_run,
                OutputFormat::Json,
                FailOn::Never,
                &clock,
                sink,
            ))
    };
    let code = match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("adguard-sentinel: {:#}", error.error);
            error.code
        }
    };
    std::process::exit(i32::from(code));
}

fn assert_loopback(endpoint: &str) {
    let url = reqwest::Url::parse(endpoint).expect("local URL");
    assert_eq!(url.scheme(), "http");
    assert_eq!(url.host_str(), Some("127.0.0.1"));
}

#[derive(Debug)]
struct Harness {
    directory: TempDir,
    config: PathBuf,
    state: PathBuf,
}

impl Harness {
    fn new(adguard_endpoint: &str) -> Self {
        let directory = tempdir().expect("temporary directory");
        let state = directory.path().join("state.sqlite");
        let config = directory.path().join("config.toml");
        let token = directory.path().join("token");
        let user = directory.path().join("user");
        fs::write(&token, "synthetic-application-token").expect("synthetic token");
        fs::write(&user, "synthetic-user-key").expect("synthetic user");
        fs::write(
            &config,
            format!(
                r#"schema_version = 1
[state]
path = "{}"
retention_days = 21
[observation]
request_timeout_ms = 60000
notification_timeout_ms = 60000
max_response_bytes = 4194304
stats_lookback_ms = 3600000
target_concurrency = 1
minimum_complete_targets = 1
adguard_version_requirement = ">=0.107.78,<0.108.0"
[notifications]
provider = "pushover"
[notifications.pushover]
application_token_file = "{}"
user_key_file = "{}"
[[targets]]
id = "resolver-a"
name = "Resolver A"
base_url = "{}"
auth = "none"
"#,
                state.display(),
                token.display(),
                user.display(),
                adguard_endpoint,
            ),
        )
        .expect("synthetic config");
        Self {
            directory,
            config,
            state,
        }
    }

    fn spawn(
        &self,
        label: &str,
        action: &str,
        dry_run: bool,
        instant: &str,
        pushover: &LocalServer,
    ) -> ChildCommand {
        let stdout = self.directory.path().join(format!("{label}.stdout"));
        let stderr = self.directory.path().join(format!("{label}.stderr"));
        let child = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
            .env("SENTINEL_ACCEPTANCE_ACTION", action)
            .env("SENTINEL_ACCEPTANCE_CONFIG", &self.config)
            .env("SENTINEL_ACCEPTANCE_DRY_RUN", dry_run.to_string())
            .env("SENTINEL_ACCEPTANCE_INSTANT", instant)
            .env("SENTINEL_ACCEPTANCE_PUSHOVER", &pushover.endpoint)
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).expect("child stdout"))
            .stderr(File::create(&stderr).expect("child stderr"))
            .spawn()
            .expect("spawn child test");
        ChildCommand {
            child,
            stdout,
            stderr,
        }
    }
}

#[derive(Debug)]
struct ChildCommand {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl ChildCommand {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll child") {
                return status;
            }
            if Instant::now() >= deadline {
                self.kill();
                panic!("child exceeded deadline: {}", self.output());
            }
            thread::sleep(POLL);
        }
    }

    fn kill(&mut self) {
        self.child.kill().expect("terminate child");
        self.child.wait().expect("reap child");
    }

    fn output(&self) -> String {
        format!(
            "stdout: {}\nstderr: {}",
            fs::read_to_string(&self.stdout).expect("read stdout"),
            fs::read_to_string(&self.stderr).expect("read stderr"),
        )
    }

    fn assert_code(&mut self, code: i32) {
        let status = self.wait();
        assert_eq!(status.code(), Some(code), "{}", self.output());
    }

    fn json_report(&self) -> serde_json::Value {
        let stdout = fs::read_to_string(&self.stdout).expect("read stdout");
        let json_start = stdout
            .find('{')
            .expect("JSON after the test runner preamble");
        serde_json::from_str(&stdout[json_start..]).expect("complete CLI JSON report")
    }
}

impl Drop for ChildCommand {
    fn drop(&mut self) {
        // Reap on assertion failure too, before the temporary state is removed.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Clone, Copy, Debug)]
enum ResponsePause {
    None,
    BeforeResponse,
    DuringSuccessBody,
}

#[derive(Debug)]
struct LocalServer {
    endpoint: String,
    requests: Receiver<String>,
    count: Arc<AtomicUsize>,
    release: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl LocalServer {
    fn new(status: u16, body: &'static str, pause: ResponsePause) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("local listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("local address"));
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let (sender, requests) = mpsc::channel();
        let count = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_count = Arc::clone(&count);
        let thread_release = Arc::clone(&release);
        let thread_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(POLL);
                        continue;
                    }
                    Err(error) => panic!("local accept failed: {error}"),
                };
                stream.set_read_timeout(Some(POLL)).expect("read timeout");
                stream.set_write_timeout(Some(POLL)).expect("write timeout");
                let request = read_request(&mut stream, &thread_stop);
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                let request = request.expect("complete local request");
                let first = thread_count.fetch_add(1, Ordering::SeqCst) == 0;
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let prefix = if first && matches!(pause, ResponsePause::DuringSuccessBody) {
                    let prefix = response.find("\r\n\r\n").expect("response headers") + 5;
                    stream
                        .write_all(&response.as_bytes()[..prefix])
                        .expect("partial response");
                    prefix
                } else {
                    0
                };
                if sender.send(request).is_err() {
                    break;
                }
                if first && !matches!(pause, ResponsePause::None) {
                    while !thread_release.load(Ordering::SeqCst)
                        && !thread_stop.load(Ordering::SeqCst)
                    {
                        thread::sleep(POLL);
                    }
                }
                if !thread_stop.load(Ordering::SeqCst) {
                    // A killed client can close the paused connection first.
                    let _ = stream.write_all(&response.as_bytes()[prefix..]);
                }
            }
        });
        Self {
            endpoint,
            requests,
            count,
            release,
            stop,
            worker: Some(worker),
        }
    }

    fn received(&self) -> String {
        self.requests
            .recv_timeout(DEADLINE)
            .expect("request before deadline")
    }

    fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("local server worker");
            }
        }
    }
}

fn read_request(stream: &mut TcpStream, stop: &AtomicBool) -> io::Result<String> {
    let deadline = Instant::now() + DEADLINE;
    let mut request = Vec::new();
    let mut buffer = [0; 4096];
    while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(length) => request.extend_from_slice(&buffer[..length]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
        assert!(request.len() < 65_536, "synthetic request exceeded bound");
        if let Some(boundary) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..boundary]);
            let length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, value)| {
                    value.trim().parse::<usize>().expect("body length")
                });
            if request.len() >= boundary + 4 + length {
                return String::from_utf8(request).map_err(io::Error::other);
            }
        }
    }
    Err(io::Error::other("local request did not complete"))
}

fn persisted_reports(state: &Path) -> Vec<sentinel_core::RunReport> {
    StateStore::open_existing(state)
        .expect("read-only state")
        .load_reports(10, None)
        .expect("persisted reports")
}

#[test]
fn killed_sender_is_quarantined_without_resending_after_restart() {
    for pause in [
        ResponsePause::BeforeResponse,
        ResponsePause::DuringSuccessBody,
    ] {
        let adguard = LocalServer::new(401, "{}", ResponsePause::None);
        let pushover = LocalServer::new(200, SUCCESS_BODY, pause);
        let harness = Harness::new(&adguard.endpoint);
        let mut sender = harness.spawn("sender", "check", false, STARTED_AT, &pushover);
        let request = pushover.received();
        assert!(request.starts_with("POST / HTTP/1.1\r\n"));
        assert!(request.contains("token=synthetic-application-token"));
        assert!(request.contains("user=synthetic-user-key"));

        let before_crash = persisted_reports(&harness.state);
        assert_eq!(before_crash.len(), 1);
        assert_eq!(before_crash[0].notifications.len(), 1);
        let notification_id = before_crash[0].notifications[0].id.clone();
        let mut reader = harness.spawn("reader", "report", false, STARTED_AT, &pushover);
        reader.assert_code(0);
        assert!(reader.output().contains(&notification_id));
        let mut overlapping = harness.spawn("overlapping", "check", false, RESTARTED_AT, &pushover);
        overlapping.assert_code(5);
        assert!(
            overlapping
                .output()
                .contains("state database is already in use")
        );
        assert_eq!(
            adguard.count(),
            1,
            "ownership ended before delivery completed"
        );

        sender.kill();
        pushover.release();
        let mut restarted = harness.spawn("restarted", "check", false, RESTARTED_AT, &pushover);
        // The synthetic resolver rejects authentication; recovery does not make
        // that observation healthy. A successful restart may still exit 3/4.
        let status = restarted.wait();
        assert!(
            matches!(status.code(), Some(3 | 4)),
            "{}",
            restarted.output()
        );
        assert_eq!(
            pushover.count(),
            1,
            "restart resent an ambiguous attempt: {pause:?}"
        );

        let reports = persisted_reports(&harness.state);
        assert_eq!(reports.len(), 2);
        let original = reports
            .iter()
            .find(|run| run.run_id == before_crash[0].run_id)
            .expect("original run");
        assert_eq!(original.notifications[0].id, notification_id);
        assert_eq!(
            original.notifications[0].status,
            NotificationStatus::Unknown
        );
        assert!(
            original
                .evaluations
                .iter()
                .any(|evaluation| evaluation.notification_state == AlertDeliveryState::Unknown)
        );
        assert!(
            StateStore::open_existing(&harness.state)
                .expect("state")
                .pending_outbox(RESTARTED_AT)
                .expect("pending outbox")
                .is_empty()
        );
        assert_eq!(reports[0].mode, RunMode::Live);
    }
}

#[test]
fn overlapping_live_and_dry_checks_cannot_claim_new_state_and_killing_owner_releases_it() {
    let adguard = LocalServer::new(401, "{}", ResponsePause::BeforeResponse);
    let pushover = LocalServer::new(200, SUCCESS_BODY, ResponsePause::None);
    let harness = Harness::new(&adguard.endpoint);
    assert!(!harness.state.exists());
    let mut owner = harness.spawn("owner", "check", false, STARTED_AT, &pushover);
    assert!(
        adguard
            .received()
            .starts_with("GET /control/status HTTP/1.1\r\n")
    );
    assert!(persisted_reports(&harness.state).is_empty());

    for (label, dry_run) in [("overlapping-live", false), ("overlapping-dry", true)] {
        let mut overlapping = harness.spawn(label, "check", dry_run, STARTED_AT, &pushover);
        overlapping.assert_code(5);
        assert!(
            overlapping
                .output()
                .contains("state database is already in use")
        );
    }
    assert_eq!(adguard.count(), 1, "overlapping check observed a target");
    assert!(persisted_reports(&harness.state).is_empty());

    owner.kill();
    adguard.release();
    let mut resumed = harness.spawn("resumed", "check", true, RESTARTED_AT, &pushover);
    resumed.assert_code(3);
    let reports = persisted_reports(&harness.state);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].mode, RunMode::DryRun);
    assert_eq!(adguard.count(), 2);
    assert_eq!(pushover.count(), 0);
}

#[derive(Debug)]
struct RegressingDeliveryClock {
    calls: AtomicUsize,
}

impl Clock for RegressingDeliveryClock {
    fn now(&self) -> Timestamp {
        let instant = match self.calls.fetch_add(1, Ordering::SeqCst) {
            0 => "2027-01-15T08:00:00.000000000Z",
            1 | 2 => "2027-01-15T08:00:00.900000000Z",
            _ => "2027-01-15T08:00:00.100000000Z",
        };
        instant.parse().expect("synthetic timestamp")
    }
}

#[tokio::test]
async fn clock_regression_before_delivery_does_not_begin_or_send_an_attempt() {
    let adguard = LocalServer::new(401, "{}", ResponsePause::None);
    let pushover = LocalServer::new(200, SUCCESS_BODY, ResponsePause::None);
    let harness = Harness::new(&adguard.endpoint);
    let config = Config::load(&harness.config, false).expect("config");
    let sink = PushoverClient::with_endpoint(&config, &pushover.endpoint).expect("local sink");
    let clock = RegressingDeliveryClock {
        calls: AtomicUsize::new(0),
    };
    let result = tokio::time::timeout(
        DEADLINE,
        check_with_sink(
            &harness.config,
            false,
            OutputFormat::Json,
            FailOn::Never,
            &clock,
            Some(sink),
        ),
    )
    .await
    .expect("check completes within deadline");

    assert_eq!(
        pushover.count(),
        0,
        "regressed clock allowed notification transmission"
    );
    let error = result.expect_err("regressed delivery timestamp must fail");
    assert_eq!(error.code, 5);
    assert!(error.error.to_string().contains("clock regressed"));
    let reports = persisted_reports(&harness.state);
    assert_eq!(
        reports.len(),
        1,
        "completed observation must remain committed"
    );
    assert_eq!(reports[0].completed_at, "2027-01-15T08:00:00.900000000Z");
    assert_eq!(reports[0].notifications.len(), 1);
    assert_eq!(
        reports[0].notifications[0].status,
        NotificationStatus::Pending
    );
    let pending = StateStore::open_existing(&harness.state)
        .expect("state")
        .pending_outbox(RESTARTED_AT)
        .expect("pending outbox");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, reports[0].notifications[0].id);
}

#[test]
fn maximum_unsigned_counts_survive_observation_sqlite_and_cli_json() {
    let adguard = MockServer::start();
    let upstream = "https://dns.example.invalid/dns-query";
    let filter = "https://filters.example.invalid/enabled.txt";
    let responses = [
        (
            "/control/status",
            serde_json::json!({
                "protection_enabled": true, "running": true, "version": "v0.107.78",
            }),
        ),
        (
            "/control/stats",
            serde_json::json!({
                "num_dns_queries": u64::MAX, "num_blocked_filtering": u64::MAX,
                "avg_processing_time": 0.01,
                "top_upstreams_avg_time": [{ upstream: 0.02 }],
                "top_clients": [{ "192.0.2.10": u64::MAX }],
            }),
        ),
        (
            "/control/dns_info",
            serde_json::json!({
                "upstream_dns": [upstream], "upstream_mode": "load_balance",
            }),
        ),
        (
            "/control/filtering/status",
            serde_json::json!({
                "enabled": true,
                "filters": [{"id": 1, "url": filter, "enabled": true,
                    "rules_count": u64::MAX, "last_updated": "2027-01-15T07:00:00Z"}],
            }),
        ),
        ("/control/rewrite/list", serde_json::json!([])),
        (
            "/control/rewrite/settings",
            serde_json::json!({"enabled": true}),
        ),
    ];
    let mocks = responses
        .into_iter()
        .map(|(path, body)| {
            adguard.mock(|when, then| {
                when.method(GET).path(path);
                then.status(200).json_body(body);
            })
        })
        .collect::<Vec<_>>();
    let harness = Harness::new(&adguard.base_url());
    let mut config = fs::read_to_string(&harness.config).expect("config");
    write!(
        config,
        r#"policy = "counts"
[[policies.counts.filters]]
url = "{filter}"
enabled = true
maximum_age_hours = 72
"#
    )
    .expect("render required-filter configuration");
    fs::write(&harness.config, config).expect("config with required filter");
    let pushover = LocalServer::new(200, SUCCESS_BODY, ResponsePause::None);
    let mut observation = harness.spawn("maximum-counts", "check", true, STARTED_AT, &pushover);
    observation.assert_code(0);
    for mock in mocks {
        mock.assert_calls(1);
    }

    let reports = persisted_reports(&harness.state);
    assert_eq!(reports.len(), 1);
    let target = &reports[0].targets[0];
    assert!(target.complete);
    let operational = target
        .operational
        .as_ref()
        .expect("operational observation");
    assert_eq!(operational.queries, u64::MAX);
    assert_eq!(operational.blocked, u64::MAX);
    assert_eq!(target.filters.len(), 1);
    assert_eq!(target.filters[0].rules_count, u64::MAX);
    assert!((operational.blocked_ratio - 1.0).abs() < f64::EPSILON);

    let mut reader = harness.spawn(
        "maximum-counts-report",
        "report",
        true,
        STARTED_AT,
        &pushover,
    );
    reader.assert_code(0);
    let json = reader.json_report();
    assert_eq!(observation.json_report(), json);
    let target = &json["targets"][0];
    assert_eq!(target["operational"]["queries"].as_u64(), Some(u64::MAX));
    assert_eq!(target["operational"]["blocked"].as_u64(), Some(u64::MAX));
    assert_eq!(target["filters"][0]["rules_count"].as_u64(), Some(u64::MAX));
    assert_eq!(pushover.count(), 0);
}
