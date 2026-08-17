#![forbid(unsafe_code)]

mod notify;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use futures::{StreamExt, stream};
use jiff::Timestamp;
use schemars::schema_for;
use secrecy::SecretString;
use sentinel_adguard::{AdGuardError, AdGuardReadClient, ReqwestAdGuardClient};
use sentinel_core::{
    AlertDeliveryState, Clock, Config, EvaluationOutcome, ExitReport, NotificationProvider,
    NotificationStatus, REPORT_SCHEMA_VERSION, RunHealth, RunMode, RunReport, RunStatus,
    STATE_SCHEMA_VERSION, Severity, SystemClock, TargetReport, TargetStatus, TransitionKind,
    evaluate_aggregate, evaluate_target, local_time_bucket,
};
use sentinel_store::{NotificationAttemptOutcome, StateStore, canonical_state_schema};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::notify::PushoverClient;

#[derive(Debug, Parser)]
#[command(name = "adguard-sentinel", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ValidateConfig {
        #[arg(long)]
        config: PathBuf,
    },
    Check {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        #[arg(long, value_enum, default_value_t = FailOn::Never)]
        fail_on: FailOn,
    },
    Report {
        #[arg(long)]
        state: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        #[arg(long, default_value_t = 24)]
        limit: usize,
        #[arg(long)]
        since: Option<String>,
    },
    MigrateState {
        #[arg(long)]
        state: PathBuf,
        #[arg(long, requires = "config")]
        legacy_json: Option<PathBuf>,
        #[arg(long, requires = "legacy_json")]
        config: Option<PathBuf>,
    },
    PrintSchema {
        #[arg(value_enum)]
        kind: SchemaKind,
        #[arg(long, default_value_t = 1)]
        version: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Jsonl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum FailOn {
    Never,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SchemaKind {
    Config,
    RunReport,
    State,
}

#[derive(Debug)]
struct CommandError {
    code: u8,
    error: anyhow::Error,
}

impl CommandError {
    fn invocation(error: impl Into<anyhow::Error>) -> Self {
        Self {
            code: 2,
            error: error.into(),
        }
    }

    fn state(error: impl Into<anyhow::Error>) -> Self {
        Self {
            code: 5,
            error: error.into(),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .without_time()
        .init();
    match execute(Cli::parse()).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("adguard-sentinel: {:#}", error.error);
            ExitCode::from(error.code)
        }
    }
}

async fn execute(cli: Cli) -> Result<u8, CommandError> {
    match cli.command {
        Command::ValidateConfig { config } => {
            Config::load(&config, true).map_err(CommandError::invocation)?;
            println!("configuration is valid (schema version 1)");
            Ok(0)
        }
        Command::Check {
            config,
            dry_run,
            format,
            fail_on,
        } => check(&config, dry_run, format, fail_on, &SystemClock).await,
        Command::Report {
            state,
            format,
            limit,
            since,
        } => report(&state, format, limit, since.as_deref()),
        Command::MigrateState {
            state,
            legacy_json,
            config,
        } => migrate_state(&state, legacy_json.as_deref(), config.as_deref()),
        Command::PrintSchema { kind, version } => print_schema(kind, version),
    }
}

async fn check(
    config_path: &Path,
    dry_run: bool,
    format: OutputFormat,
    fail_on: FailOn,
    clock: &dyn Clock,
) -> Result<u8, CommandError> {
    let config = Config::load(config_path, false).map_err(CommandError::invocation)?;
    let passwords = read_target_passwords(&config).map_err(CommandError::invocation)?;
    let started = clock.now();
    let now_unix_seconds = started.as_second();
    let mut store = StateStore::open(&config.state.path).map_err(CommandError::state)?;
    let run_mode = if dry_run {
        RunMode::DryRun
    } else {
        RunMode::Live
    };
    store
        .ensure_run_mode(run_mode)
        .map_err(CommandError::state)?;
    if let Some(latest) = store
        .latest_completed_unix_seconds()
        .map_err(CommandError::state)?
        && now_unix_seconds < latest
    {
        return Err(CommandError::state(anyhow!(
            "wall clock regressed behind the latest completed run; state was not advanced"
        )));
    }
    let client = Arc::new(
        ReqwestAdGuardClient::new(
            config.observation.request_timeout_ms,
            config.observation.max_response_bytes,
            &config.observation.adguard_version_requirement,
        )
        .map_err(CommandError::invocation)?,
    );
    let mut cooldowns = BTreeMap::new();
    for target in &config.targets {
        cooldowns.insert(
            target.id.clone(),
            store
                .target_runtime_state(&target.id)
                .map_err(CommandError::state)?,
        );
    }
    let policies = Arc::new(config.policies.clone());
    let passwords = Arc::new(passwords);
    let targets = stream::iter(config.targets.clone())
        .map(|target| {
            let client = Arc::clone(&client);
            let policies = Arc::clone(&policies);
            let passwords = Arc::clone(&passwords);
            let cooldown = cooldowns.get(&target.id).cloned().flatten();
            async move {
                if let Some(retry_after) = cooldown.and_then(|state| state.auth_retry_after)
                    && retry_after > now_unix_seconds
                {
                    let remaining = retry_after.saturating_sub(now_unix_seconds);
                    return TargetReport::incomplete(
                        target.id,
                        target.name,
                        TargetStatus::AuthenticationCooldown,
                        "authentication_cooldown",
                        format!("authentication retry is paused for {remaining} seconds"),
                    );
                }
                let policy = policies
                    .get(&target.policy)
                    .expect("configuration policy references were validated");
                let password = passwords
                    .get(&target.id)
                    .expect("every target password was loaded");
                match client
                    .observe(
                        &target,
                        policy,
                        password,
                        config.observation.stats_lookback_ms,
                        now_unix_seconds,
                    )
                    .await
                {
                    Ok(report) => report,
                    Err(error) => incomplete_report(&target, &error),
                }
            }
        })
        .buffer_unordered(config.observation.target_concurrency)
        .collect::<Vec<_>>()
        .await;
    let mut targets = targets;
    targets.sort_by(|left, right| left.id.cmp(&right.id));

    let mut evaluations = Vec::new();
    for target in &config.targets {
        let report = targets
            .iter()
            .find(|report| report.id == target.id)
            .expect("every configured target has a report");
        let policy = config
            .policies
            .get(&target.policy)
            .expect("validated policy reference");
        let profile = config
            .condition_profiles
            .get(&target.condition_profile)
            .expect("validated condition profile reference");
        evaluations.extend(evaluate_target(
            target,
            policy,
            profile,
            report,
            now_unix_seconds,
        ));
    }

    let (local_hour, utc_offset_minutes) =
        local_time_bucket(started, &config.behavioral_baseline.time_zone).map_err(|error| {
            CommandError::invocation(anyhow!("invalid behavior time zone: {error}"))
        })?;
    let cutoff_unix_seconds =
        now_unix_seconds.saturating_sub(i64::from(config.state.retention_days) * 86_400);
    let baseline_samples = store
        .load_baseline_samples(cutoff_unix_seconds)
        .map_err(CommandError::state)?;
    let aggregate_profile = baseline_profile(&config).map_err(CommandError::invocation)?;
    let aggregate_evaluation = evaluate_aggregate(
        &config.behavioral_baseline,
        aggregate_profile,
        &baseline_samples,
        &targets,
        now_unix_seconds,
        local_hour,
        utc_offset_minutes,
    );
    let aggregate = aggregate_evaluation
        .as_ref()
        .map(|value| value.observation.clone());
    if let Some(value) = aggregate_evaluation {
        evaluations.extend(value.evaluations);
    }
    evaluations.sort_by(|left, right| left.id.cmp(&right.id));
    let completed = clock.now();
    let complete_targets = targets.iter().filter(|target| target.complete).count();
    let health_met = complete_targets >= config.observation.minimum_complete_targets;
    let mut health_issues = targets
        .iter()
        .filter(|target| !target.complete)
        .map(|target| {
            format!(
                "target {} incomplete: {}",
                target.id,
                target.error_kind.as_deref().unwrap_or("unknown")
            )
        })
        .collect::<Vec<_>>();
    if !health_met {
        health_issues.push("minimum complete target count was not met".to_owned());
    }
    let fail_on_match = evaluations.iter().any(|evaluation| {
        evaluation.outcome == EvaluationOutcome::Active && fail_on.matches(evaluation.severity)
    });
    let initial_exit = if health_met {
        u8::from(fail_on_match)
    } else {
        3
    };
    let mut report = RunReport {
        schema_version: REPORT_SCHEMA_VERSION,
        run_id: Uuid::new_v4().to_string(),
        mode: run_mode,
        started_at: started.to_string(),
        completed_at: completed.to_string(),
        config_sha256: config.fingerprint(),
        state_schema_version: STATE_SCHEMA_VERSION,
        run_status: if !health_met {
            RunStatus::Unhealthy
        } else if complete_targets == config.targets.len() {
            RunStatus::Complete
        } else {
            RunStatus::Partial
        },
        expected_targets: config.targets.len(),
        complete_targets,
        minimum_complete_targets: config.observation.minimum_complete_targets,
        targets,
        aggregate,
        evaluations,
        findings: Vec::new(),
        transitions: Vec::new(),
        notifications: Vec::new(),
        health: RunHealth {
            minimum_complete_targets: config.observation.minimum_complete_targets,
            complete_targets,
            met: health_met,
            issues: health_issues,
        },
        exit: ExitReport {
            code: initial_exit,
            reason: exit_reason(initial_exit).to_owned(),
        },
    };
    let retention_cutoff = Timestamp::new(cutoff_unix_seconds, 0)
        .map_err(|error| CommandError::state(anyhow!(error)))?
        .to_string();
    let suppress_notifications = dry_run
        || matches!(
            config.notifications.provider,
            NotificationProvider::Disabled
        );
    store
        .commit_run(
            &mut report,
            &config,
            now_unix_seconds,
            &retention_cutoff,
            suppress_notifications,
        )
        .map_err(CommandError::state)?;

    let mut notification_failed = false;
    if !suppress_notifications {
        let pending = store
            .pending_outbox(&clock.now().to_string())
            .map_err(CommandError::state)?;
        if !pending.is_empty() {
            let pushover =
                PushoverClient::from_config(&config).map_err(CommandError::invocation)?;
            for message in pending {
                let attempt_started = clock.now().to_string();
                let outcome = pushover.send(&message).await;
                let attempt_completed = clock.now().to_string();
                let attempt_report = store
                    .record_notification_attempt(
                        &message,
                        &attempt_started,
                        &attempt_completed,
                        &outcome,
                    )
                    .map_err(CommandError::state)?;
                if let Some(current) = report
                    .notifications
                    .iter_mut()
                    .find(|current| current.id == attempt_report.id)
                {
                    *current = attempt_report.clone();
                }
                update_report_delivery_state(&mut report, &attempt_report);
                if !matches!(outcome, NotificationAttemptOutcome::Delivered { .. }) {
                    notification_failed = true;
                    break;
                }
            }
        }
    }
    if notification_failed {
        report.exit = ExitReport {
            code: 4,
            reason: exit_reason(4).to_owned(),
        };
        store
            .update_run_exit(&report.run_id, 4)
            .map_err(CommandError::state)?;
    }
    output_reports(std::slice::from_ref(&report), format).map_err(CommandError::invocation)?;
    Ok(report.exit.code)
}

fn update_report_delivery_state(
    report: &mut RunReport,
    notification: &sentinel_core::NotificationReport,
) {
    let state = match notification.status {
        NotificationStatus::Delivered if notification.transition == TransitionKind::Alert => {
            Some(AlertDeliveryState::Delivered)
        }
        NotificationStatus::Delivered => Some(AlertDeliveryState::Resolved),
        NotificationStatus::Failed => Some(AlertDeliveryState::Failed),
        NotificationStatus::Unknown => Some(AlertDeliveryState::Unknown),
        NotificationStatus::Pending
        | NotificationStatus::Suppressed
        | NotificationStatus::Retryable
        | NotificationStatus::Cancelled => None,
    };
    if let Some(state) = state {
        for condition_id in &notification.condition_ids {
            if let Some(evaluation) = report
                .evaluations
                .iter_mut()
                .find(|evaluation| evaluation.id == *condition_id)
            {
                evaluation.notification_state = state;
            }
            if let Some(finding) = report
                .findings
                .iter_mut()
                .find(|finding| finding.id == *condition_id)
            {
                finding.notification_state = state;
            }
        }
    }
}

fn report(
    state: &Path,
    format: OutputFormat,
    limit: usize,
    since: Option<&str>,
) -> Result<u8, CommandError> {
    if limit == 0 || limit > 10_000 {
        return Err(CommandError::invocation(anyhow!(
            "report limit must be between 1 and 10000"
        )));
    }
    if let Some(value) = since {
        value.parse::<Timestamp>().map_err(|error| {
            CommandError::invocation(anyhow!("invalid --since timestamp: {error}"))
        })?;
    }
    if format == OutputFormat::Json && limit != 1 {
        return Err(CommandError::invocation(anyhow!(
            "--format json requires --limit 1; use jsonl for multiple reports"
        )));
    }
    let store = StateStore::open_existing(state).map_err(CommandError::state)?;
    let reports = store
        .load_reports(limit, since)
        .map_err(CommandError::state)?;
    if reports.is_empty() {
        return Err(CommandError::invocation(anyhow!(
            "state contains no matching runs"
        )));
    }
    output_reports(&reports, format).map_err(CommandError::invocation)?;
    Ok(0)
}

fn migrate_state(
    state: &Path,
    legacy_json: Option<&Path>,
    config_path: Option<&Path>,
) -> Result<u8, CommandError> {
    if let Some(source) = legacy_json {
        let config_path = config_path.ok_or_else(|| {
            CommandError::invocation(anyhow!("--config is required with --legacy-json"))
        })?;
        let config = Config::load(config_path, false).map_err(CommandError::invocation)?;
        let summary =
            StateStore::import_legacy_json(source, state, &config, &Timestamp::now().to_string())
                .map_err(CommandError::state)?;
        println!(
            "imported legacy state: samples={} conditions={} auth_cooldowns={} latest_targets={} source={}",
            summary.samples,
            summary.conditions,
            summary.auth_cooldowns,
            summary.latest_targets,
            summary.source_sha256
        );
    } else {
        let store = StateStore::open(state).map_err(CommandError::state)?;
        println!(
            "state schema is current (version {})",
            store.schema_version()
        );
    }
    Ok(0)
}

fn print_schema(kind: SchemaKind, version: u32) -> Result<u8, CommandError> {
    if version != 1 {
        return Err(CommandError::invocation(anyhow!(
            "only schema version 1 is available"
        )));
    }
    match kind {
        SchemaKind::Config => {
            let schema = versioned_schema(
                schema_for!(Config),
                "urn:adguard-sentinel:schema:config:v1",
                false,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).map_err(CommandError::invocation)?
            );
        }
        SchemaKind::RunReport => {
            let schema = versioned_schema(
                schema_for!(RunReport),
                "urn:adguard-sentinel:schema:run-report:v1",
                true,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).map_err(CommandError::invocation)?
            );
        }
        SchemaKind::State => print!("{}", canonical_state_schema()),
    }
    Ok(0)
}

fn versioned_schema<T: serde::Serialize>(
    schema: T,
    identifier: &str,
    include_state_version: bool,
) -> Result<serde_json::Value, CommandError> {
    let mut value = serde_json::to_value(schema).map_err(CommandError::invocation)?;
    let root = value.as_object_mut().ok_or_else(|| {
        CommandError::invocation(anyhow!("generated schema root is not an object"))
    })?;
    root.insert(
        "$id".to_owned(),
        serde_json::Value::String(identifier.to_owned()),
    );
    let properties = root
        .get_mut("properties")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| CommandError::invocation(anyhow!("generated schema has no properties")))?;
    properties.insert(
        "schema_version".to_owned(),
        serde_json::json!({ "const": 1 }),
    );
    if include_state_version {
        properties.insert(
            "state_schema_version".to_owned(),
            serde_json::json!({ "const": 1 }),
        );
    }
    Ok(value)
}

fn read_target_passwords(config: &Config) -> anyhow::Result<BTreeMap<String, SecretString>> {
    let mut passwords = BTreeMap::new();
    for target in &config.targets {
        let metadata = fs::metadata(&target.password_file)
            .with_context(|| format!("cannot inspect password file for target {}", target.id))?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(anyhow!(
                "password file for target {} is not a nonempty regular file",
                target.id
            ));
        }
        let password = fs::read_to_string(&target.password_file)
            .with_context(|| format!("cannot read password file for target {}", target.id))?
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        if password.is_empty() {
            return Err(anyhow!("password file for target {} is empty", target.id));
        }
        passwords.insert(target.id.clone(), SecretString::from(password));
    }
    Ok(passwords)
}

fn incomplete_report(target: &sentinel_core::TargetConfig, error: &AdGuardError) -> TargetReport {
    TargetReport::incomplete(
        target.id.clone(),
        target.name.clone(),
        error.target_status(),
        error.kind(),
        error.to_string(),
    )
}

fn baseline_profile(config: &Config) -> anyhow::Result<&sentinel_core::ConditionProfile> {
    let first = config
        .behavioral_baseline
        .target_ids
        .first()
        .ok_or_else(|| anyhow!("behavioral target group is empty"))?;
    let target = config
        .targets
        .iter()
        .find(|target| &target.id == first)
        .ok_or_else(|| anyhow!("behavioral target is not configured"))?;
    config
        .condition_profiles
        .get(&target.condition_profile)
        .ok_or_else(|| anyhow!("behavioral target condition profile is missing"))
}

fn output_reports(reports: &[RunReport], format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&reports[0])?);
        }
        OutputFormat::Jsonl => {
            for report in reports {
                println!("{}", serde_json::to_string(report)?);
            }
        }
        OutputFormat::Human => {
            for (index, report) in reports.iter().enumerate() {
                if index > 0 {
                    println!();
                }
                println!(
                    "run={} completed={} status={:?} complete_targets={}/{} exit={}",
                    report.run_id,
                    report.completed_at,
                    report.run_status,
                    report.complete_targets,
                    report.expected_targets,
                    report.exit.code
                );
                for target in &report.targets {
                    if let Some(observation) = &target.operational {
                        println!(
                            "{}: queries={} blocked={:.1}% processing={:.0}ms upstream_max={:.0}ms",
                            target.name,
                            observation.queries,
                            observation.blocked_ratio * 100.0,
                            observation.average_processing_seconds * 1_000.0,
                            observation.maximum_upstream_seconds * 1_000.0
                        );
                    } else {
                        println!(
                            "{}: incomplete ({})",
                            target.name,
                            target.error_kind.as_deref().unwrap_or("unknown")
                        );
                    }
                }
                if let Some(aggregate) = &report.aggregate {
                    println!(
                        "behavioral baseline: {} (age={}s same_hour_samples={})",
                        if aggregate.baseline_ready {
                            "active"
                        } else {
                            "learning"
                        },
                        aggregate.baseline_age_seconds,
                        aggregate.same_hour_samples
                    );
                }
                for finding in &report.findings {
                    println!(
                        "finding [{:?}/{:?}]: {}",
                        finding.severity, finding.lifecycle, finding.summary
                    );
                }
            }
        }
    }
    Ok(())
}

impl FailOn {
    fn matches(self, severity: Severity) -> bool {
        match self {
            Self::Never => false,
            Self::Warning => true,
            Self::Error => severity >= Severity::Error,
            Self::Critical => severity >= Severity::Critical,
        }
    }
}

fn exit_reason(code: u8) -> &'static str {
    match code {
        0 => "observation completed",
        1 => "finding met fail-on threshold",
        2 => "invocation or configuration error",
        3 => "minimum complete target count was not met",
        4 => "notification delivery was not confirmed",
        5 => "state persistence failed",
        _ => "reserved exit code",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use httpmock::Method::GET;
    use httpmock::MockServer;
    use jiff::Timestamp;
    use sentinel_core::FixedClock;
    use sentinel_store::StateStore;
    use tempfile::tempdir;

    use super::{FailOn, OutputFormat, check};

    #[tokio::test]
    async fn dry_run_never_loads_missing_pushover_credentials() {
        let server = MockServer::start_async().await;
        let fixtures = [
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
        let mut mocks = Vec::new();
        for (path, body) in fixtures {
            mocks.push(
                server
                    .mock_async(|when, then| {
                        when.method(GET).path(path);
                        then.status(200)
                            .header("content-type", "application/json")
                            .body(body);
                    })
                    .await,
            );
        }
        let directory = tempdir().expect("tempdir");
        let password = directory.path().join("password");
        fs::write(&password, "synthetic\n").expect("password");
        let state = directory.path().join("state.sqlite");
        let config_path = directory.path().join("config.toml");
        fs::write(
            &config_path,
            format!(
                r#"schema_version = 1
[state]
path = "{}"
retention_days = 21
[observation]
request_timeout_ms = 5000
notification_timeout_ms = 15000
max_response_bytes = 4194304
stats_lookback_ms = 3600000
target_concurrency = 1
minimum_complete_targets = 1
adguard_version_requirement = ">=0.107.78,<0.108.0"
[behavioral_baseline]
target_ids = ["resolver-a"]
time_zone = "Europe/Amsterdam"
learning_days = 7
minimum_same_hour_samples = 36
[condition_profiles.current]
authentication_rejected_sustain_runs = 1
api_unavailable_sustain_runs = 4
invalid_response_sustain_runs = 1
unsupported_version_sustain_runs = 1
protection_disabled_sustain_runs = 2
processing_latency_sustain_runs = 4
upstream_latency_sustain_runs = 4
policy_drift_sustain_runs = 4
behavioral_anomaly_sustain_runs = 4
recovery_runs = 1
authentication_retry_seconds = 900
processing_latency_ms = 500
upstream_latency_ms = 750
[notifications]
provider = "pushover"
[notifications.pushover]
application_token_file = "/missing/application-token"
user_key_file = "/missing/user-key"
[policies.test]
protection_enabled = true
upstream_mode = "load_balance"
upstream_dns = ["tls://resolver.invalid"]
filters = []
[policies.test.rewrites]
enabled = true
required = []
[[targets]]
id = "resolver-a"
name = "Resolver A"
base_url = "{}"
username = "admin"
password_file = "{}"
policy = "test"
condition_profile = "current"
allow_insecure_local_http = false
"#,
                state.display(),
                server.base_url(),
                password.display(),
            ),
        )
        .expect("config");
        let timestamp: Timestamp = "2026-08-17T12:00:00Z".parse().expect("timestamp");
        let code = check(
            &config_path,
            true,
            OutputFormat::Json,
            FailOn::Never,
            &FixedClock::new(timestamp),
        )
        .await
        .expect("dry run");
        assert_eq!(code, 0);
        let store = StateStore::open_existing(&state).expect("state");
        assert_eq!(store.load_reports(1, None).expect("report").len(), 1);
        drop(store);
        let earlier: Timestamp = "2026-08-17T11:59:59Z".parse().expect("timestamp");
        let error = check(
            &config_path,
            true,
            OutputFormat::Json,
            FailOn::Never,
            &FixedClock::new(earlier),
        )
        .await
        .expect_err("regressed wall clock must fail before observation");
        assert_eq!(error.code, 5);
        for mock in mocks {
            mock.assert_async().await;
        }
    }
}
