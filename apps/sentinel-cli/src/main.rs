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
        Command::MigrateState { state } => migrate_state(&state),
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
    check_with_sink(config_path, dry_run, format, fail_on, clock, None).await
}

async fn check_with_sink(
    config_path: &Path,
    dry_run: bool,
    format: OutputFormat,
    fail_on: FailOn,
    clock: &dyn Clock,
    sink: Option<PushoverClient>,
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
            let pushover = match sink {
                Some(sink) => sink,
                None => PushoverClient::from_config(&config).map_err(CommandError::invocation)?,
            };
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

fn migrate_state(state: &Path) -> Result<u8, CommandError> {
    let store = StateStore::open(state).map_err(CommandError::state)?;
    println!(
        "state schema is current (version {})",
        store.schema_version()
    );
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
    use std::path::PathBuf;

    use httpmock::Method::{GET, POST};
    use httpmock::{Mock, MockServer};
    use jiff::Timestamp;
    use sentinel_core::{Config, FixedClock, NotificationStatus, RunReport, RunStatus};
    use sentinel_store::StateStore;
    use tempfile::{TempDir, tempdir};

    use super::{
        CommandError, FailOn, OutputFormat, PushoverClient, SchemaKind, check, check_with_sink,
        print_schema, report,
    };

    const REFERENCE_INSTANT: &str = "2027-01-15T08:00:00Z";
    const DECLARED_MODE: &str = "load_balance";
    const DRIFTED_MODE: &str = "parallel";

    const ADGUARD_PASSWORD: &str = "adguard-password-must-not-leak";
    const PUSHOVER_TOKEN: &str = "pushover-token-must-not-leak";
    const PUSHOVER_USER_KEY: &str = "pushover-user-key-must-not-leak";

    const DNS_INFO_PARALLEL: &str =
        include_str!("../../../testdata/api/dns-info-parallel-mode.json");

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

    #[derive(Clone, Copy)]
    enum Notifications {
        Disabled,
        Pushover,
        PushoverWithAbsentSecrets,
    }

    struct Harness {
        _directory: TempDir,
        config_path: PathBuf,
        state: PathBuf,
    }

    async fn serve<'server>(
        server: &'server MockServer,
        bodies: &[(&'static str, &'static str)],
    ) -> Vec<Mock<'server>> {
        let mut mocks = Vec::with_capacity(bodies.len());
        for (path, body) in bodies.iter().copied() {
            mocks.push(
                server
                    .mock_async(move |when, then| {
                        when.method(GET).path(path);
                        then.status(200)
                            .header("content-type", "application/json")
                            .body(body);
                    })
                    .await,
            );
        }
        mocks
    }

    async fn serve_golden(server: &MockServer) -> Vec<Mock<'_>> {
        serve(server, &GOLDEN).await
    }

    async fn serve_golden_replacing<'server>(
        server: &'server MockServer,
        path: &str,
        body: &'static str,
    ) -> Vec<Mock<'server>> {
        let mut bodies = GOLDEN;
        for entry in &mut bodies {
            if entry.0 == path {
                entry.1 = body;
            }
        }
        serve(server, &bodies).await
    }

    fn harness(
        base_url: &str,
        upstream_mode: &str,
        drift_sustain: u32,
        notifications: Notifications,
    ) -> Harness {
        let directory = tempdir().expect("tempdir");
        let password = directory.path().join("password");
        fs::write(&password, format!("{ADGUARD_PASSWORD}\n")).expect("password");
        let token = directory.path().join("pushover-token");
        let user = directory.path().join("pushover-user");
        fs::write(&token, format!("{PUSHOVER_TOKEN}\n")).expect("token");
        fs::write(&user, format!("{PUSHOVER_USER_KEY}\n")).expect("user");
        let notifications = match notifications {
            Notifications::Disabled => "[notifications]\nprovider = \"disabled\"".to_owned(),
            Notifications::Pushover => pushover_block(&token, &user),
            Notifications::PushoverWithAbsentSecrets => pushover_block(
                &PathBuf::from("/missing/application-token"),
                &PathBuf::from("/missing/user-key"),
            ),
        };
        let state = directory.path().join("state.sqlite");
        let config_path = directory.path().join("config.toml");
        fs::write(
            &config_path,
            format!(
                r#"schema_version = 1
[state]
path = "{state}"
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
api_unavailable_sustain_runs = 1
invalid_response_sustain_runs = 1
unsupported_version_sustain_runs = 1
protection_disabled_sustain_runs = 2
processing_latency_sustain_runs = 4
upstream_latency_sustain_runs = 4
policy_drift_sustain_runs = {drift_sustain}
behavioral_anomaly_sustain_runs = 4
recovery_runs = 1
authentication_retry_seconds = 900
processing_latency_ms = 500
upstream_latency_ms = 750
{notifications}
[policies.test]
protection_enabled = true
upstream_mode = "{upstream_mode}"
upstream_dns = [
  "quic://dns10.quad9.net",
  "tls://unfiltered.adguard-dns.com",
  "https://cloudflare-dns.com/dns-query",
]
filters = []
[policies.test.rewrites]
enabled = true
required = []
[[targets]]
id = "resolver-a"
name = "Resolver A"
base_url = "{base_url}"
username = "admin"
password_file = "{password}"
policy = "test"
condition_profile = "current"
allow_insecure_local_http = false
"#,
                state = state.display(),
                password = password.display(),
            ),
        )
        .expect("config");
        Harness {
            _directory: directory,
            config_path,
            state,
        }
    }

    fn pushover_block(token: &std::path::Path, user: &std::path::Path) -> String {
        format!(
            "[notifications]\nprovider = \"pushover\"\n[notifications.pushover]\napplication_token_file = \"{}\"\nuser_key_file = \"{}\"",
            token.display(),
            user.display()
        )
    }

    fn at(instant: &str) -> FixedClock {
        FixedClock::new(instant.parse::<Timestamp>().expect("timestamp"))
    }

    async fn run(harness: &Harness, fail_on: FailOn) -> Result<u8, CommandError> {
        check(
            &harness.config_path,
            false,
            OutputFormat::Json,
            fail_on,
            &at(REFERENCE_INSTANT),
        )
        .await
    }

    async fn run_notifying(
        harness: &Harness,
        pushover: &MockServer,
        instant: &str,
    ) -> Result<u8, CommandError> {
        let config = Config::load(&harness.config_path, false).expect("config");
        let sink =
            PushoverClient::with_endpoint(&config, &pushover.base_url()).expect("pushover client");
        check_with_sink(
            &harness.config_path,
            false,
            OutputFormat::Json,
            FailOn::Never,
            &at(instant),
            Some(sink),
        )
        .await
    }

    fn latest_report(harness: &Harness) -> RunReport {
        let store = StateStore::open_existing(&harness.state).expect("state");
        store
            .load_reports(1, None)
            .expect("reports")
            .into_iter()
            .next()
            .expect("one persisted report")
    }

    #[tokio::test]
    async fn a_healthy_run_exits_zero_without_findings() {
        let server = MockServer::start_async().await;
        let mocks = serve_golden(&server).await;
        let harness = harness(
            &server.base_url(),
            DECLARED_MODE,
            1,
            Notifications::Disabled,
        );

        let code = run(&harness, FailOn::Never).await.expect("healthy run");

        assert_eq!(code, 0);
        let report = latest_report(&harness);
        assert_eq!(report.run_status, RunStatus::Complete);
        assert_eq!(report.complete_targets, 1);
        assert!(
            report.findings.is_empty(),
            "findings: {:?}",
            report.findings
        );
        assert!(report.transitions.is_empty());
        assert!(report.health.met);
        assert_eq!(report.exit.reason, "observation completed");
        for mock in mocks {
            mock.assert_calls_async(1).await;
        }
    }

    #[tokio::test]
    async fn an_active_finding_exits_one_only_when_fail_on_matches() {
        let server = MockServer::start_async().await;
        let _mocks = serve_golden(&server).await;
        let harness = harness(&server.base_url(), DRIFTED_MODE, 1, Notifications::Disabled);

        let ignored = run(&harness, FailOn::Never).await.expect("run");
        assert_eq!(ignored, 0);

        let escalated = run(&harness, FailOn::Warning).await.expect("run");
        assert_eq!(escalated, 1);

        let report = latest_report(&harness);
        assert_eq!(report.exit.code, 1);
        assert_eq!(report.exit.reason, "finding met fail-on threshold");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == "upstream_mode_drift")
        );

        let above_threshold = run(&harness, FailOn::Error).await.expect("run");
        assert_eq!(above_threshold, 0);
    }

    #[tokio::test]
    async fn an_unreachable_target_exits_three() {
        let harness = harness(
            "http://127.0.0.1:1",
            DECLARED_MODE,
            1,
            Notifications::Disabled,
        );

        let code = run(&harness, FailOn::Never).await.expect("run");

        assert_eq!(code, 3);
        let report = latest_report(&harness);
        assert_eq!(report.run_status, RunStatus::Unhealthy);
        assert_eq!(report.complete_targets, 0);
        assert!(!report.health.met);
        assert_eq!(
            report.exit.reason,
            "minimum complete target count was not met"
        );
    }

    #[tokio::test]
    async fn an_invalid_configuration_exits_two() {
        let directory = tempdir().expect("tempdir");
        let config_path = directory.path().join("config.toml");
        fs::write(&config_path, "schema_version = 1\nnot valid toml").expect("config");

        let error = check(
            &config_path,
            false,
            OutputFormat::Json,
            FailOn::Never,
            &at(REFERENCE_INSTANT),
        )
        .await
        .expect_err("an invalid configuration must fail");

        assert_eq!(error.code, 2);
    }

    #[tokio::test]
    async fn a_regressed_wall_clock_exits_five_without_advancing_state() {
        let server = MockServer::start_async().await;
        let _mocks = serve_golden(&server).await;
        let harness = harness(
            &server.base_url(),
            DECLARED_MODE,
            1,
            Notifications::Disabled,
        );

        assert_eq!(run(&harness, FailOn::Never).await.expect("first run"), 0);

        let error = check(
            &harness.config_path,
            false,
            OutputFormat::Json,
            FailOn::Never,
            &at("2027-01-15T07:59:59Z"),
        )
        .await
        .expect_err("a regressed wall clock must fail");

        assert_eq!(error.code, 5);
        let store = StateStore::open_existing(&harness.state).expect("state");
        assert_eq!(store.load_reports(10, None).expect("reports").len(), 1);
    }

    #[tokio::test]
    async fn dry_run_never_loads_absent_pushover_credentials() {
        let server = MockServer::start_async().await;
        let mocks = serve_golden(&server).await;
        let harness = harness(
            &server.base_url(),
            DECLARED_MODE,
            1,
            Notifications::PushoverWithAbsentSecrets,
        );

        let code = check(
            &harness.config_path,
            true,
            OutputFormat::Json,
            FailOn::Never,
            &at(REFERENCE_INSTANT),
        )
        .await
        .expect("dry run");

        assert_eq!(code, 0);
        assert_eq!(latest_report(&harness).mode, sentinel_core::RunMode::DryRun);
        for mock in mocks {
            mock.assert_calls_async(1).await;
        }
    }

    #[tokio::test]
    async fn a_confirmed_delivery_records_the_remote_request_id() {
        let server = MockServer::start_async().await;
        let _mocks = serve_golden(&server).await;
        let pushover = MockServer::start_async().await;
        let delivery = pushover
            .mock_async(|when, then| {
                when.method(POST).path("/");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(r#"{"status":1,"request":"synthetic-request-id"}"#);
            })
            .await;
        let harness = harness(&server.base_url(), DRIFTED_MODE, 1, Notifications::Pushover);

        let code = run_notifying(&harness, &pushover, REFERENCE_INSTANT)
            .await
            .expect("run");

        assert_eq!(code, 0);
        let report = latest_report(&harness);
        assert_eq!(report.notifications.len(), 1);
        assert_eq!(
            report.notifications[0].status,
            NotificationStatus::Delivered
        );
        assert_eq!(
            report.notifications[0].remote_request_id.as_deref(),
            Some("synthetic-request-id")
        );
        delivery.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn a_retryable_delivery_exits_four() {
        let server = MockServer::start_async().await;
        let _mocks = serve_golden(&server).await;
        let pushover = MockServer::start_async().await;
        let rejected = pushover
            .mock_async(|when, then| {
                when.method(POST).path("/");
                then.status(503);
            })
            .await;
        let harness = harness(&server.base_url(), DRIFTED_MODE, 1, Notifications::Pushover);

        let code = run_notifying(&harness, &pushover, REFERENCE_INSTANT)
            .await
            .expect("run");

        assert_eq!(code, 4);
        let report = latest_report(&harness);
        assert_eq!(
            report.exit.reason,
            "notification delivery was not confirmed"
        );
        assert_eq!(
            report.notifications[0].status,
            NotificationStatus::Retryable
        );
        rejected.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn an_ambiguous_delivery_exits_four_and_is_never_resent() {
        let server = MockServer::start_async().await;
        let _mocks = serve_golden(&server).await;
        let pushover = MockServer::start_async().await;
        let ambiguous = pushover
            .mock_async(|when, then| {
                when.method(POST).path("/");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(r#"{"status":1,"request":""}"#);
            })
            .await;
        let harness = harness(&server.base_url(), DRIFTED_MODE, 1, Notifications::Pushover);

        let first = run_notifying(&harness, &pushover, REFERENCE_INSTANT)
            .await
            .expect("first run");
        assert_eq!(first, 4);
        assert_eq!(
            latest_report(&harness).notifications[0].status,
            NotificationStatus::Unknown
        );

        let second = run_notifying(&harness, &pushover, "2027-01-15T08:05:00Z")
            .await
            .expect("second run");

        assert_eq!(second, 0);
        assert!(latest_report(&harness).notifications.is_empty());
        ambiguous.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn a_notification_carries_only_the_declared_pushover_fields() {
        let server = MockServer::start_async().await;
        let _mocks = serve_golden(&server).await;
        let pushover = MockServer::start_async().await;
        let declared = pushover
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/")
                    .form_urlencoded_tuple("token", PUSHOVER_TOKEN)
                    .form_urlencoded_tuple("user", PUSHOVER_USER_KEY)
                    .form_urlencoded_tuple("priority", "0")
                    .form_urlencoded_tuple_exists("title")
                    .form_urlencoded_tuple_exists("message");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(r#"{"status":1,"request":"synthetic-request-id"}"#);
            })
            .await;
        let harness = harness(&server.base_url(), DRIFTED_MODE, 1, Notifications::Pushover);

        let code = run_notifying(&harness, &pushover, REFERENCE_INSTANT)
            .await
            .expect("run");

        assert_eq!(code, 0);
        declared.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn an_alert_resolves_quietly_exactly_once() {
        let server = MockServer::start_async().await;
        let _drifted = serve_golden(&server).await;
        let pushover = MockServer::start_async().await;
        let alert = pushover
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/")
                    .form_urlencoded_tuple("priority", "0");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(r#"{"status":1,"request":"alert-request-id"}"#);
            })
            .await;
        let resolution = pushover
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/")
                    .form_urlencoded_tuple("priority", "-1");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(r#"{"status":1,"request":"resolution-request-id"}"#);
            })
            .await;
        let harness = harness(&server.base_url(), DRIFTED_MODE, 1, Notifications::Pushover);

        assert_eq!(
            run_notifying(&harness, &pushover, "2027-01-15T08:00:00Z")
                .await
                .expect("alert run"),
            0
        );
        alert.assert_calls_async(1).await;
        resolution.assert_calls_async(0).await;

        server.reset_async().await;
        let _recovered =
            serve_golden_replacing(&server, "/control/dns_info", DNS_INFO_PARALLEL).await;

        assert_eq!(
            run_notifying(&harness, &pushover, "2027-01-15T08:05:00Z")
                .await
                .expect("resolution run"),
            0
        );
        let resolved = latest_report(&harness);
        assert!(resolved.findings.is_empty());
        assert_eq!(resolved.transitions.len(), 1);
        assert_eq!(
            resolved.notifications[0].remote_request_id.as_deref(),
            Some("resolution-request-id")
        );

        assert_eq!(
            run_notifying(&harness, &pushover, "2027-01-15T08:10:00Z")
                .await
                .expect("steady run"),
            0
        );
        assert!(latest_report(&harness).notifications.is_empty());
        alert.assert_calls_async(1).await;
        resolution.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn credentials_never_reach_a_persisted_report() {
        let server = MockServer::start_async().await;
        let _mocks = serve_golden(&server).await;
        let pushover = MockServer::start_async().await;
        let _rejected = pushover
            .mock_async(|when, then| {
                when.method(POST).path("/");
                then.status(400)
                    .header("content-type", "application/json")
                    .body(r#"{"status":0,"request":"rejected-request-id","errors":["invalid"]}"#);
            })
            .await;
        let harness = harness(&server.base_url(), DRIFTED_MODE, 1, Notifications::Pushover);

        let code = run_notifying(&harness, &pushover, REFERENCE_INSTANT)
            .await
            .expect("run");
        assert_eq!(code, 4);

        let serialized = serde_json::to_string(&latest_report(&harness)).expect("serialize");
        for secret in [ADGUARD_PASSWORD, PUSHOVER_TOKEN, PUSHOVER_USER_KEY] {
            assert!(
                !serialized.contains(secret),
                "a persisted report leaked {secret}"
            );
        }
        assert!(!serialized.contains("Basic "));
        assert!(serialized.contains("pushover_permanent_rejection"));
    }

    #[tokio::test]
    async fn a_rejected_password_never_reaches_the_report_or_the_error() {
        let server = MockServer::start_async().await;
        let _unauthorized = server
            .mock_async(|when, then| {
                when.method(GET).path("/control/status");
                then.status(401);
            })
            .await;
        let harness = harness(
            &server.base_url(),
            DECLARED_MODE,
            1,
            Notifications::Disabled,
        );

        let code = run(&harness, FailOn::Never).await.expect("run");

        assert_eq!(code, 3);
        let report = latest_report(&harness);
        assert_eq!(
            report.targets[0].error_kind.as_deref(),
            Some("authentication_rejected")
        );
        let serialized = serde_json::to_string(&report).expect("serialize");
        assert!(!serialized.contains(ADGUARD_PASSWORD));
        assert!(!serialized.contains("Basic "));
    }

    #[tokio::test]
    async fn persisted_reports_match_the_checked_in_run_report_schema() {
        let server = MockServer::start_async().await;
        let _mocks = serve_golden(&server).await;
        let harness = harness(&server.base_url(), DRIFTED_MODE, 1, Notifications::Disabled);
        run(&harness, FailOn::Never).await.expect("run");

        let persisted = latest_report(&harness);
        let value = serde_json::to_value(&persisted).expect("serialize");
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/run-report-v1.schema.json"))
                .expect("schema");

        let object = value.as_object().expect("a report serializes to an object");
        let properties = schema["properties"]
            .as_object()
            .expect("the schema declares properties");
        for name in schema["required"]
            .as_array()
            .expect("the schema declares required properties")
        {
            let name = name.as_str().expect("a required property name");
            assert!(object.contains_key(name), "report is missing {name}");
        }
        for name in object.keys() {
            assert!(
                properties.contains_key(name),
                "report declares undeclared property {name}"
            );
        }
        assert_eq!(value["schema_version"], serde_json::json!(1));
        assert_eq!(value["state_schema_version"], serde_json::json!(1));
        assert!(!persisted.findings.is_empty());

        let round_tripped: RunReport =
            serde_json::from_value(value).expect("a report round trips through its versioned type");
        assert_eq!(round_tripped.run_id, persisted.run_id);
    }

    #[test]
    fn invocation_errors_use_exit_code_two() {
        let directory = tempdir().expect("tempdir");
        let state = directory.path().join("state.sqlite");

        assert_eq!(
            print_schema(SchemaKind::Config, 2)
                .expect_err("only version 1 exists")
                .code,
            2
        );
        assert_eq!(
            report(&state, OutputFormat::Human, 0, None)
                .expect_err("a zero limit is invalid")
                .code,
            2
        );
        assert_eq!(
            report(&state, OutputFormat::Json, 2, None)
                .expect_err("json output requires a single report")
                .code,
            2
        );
        assert_eq!(
            report(&state, OutputFormat::Human, 1, Some("not-a-timestamp"))
                .expect_err("an invalid since value is rejected")
                .code,
            2
        );
    }

    #[test]
    fn an_absent_state_database_exits_five() {
        let directory = tempdir().expect("tempdir");
        let state = directory.path().join("absent.sqlite");

        let error = report(&state, OutputFormat::Human, 1, None)
            .expect_err("an absent state database must fail");

        assert_eq!(error.code, 5);
    }

    #[test]
    fn every_documented_exit_code_has_a_distinct_reason() {
        let reasons: Vec<&str> = (0..=5).map(super::exit_reason).collect();
        assert_eq!(
            reasons,
            [
                "observation completed",
                "finding met fail-on threshold",
                "invocation or configuration error",
                "minimum complete target count was not met",
                "notification delivery was not confirmed",
                "state persistence failed",
            ]
        );
        assert_eq!(super::exit_reason(6), "reserved exit code");
    }
}
