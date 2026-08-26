use std::collections::BTreeMap;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const REPORT_SCHEMA_VERSION: u32 = 1;
pub const STATE_SCHEMA_VERSION: u32 = 1;

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warning,
    Error,
    Critical,
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            "critical" => Ok(Self::Critical),
            _ => Err(format!("unsupported severity {value:?}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Live,
    DryRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Complete,
    Partial,
    Unhealthy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    Complete,
    AuthenticationRejected,
    AuthenticationCooldown,
    Unavailable,
    InvalidResponse,
    UnsupportedVersion,
    ResponseTooLarge,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalObservation {
    pub protection_enabled: bool,
    pub queries: u64,
    pub blocked: u64,
    pub blocked_ratio: f64,
    pub average_processing_seconds: f64,
    pub maximum_upstream_seconds: f64,
    pub top_client_share: f64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsObservation {
    pub upstream_mode: String,
    pub upstream_dns: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamObservation {
    pub identity: String,
    pub average_seconds: f64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilterObservation {
    pub url: String,
    pub server_id: i64,
    pub enabled: bool,
    pub rules_count: u64,
    pub last_updated: Option<String>,
    pub last_updated_unix_seconds: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RewriteObservation {
    pub domain: String,
    pub answer: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetReport {
    pub id: String,
    pub name: String,
    pub status: TargetStatus,
    pub complete: bool,
    pub server_version: Option<String>,
    pub operational: Option<OperationalObservation>,
    pub dns: Option<DnsObservation>,
    pub filtering_enabled: Option<bool>,
    pub rewrites_enabled: Option<bool>,
    pub upstreams: Vec<UpstreamObservation>,
    pub filters: Vec<FilterObservation>,
    pub rewrites: Vec<RewriteObservation>,
    pub error_kind: Option<String>,
    pub error_detail: Option<String>,
}

impl TargetReport {
    pub fn incomplete(
        id: impl Into<String>,
        name: impl Into<String>,
        status: TargetStatus,
        error_kind: impl Into<String>,
        error_detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            status,
            complete: false,
            server_version: None,
            operational: None,
            dns: None,
            filtering_enabled: None,
            rewrites_enabled: None,
            upstreams: Vec::new(),
            filters: Vec::new(),
            rewrites: Vec::new(),
            error_kind: Some(error_kind.into()),
            error_detail: Some(error_detail.into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineSample {
    pub timestamp: i64,
    pub local_hour: u8,
    pub combined_queries: u64,
    pub combined_blocked_ratio: f64,
}

/// One persisted per-target statistics reading.
///
/// Like `BaselineSample` this holds the raw cumulative counter that `AdGuard`
/// Home reported, not a rate. Rates are derived on read by differencing
/// consecutive readings; see ADR 0012.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetSample {
    pub target_id: String,
    pub timestamp: i64,
    pub queries: u64,
    pub blocked_ratio: f64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateObservation {
    pub local_hour: u8,
    pub utc_offset_minutes: i32,
    pub combined_queries: u64,
    pub combined_blocked_ratio: f64,
    pub baseline_age_seconds: i64,
    pub same_hour_samples: usize,
    pub baseline_ready: bool,
    pub volume_limit: Option<f64>,
    pub ratio_limit: Option<f64>,
    pub resolver_query_share: BTreeMap<String, f64>,
    pub top_client_share: BTreeMap<String, f64>,
}

/// Reports persisted by 0.1.0 carry no `reason`, so one is supplied rather than
/// failing the read. Never produced by an evaluation.
fn unrecorded_reason() -> String {
    "unrecorded".to_owned()
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationOutcome {
    Active,
    Clear,
    NotEvaluated,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionEvaluation {
    pub id: String,
    pub target_id: Option<String>,
    /// What was checked. Stable for a given `id` across runs and outcomes, so a
    /// consumer can group by it.
    pub kind: String,
    /// What the check found this time. Varies with `outcome`, and is where the
    /// specific divergence lives. Absent from reports persisted by 0.1.0, which
    /// read back as `unrecorded`.
    #[serde(default = "unrecorded_reason")]
    pub reason: String,
    pub severity: Severity,
    pub outcome: EvaluationOutcome,
    /// Human sentence chosen from `outcome`: a clear row reads as the pass, an
    /// active row reads as the failure.
    pub summary: String,
    pub expected: Value,
    pub observed: Value,
    pub evidence_source: String,
    pub observation_complete: bool,
    pub sustain_runs: u32,
    pub recovery_runs: u32,
    /// Consecutive active runs, counted toward `sustain_runs`. Persisted in the
    /// `active_count` column, whose name the versioned state schema pins.
    #[serde(alias = "active_count")]
    pub consecutive_active: u32,
    /// Consecutive clear runs, counted toward `recovery_runs`. Persisted in the
    /// `clear_count` column, whose name the versioned state schema pins.
    #[serde(alias = "clear_count")]
    pub consecutive_clear: u32,
    pub lifecycle: ConditionLifecycle,
    pub notification_state: AlertDeliveryState,
    pub first_observed_at: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionLifecycle {
    Clear,
    Pending,
    Firing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertDeliveryState {
    Never,
    Pending,
    Delivered,
    Suppressed,
    Failed,
    Unknown,
    Resolved,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionState {
    pub id: String,
    pub target_id: Option<String>,
    pub kind: String,
    pub severity: Severity,
    pub lifecycle: ConditionLifecycle,
    pub first_observed_at: Option<String>,
    pub last_observed_at: Option<String>,
    pub consecutive_active: u32,
    pub consecutive_clear: u32,
    pub alert_delivery_state: AlertDeliveryState,
    pub last_transition_run: Option<String>,
}

impl ConditionState {
    pub fn from_evaluation(evaluation: &ConditionEvaluation) -> Self {
        Self {
            id: evaluation.id.clone(),
            target_id: evaluation.target_id.clone(),
            kind: evaluation.kind.clone(),
            severity: evaluation.severity,
            lifecycle: ConditionLifecycle::Clear,
            first_observed_at: None,
            last_observed_at: None,
            consecutive_active: 0,
            consecutive_clear: 0,
            alert_delivery_state: AlertDeliveryState::Never,
            last_transition_run: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub target_id: Option<String>,
    /// What was checked. Stable for a given `id`; see `ConditionEvaluation`.
    pub kind: String,
    /// Why this finding is active. See `ConditionEvaluation::reason`.
    #[serde(default = "unrecorded_reason")]
    pub reason: String,
    pub severity: Severity,
    pub lifecycle: ConditionLifecycle,
    pub first_observed_at: Option<String>,
    pub consecutive_active: u32,
    pub consecutive_clear: u32,
    pub notification_state: AlertDeliveryState,
    pub summary: String,
    pub expected: Value,
    pub observed: Value,
    pub evidence_source: String,
    pub observation_complete: bool,
}

impl From<&ConditionEvaluation> for Finding {
    fn from(evaluation: &ConditionEvaluation) -> Self {
        Self {
            id: evaluation.id.clone(),
            target_id: evaluation.target_id.clone(),
            kind: evaluation.kind.clone(),
            reason: evaluation.reason.clone(),
            severity: evaluation.severity,
            lifecycle: evaluation.lifecycle,
            first_observed_at: evaluation.first_observed_at.clone(),
            consecutive_active: evaluation.consecutive_active,
            consecutive_clear: evaluation.consecutive_clear,
            notification_state: evaluation.notification_state,
            summary: evaluation.summary.clone(),
            expected: evaluation.expected.clone(),
            observed: evaluation.observed.clone(),
            evidence_source: evaluation.evidence_source.clone(),
            observation_complete: evaluation.observation_complete,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    Alert,
    Resolution,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionTransition {
    pub condition_id: String,
    pub kind: TransitionKind,
    pub summary: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationStatus {
    Pending,
    Suppressed,
    Delivered,
    Retryable,
    Failed,
    Unknown,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationReport {
    pub id: String,
    pub transition: TransitionKind,
    pub condition_ids: Vec<String>,
    pub status: NotificationStatus,
    pub remote_request_id: Option<String>,
    pub error_class: Option<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunHealth {
    pub minimum_complete_targets: usize,
    pub complete_targets: usize,
    pub met: bool,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExitReport {
    pub code: u8,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunReport {
    pub schema_version: u32,
    pub run_id: String,
    pub mode: RunMode,
    pub started_at: String,
    pub completed_at: String,
    pub config_sha256: String,
    pub state_schema_version: u32,
    pub run_status: RunStatus,
    pub expected_targets: usize,
    pub complete_targets: usize,
    pub minimum_complete_targets: usize,
    pub targets: Vec<TargetReport>,
    pub aggregate: Option<AggregateObservation>,
    pub evaluations: Vec<ConditionEvaluation>,
    pub findings: Vec<Finding>,
    pub transitions: Vec<ConditionTransition>,
    pub notifications: Vec<NotificationReport>,
    pub health: RunHealth,
    pub exit: ExitReport,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRuntimeState {
    pub target_id: String,
    pub auth_failed_at: Option<i64>,
    pub auth_retry_after: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct OutboxMessage {
    pub id: String,
    pub run_id: String,
    pub transition: TransitionKind,
    pub title: String,
    pub message: String,
    pub priority: i8,
    pub status: NotificationStatus,
    pub condition_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::{ConditionEvaluation, EvaluationOutcome};

    /// A 0.1.0 state database stores each evaluation as serialised JSON and
    /// `report` reads it back, so a 0.1.1 binary meeting 0.1.0 rows must not
    /// fail the read. The counters arrive under their old names and `reason` is
    /// absent entirely.
    #[test]
    fn an_evaluation_persisted_by_0_1_0_still_reads() {
        let persisted = r#"{
            "id": "target:maxwell:filter:8d676d2e2236732b",
            "target_id": "maxwell",
            "kind": "required_filter_stale",
            "severity": "warning",
            "outcome": "clear",
            "summary": "Maxwell has a stale required filter",
            "expected": { "enabled": true, "maximum_age_hours": 72 },
            "observed": { "enabled": true },
            "evidence_source": "GET /control/filtering/status filters",
            "observation_complete": true,
            "sustain_runs": 4,
            "recovery_runs": 1,
            "active_count": 0,
            "clear_count": 3,
            "lifecycle": "clear",
            "notification_state": "never",
            "first_observed_at": null
        }"#;

        let evaluation: ConditionEvaluation =
            serde_json::from_str(persisted).expect("a 0.1.0 evaluation must still deserialize");

        assert_eq!(evaluation.consecutive_active, 0);
        assert_eq!(evaluation.consecutive_clear, 3);
        assert_eq!(evaluation.reason, "unrecorded");
        assert_eq!(evaluation.outcome, EvaluationOutcome::Clear);
        // History is reported as it was recorded, not retrospectively corrected.
        assert_eq!(evaluation.kind, "required_filter_stale");
        assert_eq!(evaluation.summary, "Maxwell has a stale required filter");
    }

    /// The new names are what a 0.1.1 report writes, so they must round-trip too.
    #[test]
    fn an_evaluation_round_trips_through_its_current_names() {
        let persisted = r#"{
            "id": "target:maxwell:filter:8d676d2e2236732b",
            "target_id": "maxwell",
            "kind": "required_filter",
            "reason": "matches_policy",
            "severity": "warning",
            "outcome": "clear",
            "summary": "Maxwell required filter matches declared policy",
            "expected": {},
            "observed": {},
            "evidence_source": "GET /control/filtering/status filters",
            "observation_complete": true,
            "sustain_runs": 4,
            "recovery_runs": 1,
            "consecutive_active": 0,
            "consecutive_clear": 3,
            "lifecycle": "clear",
            "notification_state": "never",
            "first_observed_at": null
        }"#;

        let evaluation: ConditionEvaluation =
            serde_json::from_str(persisted).expect("current shape");
        let encoded = serde_json::to_string(&evaluation).expect("encode");
        let again: ConditionEvaluation = serde_json::from_str(&encoded).expect("round trip");

        assert_eq!(again.reason, "matches_policy");
        assert_eq!(again.consecutive_clear, 3);
    }
}
