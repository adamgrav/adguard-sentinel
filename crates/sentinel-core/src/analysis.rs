use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use jiff::tz::TimeZoneDatabase;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::{
    BehavioralBaselineConfig, ConditionProfile, PolicyConfig, TargetConfig, normalize_dns_name,
    normalize_rewrite_answer,
};
use crate::model::{
    AggregateObservation, AlertDeliveryState, ConditionEvaluation, ConditionLifecycle,
    ConditionState, ConditionTransition, EvaluationOutcome, OperationalObservation, Severity,
    TargetReport, TargetSample, TargetStatus, TransitionKind,
};

#[derive(Clone, Debug)]
pub struct AggregateEvaluation {
    pub observation: AggregateObservation,
    pub evaluations: Vec<ConditionEvaluation>,
}

pub fn local_time_bucket(timestamp: Timestamp, time_zone: &str) -> Result<(u8, i32), String> {
    let database = TimeZoneDatabase::bundled();
    let time_zone = database.get(time_zone).map_err(|error| error.to_string())?;
    let zoned = timestamp.to_zoned(time_zone);
    let hour = u8::try_from(zoned.hour()).map_err(|_| "local hour is out of range".to_owned())?;
    Ok((hour, zoned.offset().seconds() / 60))
}

/// Longest gap between two samples that still counts as one measurement
/// window. The timer fires about every five minutes; a longer gap means runs
/// were missed and the rate across it would be an average over an outage.
const RATE_WINDOW_MAXIMUM_SECONDS: f64 = 600.0;
/// Queries a window needs before its blocked ratio is worth comparing.
const RATE_WINDOW_MINIMUM_QUERIES: u64 = 100;
const QUERY_RATE_MEDIAN_MULTIPLE: f64 = 3.0;
const QUERY_RATE_DEVIATION_MULTIPLE: f64 = 4.0;
const BLOCKED_RATIO_DEVIATION_MULTIPLE: f64 = 6.0;
const BLOCKED_RATIO_MINIMUM_DEVIATION: f64 = 0.04;
const BLOCKING_COLLAPSE_FRACTION: f64 = 0.25;

/// One measurement window between two consecutive aggregate samples.
///
/// `AdGuard Home` reports statistics as a counter that resets on its own local
/// hour, so a single sample is a partial hour total and not a rate: the same
/// traffic reads as a small number just after the reset and a large one just
/// before it. Differencing consecutive samples removes that ramp and yields a
/// quantity that means the same thing wherever in the hour it was taken.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateWindow {
    pub local_hour: u8,
    pub queries: u64,
    pub elapsed_seconds: f64,
    pub query_rate: f64,
    pub blocked_ratio: f64,
}

impl RateWindow {
    /// The window blocked ratio, or `None` when too few queries landed in the
    /// window for the ratio to carry information.
    fn comparable_blocked_ratio(&self) -> Option<f64> {
        (self.queries >= RATE_WINDOW_MINIMUM_QUERIES).then_some(self.blocked_ratio)
    }
}

/// Derives the measurement window between two consecutive readings. Each tuple
/// is `(timestamp, cumulative queries, cumulative blocked)`.
///
/// Returns `None` when the pair cannot describe one: a counter that went
/// backwards means `AdGuard Home` reset its statistics between the readings and
/// the elapsed traffic is unknowable, and a gap longer than
/// `RATE_WINDOW_MAXIMUM_SECONDS` spans missed runs. Both are skipped rather
/// than estimated, because guessing the reset boundary would bias the rate in
/// a direction that depends on the resolver timezone.
///
/// Counts are differenced as integers. Reconstructing a count from a stored
/// ratio and differencing that would subtract two large nearly-equal floats to
/// recover a small one, and rounding could then present as a blocked count of
/// zero, which is indistinguishable from blocking having stopped.
fn window_between(
    previous: (i64, u64, u64),
    current: (i64, u64, u64),
    local_hour: u8,
) -> Option<RateWindow> {
    let (previous_timestamp, previous_queries, previous_blocked) = previous;
    let (current_timestamp, current_queries, current_blocked) = current;
    if current_queries < previous_queries || current_blocked < previous_blocked {
        return None;
    }
    let elapsed = (current_timestamp - previous_timestamp) as f64;
    if !elapsed.is_finite() || elapsed <= 0.0 || elapsed > RATE_WINDOW_MAXIMUM_SECONDS {
        return None;
    }
    let queries = current_queries - previous_queries;
    let blocked = current_blocked - previous_blocked;
    if blocked > queries {
        return None;
    }
    let blocked_ratio = if queries == 0 {
        0.0
    } else {
        blocked as f64 / queries as f64
    };
    Some(RateWindow {
        local_hour,
        queries,
        elapsed_seconds: elapsed,
        query_rate: queries as f64 / elapsed,
        blocked_ratio,
    })
}

/// Sums the declared group members per run into one combined reading, keeping
/// only runs where every member reported, oldest first.
///
/// The group aggregate is the sum of its members, so summing exact per-target
/// counts avoids reconstructing anything. A run missing a member is dropped
/// rather than summed over what is present, which would read as a fall in
/// traffic that never happened.
fn combined_readings(
    config: &BehavioralBaselineConfig,
    samples: &[TargetSample],
) -> Vec<(i64, u64, u64)> {
    let mut per_run: BTreeMap<&str, (BTreeSet<&str>, i64, u64, u64)> = BTreeMap::new();
    for sample in samples {
        if !config.target_ids.iter().any(|id| id == &sample.target_id) {
            continue;
        }
        let entry = per_run.entry(sample.run_id.as_str()).or_insert((
            BTreeSet::new(),
            sample.timestamp,
            0,
            0,
        ));
        // Count distinct members, so a duplicated reading cannot stand in for a
        // member that never reported.
        if entry.0.insert(sample.target_id.as_str()) {
            entry.2 = entry.2.saturating_add(sample.queries);
            entry.3 = entry.3.saturating_add(sample.blocked);
        }
    }
    let mut readings: Vec<(i64, u64, u64)> = per_run
        .into_values()
        .filter(|(members, _, _, _)| members.len() == config.target_ids.len())
        .map(|(_, timestamp, queries, blocked)| (timestamp, queries, blocked))
        .collect();
    readings.sort_by_key(|(timestamp, _, _)| *timestamp);
    readings
}

/// The local hour a timestamp falls in, or `None` if it cannot be resolved.
fn local_hour_of(timestamp: i64, time_zone: &str) -> Option<u8> {
    Timestamp::from_second(timestamp)
        .ok()
        .and_then(|value| local_time_bucket(value, time_zone).ok())
        .map(|(hour, _)| hour)
}

pub fn robust_bounds(values: &[f64]) -> Option<(f64, f64)> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let center = median(values);
    let deviations: Vec<_> = values.iter().map(|value| (value - center).abs()).collect();
    let scaled_deviation: f64 = 1.4826 * median(&deviations);
    Some((center, scaled_deviation.max(1e-9)))
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        f64::midpoint(sorted[middle - 1], sorted[middle])
    } else {
        sorted[middle]
    }
}

/// Both the failure and the available paths report the same condition id, so
/// they must report the same kind. What differed between them moves to the
/// verdict reason.
const API_CONDITION_KIND: &str = "api";

pub fn evaluate_target_failure(
    target: &TargetConfig,
    profile: &ConditionProfile,
    report: &TargetReport,
) -> Vec<ConditionEvaluation> {
    let (reason, severity, sustain, summary) = match report.status {
        TargetStatus::AuthenticationRejected | TargetStatus::AuthenticationCooldown => (
            "authentication_rejected",
            Severity::Critical,
            profile.authentication_rejected_sustain_runs,
            format!("{} API authentication failed", target.name),
        ),
        TargetStatus::UnsupportedVersion => (
            "unsupported_version",
            Severity::Error,
            profile.unsupported_version_sustain_runs,
            format!(
                "{} returned an unsupported AdGuard Home version",
                target.name
            ),
        ),
        TargetStatus::InvalidResponse | TargetStatus::ResponseTooLarge => (
            "invalid_response",
            Severity::Error,
            profile.invalid_response_sustain_runs,
            format!(
                "{} returned an incomplete or invalid API response",
                target.name
            ),
        ),
        TargetStatus::Unavailable => (
            "unavailable",
            Severity::Warning,
            profile.api_unavailable_sustain_runs,
            format!("{} AdGuard API is unavailable", target.name),
        ),
        TargetStatus::Complete => return Vec::new(),
    };
    vec![evaluation(
        format!("target:{}:api", target.id),
        Some(target.id.clone()),
        API_CONDITION_KIND,
        severity,
        Verdict::active(reason, summary),
        json!({ "complete": true }),
        json!({
            "status": report.status,
            "error_kind": report.error_kind,
            "error_detail": report.error_detail,
        }),
        "AdGuard request boundary",
        false,
        sustain,
        profile.recovery_runs,
    )]
}

pub fn evaluate_target(
    target: &TargetConfig,
    policy: Option<&PolicyConfig>,
    profile: &ConditionProfile,
    report: &TargetReport,
    now_unix_seconds: i64,
) -> Vec<ConditionEvaluation> {
    if !report.complete {
        return evaluate_target_failure(target, profile, report);
    }
    let Some(operational) = report.operational.as_ref() else {
        return evaluate_target_failure(target, profile, report);
    };
    let mut evaluations = Vec::new();
    evaluations.push(evaluation(
        format!("target:{}:api", target.id),
        Some(target.id.clone()),
        API_CONDITION_KIND,
        Severity::Warning,
        Verdict::clear(
            "available",
            format!("{} AdGuard API is available", target.name),
        ),
        json!({ "complete": true }),
        json!({ "complete": true }),
        "GET /control/status and allowlisted observations",
        true,
        profile.api_unavailable_sustain_runs,
        profile.recovery_runs,
    ));
    if let Some(protection_enabled) = policy.and_then(|policy| policy.protection_enabled) {
        // The declared value decides the outcome; `reason` keeps naming the
        // observed state, so the common `protection_enabled = true` policy
        // reports exactly as it did before.
        let verdict = match (protection_enabled, operational.protection_enabled) {
            (true, false) => Verdict::active(
                "disabled",
                format!("{} AdGuard protection is disabled", target.name),
            ),
            (false, true) => Verdict::active(
                "enabled",
                format!(
                    "{} AdGuard protection is enabled, but policy declares it disabled",
                    target.name
                ),
            ),
            (true, true) => Verdict::clear(
                "enabled",
                format!("{} AdGuard protection is enabled", target.name),
            ),
            (false, false) => Verdict::clear(
                "disabled",
                format!(
                    "{} AdGuard protection is disabled, as policy declares",
                    target.name
                ),
            ),
        };
        evaluations.push(boolean_evaluation(
            format!("target:{}:protection", target.id),
            target,
            "protection",
            Severity::Critical,
            verdict,
            protection_enabled,
            operational.protection_enabled,
            "GET /control/status protection_enabled",
            profile.protection_disabled_sustain_runs,
            profile.recovery_runs,
        ));
    }
    evaluations.push(threshold_evaluation(
        format!("target:{}:processing-latency", target.id),
        target,
        "processing_latency",
        operational.average_processing_seconds,
        profile.processing_latency_ms as f64 / 1_000.0,
        format!("{} DNS processing is persistently slow", target.name),
        format!("{} DNS processing latency is within threshold", target.name),
        "GET /control/stats avg_processing_time",
        profile.processing_latency_sustain_runs,
        profile.recovery_runs,
    ));
    evaluations.push(threshold_evaluation(
        format!("target:{}:upstream-latency", target.id),
        target,
        "upstream_latency",
        operational.maximum_upstream_seconds,
        profile.upstream_latency_ms as f64 / 1_000.0,
        format!("{} has a persistently slow upstream", target.name),
        format!("{} upstream latency is within threshold", target.name),
        "GET /control/stats top_upstreams_avg_time",
        profile.upstream_latency_sustain_runs,
        profile.recovery_runs,
    ));
    if let Some(policy) = policy {
        evaluate_dns_policy(target, policy, profile, report, &mut evaluations);
        evaluate_filters(
            target,
            policy,
            profile,
            report,
            now_unix_seconds,
            &mut evaluations,
        );
        evaluate_rewrites(target, policy, profile, report, &mut evaluations);
    }
    evaluations
}

fn evaluate_dns_policy(
    target: &TargetConfig,
    policy: &PolicyConfig,
    profile: &ConditionProfile,
    report: &TargetReport,
    evaluations: &mut Vec<ConditionEvaluation>,
) {
    let Some(dns) = report.dns.as_ref() else {
        return;
    };
    if let Some(expected_mode) = &policy.upstream_mode {
        evaluations.push(boolean_evaluation(
            format!("target:{}:upstream-mode", target.id),
            target,
            "upstream_mode",
            Severity::Warning,
            Verdict::from_flag(
                dns.upstream_mode != *expected_mode,
                (
                    "drift",
                    format!("{} upstream mode differs from declared policy", target.name),
                ),
                (
                    "matches_policy",
                    format!("{} upstream mode matches declared policy", target.name),
                ),
            ),
            expected_mode,
            &dns.upstream_mode,
            "GET /control/dns_info upstream_mode",
            profile.policy_drift_sustain_runs,
            profile.recovery_runs,
        ));
    }
    if let Some(upstream_dns) = &policy.upstream_dns {
        let expected: BTreeSet<_> = upstream_dns.iter().cloned().collect();
        let observed: BTreeSet<_> = dns.upstream_dns.iter().cloned().collect();
        evaluations.push(boolean_evaluation(
            format!("target:{}:upstream-set", target.id),
            target,
            "upstream_set",
            Severity::Warning,
            Verdict::from_flag(
                expected != observed,
                (
                    "drift",
                    format!("{} upstream set differs from declared policy", target.name),
                ),
                (
                    "matches_policy",
                    format!("{} upstream set matches declared policy", target.name),
                ),
            ),
            expected,
            observed,
            "GET /control/dns_info upstream_dns",
            profile.policy_drift_sustain_runs,
            profile.recovery_runs,
        ));
    }
}

fn evaluate_filters(
    target: &TargetConfig,
    policy: &PolicyConfig,
    profile: &ConditionProfile,
    report: &TargetReport,
    now_unix_seconds: i64,
    evaluations: &mut Vec<ConditionEvaluation>,
) {
    let observed: BTreeMap<_, _> = report
        .filters
        .iter()
        .map(|filter| (filter.url.as_str(), filter))
        .collect();
    for required in &policy.filters {
        let id = short_hash(&required.url);
        let condition_id = format!("target:{}:filter:{id}", target.id);
        let matches_policy = || {
            Verdict::clear(
                "matches_policy",
                format!("{} required filter matches declared policy", target.name),
            )
        };
        let (verdict, observed_value) = match observed.get(required.url.as_str()) {
            None => (
                Verdict::active(
                    "missing",
                    format!("{} is missing a required filter", target.name),
                ),
                json!(null),
            ),
            Some(filter) if filter.enabled != required.enabled => (
                Verdict::active(
                    "state_drift",
                    format!("{} has a required filter in the wrong state", target.name),
                ),
                json!({ "enabled": filter.enabled, "last_updated": filter.last_updated }),
            ),
            Some(filter) if required.enabled => {
                let maximum_age = i64::from(required.maximum_age_hours.unwrap_or_default()) * 3_600;
                let stale = filter
                    .last_updated_unix_seconds
                    .is_none_or(|updated| now_unix_seconds.saturating_sub(updated) > maximum_age);
                (
                    if stale {
                        Verdict::active(
                            "stale",
                            format!("{} has a stale required filter", target.name),
                        )
                    } else {
                        matches_policy()
                    },
                    json!({
                        "enabled": filter.enabled,
                        "last_updated": filter.last_updated,
                        "age_seconds": filter.last_updated_unix_seconds.map(|updated| now_unix_seconds.saturating_sub(updated)),
                    }),
                )
            }
            Some(filter) => (
                matches_policy(),
                json!({ "enabled": filter.enabled, "last_updated": filter.last_updated }),
            ),
        };
        evaluations.push(evaluation(
            condition_id,
            Some(target.id.clone()),
            "required_filter",
            Severity::Warning,
            verdict,
            json!({
                "url": required.url,
                "enabled": required.enabled,
                "maximum_age_hours": required.maximum_age_hours,
            }),
            observed_value,
            "GET /control/filtering/status filters",
            true,
            profile.policy_drift_sustain_runs,
            profile.recovery_runs,
        ));
    }
}

fn evaluate_rewrites(
    target: &TargetConfig,
    policy: &PolicyConfig,
    profile: &ConditionProfile,
    report: &TargetReport,
    evaluations: &mut Vec<ConditionEvaluation>,
) {
    if let Some(enabled) = policy.rewrites.enabled {
        evaluations.push(boolean_evaluation(
            format!("target:{}:rewrites-enabled", target.id),
            target,
            "rewrite_settings",
            Severity::Warning,
            Verdict::from_flag(
                report.rewrites_enabled != Some(enabled),
                (
                    "drift",
                    format!(
                        "{} rewrite settings differ from declared policy",
                        target.name
                    ),
                ),
                (
                    "matches_policy",
                    format!("{} rewrite settings match declared policy", target.name),
                ),
            ),
            enabled,
            report.rewrites_enabled,
            "GET /control/rewrite/settings enabled",
            profile.policy_drift_sustain_runs,
            profile.recovery_runs,
        ));
    }
    let observed: BTreeMap<_, _> = report
        .rewrites
        .iter()
        .map(|rewrite| {
            (
                (
                    normalize_dns_name(&rewrite.domain),
                    normalize_rewrite_answer(&rewrite.answer),
                ),
                rewrite,
            )
        })
        .collect();
    for required in &policy.rewrites.required {
        let key = (
            normalize_dns_name(&required.domain),
            normalize_rewrite_answer(&required.answer),
        );
        let current = observed.get(&key);
        // A rewrite entry only takes effect while the resolver's global rewrite
        // switch is on, so a required-and-enabled rewrite cannot report clear
        // while that switch is off or unreadable. The switch has its own
        // condition, but only when the policy declares it, and an undeclared
        // switch must not turn this row into a false clear.
        let verdict = if current.is_none_or(|rewrite| rewrite.enabled != required.enabled) {
            Verdict::active(
                "missing_or_disabled",
                format!(
                    "{} is missing or has disabled a required rewrite",
                    target.name
                ),
            )
        } else if required.enabled && report.rewrites_enabled != Some(true) {
            Verdict::active(
                "globally_disabled",
                format!(
                    "{} has DNS rewrites switched off, so a required rewrite does not resolve",
                    target.name
                ),
            )
        } else {
            Verdict::clear(
                "matches_policy",
                format!("{} required rewrite matches declared policy", target.name),
            )
        };
        evaluations.push(evaluation(
            format!(
                "target:{}:rewrite:{}",
                target.id,
                short_hash(&format!("{}={}", key.0, key.1))
            ),
            Some(target.id.clone()),
            "required_rewrite",
            Severity::Warning,
            verdict,
            json!({ "domain": key.0, "answer": key.1, "enabled": required.enabled }),
            current.map_or(Value::Null, |rewrite| {
                json!({
                    "domain": rewrite.domain,
                    "answer": rewrite.answer,
                    "enabled": rewrite.enabled,
                })
            }),
            "GET /control/rewrite/list",
            true,
            profile.policy_drift_sustain_runs,
            profile.recovery_runs,
        ));
    }
}

/// Identifiers and phrasing for one behavioural condition set: the group
/// aggregate, or a single target.
struct BehavioralSubject {
    query_rate_id: String,
    blocked_ratio_id: String,
    collapse_id: String,
    query_rate_kind: &'static str,
    blocked_ratio_kind: &'static str,
    collapse_kind: &'static str,
    target_id: Option<String>,
    evidence_source: &'static str,
    /// Sentence subject, such as `Combined AdGuard` or a resolver name.
    noun: String,
}

impl BehavioralSubject {
    fn aggregate() -> Self {
        Self {
            query_rate_id: "aggregate:query-rate".to_owned(),
            blocked_ratio_id: "aggregate:blocked-ratio".to_owned(),
            collapse_id: "aggregate:blocking-collapsed".to_owned(),
            query_rate_kind: "combined_query_rate",
            blocked_ratio_kind: "combined_blocked_ratio",
            collapse_kind: "combined_blocking_collapse",
            target_id: None,
            evidence_source: "combined complete target statistics",
            noun: "Combined AdGuard".to_owned(),
        }
    }

    fn target(id: &str, name: &str) -> Self {
        Self {
            query_rate_id: format!("target:{id}:query-rate"),
            blocked_ratio_id: format!("target:{id}:blocked-ratio"),
            collapse_id: format!("target:{id}:blocking-collapsed"),
            query_rate_kind: "query_rate",
            blocked_ratio_kind: "blocked_ratio",
            collapse_kind: "blocking_collapse",
            target_id: Some(id.to_owned()),
            evidence_source: "target statistics",
            noun: name.to_owned(),
        }
    }
}

/// Limits a behavioural comparison produced, for the aggregate observation.
#[derive(Clone, Copy, Debug, Default)]
struct BehavioralLimits {
    query_rate: Option<f64>,
    blocked_ratio: Option<f64>,
}

/// Emits the three behavioural conditions for one subject.
///
/// Query rate and blocked ratio have **independent** baselines. Every window
/// carries a rate, but only windows holding at least
/// `RATE_WINDOW_MINIMUM_QUERIES` carry a ratio worth comparing, so a subject can
/// have enough history to judge its rate and not enough to judge its ratio. The
/// two readiness counts are therefore kept apart: a sparse ratio population must
/// not suppress the rate condition, and a large rate population must not admit a
/// ratio comparison against one or two points.
///
/// A condition that cannot be compared reports why, and the three reasons are
/// distinct: `baseline_learning` when the history is too short or too sparse,
/// `rate_window_unavailable` when the latest pair spans a counter reset or a
/// gap, and `window_too_small` when the latest window holds too few queries.
/// None of them increments, clears, or resolves a latch.
fn behavioral_evaluations(
    subject: &BehavioralSubject,
    profile: &ConditionProfile,
    baseline_ready: bool,
    history: &[RateWindow],
    current: Option<RateWindow>,
    minimum_windows: usize,
) -> (Vec<ConditionEvaluation>, BehavioralLimits) {
    let rate_values: Vec<f64> = history.iter().map(|window| window.query_rate).collect();
    let ratio_values: Vec<f64> = history
        .iter()
        .filter_map(RateWindow::comparable_blocked_ratio)
        .collect();
    let rate_bounds = (baseline_ready && rate_values.len() >= minimum_windows)
        .then(|| robust_bounds(&rate_values))
        .flatten();
    let ratio_bounds = (baseline_ready && ratio_values.len() >= minimum_windows)
        .then(|| robust_bounds(&ratio_values))
        .flatten();

    let unevaluated = |id: &String,
                       kind: &'static str,
                       severity: Severity,
                       reason: &'static str,
                       summary: String,
                       windows: usize| {
        evaluation(
            id.clone(),
            subject.target_id.clone(),
            kind,
            severity,
            Verdict::not_evaluated(reason, summary),
            json!({ "minimum_same_hour_windows": minimum_windows }),
            json!({
                "same_hour_windows": windows,
                "baseline_ready": baseline_ready,
                "window_available": current.is_some(),
            }),
            subject.evidence_source,
            false,
            profile.behavioral_anomaly_sustain_runs,
            profile.recovery_runs,
        )
    };

    let mut limits = BehavioralLimits::default();
    let mut evaluations = Vec::new();

    evaluations.push(match (rate_bounds, current) {
        (None, _) => unevaluated(
            &subject.query_rate_id,
            subject.query_rate_kind,
            Severity::Warning,
            "baseline_learning",
            format!("{} query-rate baseline is still learning", subject.noun),
            rate_values.len(),
        ),
        (Some(_), None) => unevaluated(
            &subject.query_rate_id,
            subject.query_rate_kind,
            Severity::Warning,
            "rate_window_unavailable",
            format!("{} query rate has no comparable window", subject.noun),
            rate_values.len(),
        ),
        (Some((median, deviation)), Some(window)) => {
            let limit = (median * QUERY_RATE_MEDIAN_MULTIPLE)
                .max(median + QUERY_RATE_DEVIATION_MULTIPLE * deviation);
            limits.query_rate = Some(limit);
            evaluation(
                subject.query_rate_id.clone(),
                subject.target_id.clone(),
                subject.query_rate_kind,
                Severity::Warning,
                Verdict::from_flag(
                    window.query_rate > limit,
                    (
                        "above_baseline",
                        format!("{} query rate is anomalously high", subject.noun),
                    ),
                    (
                        "within_baseline",
                        format!("{} query rate is within baseline", subject.noun),
                    ),
                ),
                json!({
                    "maximum_queries_per_second": limit,
                    "same_hour_median_queries_per_second": median,
                    "same_hour_windows": rate_values.len(),
                }),
                json!({
                    "queries_per_second": window.query_rate,
                    "window_queries": window.queries,
                    "window_seconds": window.elapsed_seconds,
                }),
                subject.evidence_source,
                true,
                profile.behavioral_anomaly_sustain_runs,
                profile.recovery_runs,
            )
        }
    });

    let comparable = current.and_then(|window| window.comparable_blocked_ratio());
    for (id, kind, severity, collapse) in [
        (
            &subject.blocked_ratio_id,
            subject.blocked_ratio_kind,
            Severity::Warning,
            false,
        ),
        (
            &subject.collapse_id,
            subject.collapse_kind,
            Severity::Critical,
            true,
        ),
    ] {
        let Some((median, deviation)) = ratio_bounds else {
            evaluations.push(unevaluated(
                id,
                kind,
                severity,
                "baseline_learning",
                format!(
                    "{} {} baseline is still learning",
                    subject.noun,
                    if collapse {
                        "blocking-collapse"
                    } else {
                        "blocked-ratio"
                    }
                ),
                ratio_values.len(),
            ));
            continue;
        };
        let Some(window) = current else {
            evaluations.push(unevaluated(
                id,
                kind,
                severity,
                "rate_window_unavailable",
                format!("{} has no comparable window", subject.noun),
                ratio_values.len(),
            ));
            continue;
        };
        let Some(ratio) = comparable else {
            evaluations.push(unevaluated(
                id,
                kind,
                severity,
                "window_too_small",
                format!("{} has too few queries to compare", subject.noun),
                ratio_values.len(),
            ));
            continue;
        };
        let limit =
            BLOCKED_RATIO_MINIMUM_DEVIATION.max(BLOCKED_RATIO_DEVIATION_MULTIPLE * deviation);
        let collapse_limit = median * BLOCKING_COLLAPSE_FRACTION;
        let verdict = if collapse {
            Verdict::from_flag(
                ratio < collapse_limit,
                (
                    "blocking_collapsed",
                    format!("{} blocking has nearly stopped", subject.noun),
                ),
                (
                    "blocking_sustained",
                    format!("{} blocking is sustained", subject.noun),
                ),
            )
        } else {
            limits.blocked_ratio = Some(limit);
            Verdict::from_flag(
                (ratio - median).abs() > limit,
                (
                    "outside_baseline",
                    format!("{} blocked-query ratio is anomalous", subject.noun),
                ),
                (
                    "within_baseline",
                    format!("{} blocked-query ratio is within baseline", subject.noun),
                ),
            )
        };
        let expected = if collapse {
            json!({
                "minimum_blocked_ratio": collapse_limit,
                "same_hour_median": median,
                "minimum_queries": RATE_WINDOW_MINIMUM_QUERIES,
                "same_hour_windows": ratio_values.len(),
            })
        } else {
            json!({
                "maximum_absolute_deviation": limit,
                "same_hour_median": median,
                "minimum_queries": RATE_WINDOW_MINIMUM_QUERIES,
                "same_hour_windows": ratio_values.len(),
            })
        };
        evaluations.push(evaluation(
            id.clone(),
            subject.target_id.clone(),
            kind,
            severity,
            verdict,
            expected,
            json!({
                "window_blocked_ratio": ratio,
                "window_queries": window.queries,
            }),
            subject.evidence_source,
            true,
            profile.behavioral_anomaly_sustain_runs,
            profile.recovery_runs,
        ));
    }

    (evaluations, limits)
}

/// Behavioural conditions for one target, so that a single resolver losing
/// blocking is not diluted by the other members of its group.
///
/// Returns nothing when the target is absent from the declared behavioural
/// group or its current observation is incomplete: an incomplete reading has no
/// counter to difference against, and under ADR 0011 a condition that stops
/// being produced retains its latch rather than resolving.
pub fn evaluate_target_behavior(
    config: &BehavioralBaselineConfig,
    profile: &ConditionProfile,
    report: &TargetReport,
    samples: &[TargetSample],
    now_unix_seconds: i64,
    local_hour: u8,
) -> Vec<ConditionEvaluation> {
    if !config.target_ids.iter().any(|id| id == &report.id) {
        return Vec::new();
    }
    let Some(operational) = report.operational.as_ref() else {
        return Vec::new();
    };
    if !report.complete {
        return Vec::new();
    }
    let mine: Vec<&TargetSample> = samples
        .iter()
        .filter(|sample| sample.target_id == report.id)
        .collect();
    let history: Vec<RateWindow> = mine
        .windows(2)
        .filter_map(|pair| {
            let hour = local_hour_of(pair[1].timestamp, &config.time_zone)?;
            if hour != local_hour {
                return None;
            }
            window_between(
                (pair[0].timestamp, pair[0].queries, pair[0].blocked),
                (pair[1].timestamp, pair[1].queries, pair[1].blocked),
                hour,
            )
        })
        .collect();
    let current = mine.last().and_then(|previous| {
        window_between(
            (previous.timestamp, previous.queries, previous.blocked),
            (now_unix_seconds, operational.queries, operational.blocked),
            local_hour,
        )
    });
    let baseline_ready = mine.first().is_some_and(|oldest| {
        now_unix_seconds.saturating_sub(oldest.timestamp)
            >= i64::from(config.learning_days) * 86_400
    });
    let (evaluations, _) = behavioral_evaluations(
        &BehavioralSubject::target(&report.id, &report.name),
        profile,
        baseline_ready,
        &history,
        current,
        config.minimum_same_hour_samples,
    );
    evaluations
}

pub fn evaluate_aggregate(
    config: &BehavioralBaselineConfig,
    profile: &ConditionProfile,
    target_samples: &[TargetSample],
    target_reports: &[TargetReport],
    now_unix_seconds: i64,
    local_hour: u8,
    utc_offset_minutes: i32,
) -> Option<AggregateEvaluation> {
    let reports: BTreeMap<_, _> = target_reports
        .iter()
        .map(|report| (report.id.as_str(), report))
        .collect();
    let members: Option<Vec<_>> = config
        .target_ids
        .iter()
        .map(|id| reports.get(id.as_str()).copied())
        .collect();
    let members = members?;
    if members
        .iter()
        .any(|report| !report.complete || report.operational.is_none())
    {
        return None;
    }
    let operational: Vec<&OperationalObservation> = members
        .iter()
        .filter_map(|report| report.operational.as_ref())
        .collect();
    let combined_queries = operational.iter().map(|item| item.queries).sum::<u64>();
    let combined_blocked = operational.iter().map(|item| item.blocked).sum::<u64>();
    let combined_blocked_ratio = if combined_queries == 0 {
        0.0
    } else {
        combined_blocked as f64 / combined_queries as f64
    };
    // Age and readiness come from the readings the comparison actually uses, not
    // from any aggregate row ever persisted. A group whose membership changed
    // has older rows for its previous shape, and judging the new group ready on
    // the strength of those would compare it against a baseline it never had.
    let readings = combined_readings(config, target_samples);
    let baseline_age_seconds = readings
        .first()
        .map_or(0, |(oldest, _, _)| now_unix_seconds.saturating_sub(*oldest));
    let same_hour: Vec<_> = readings
        .iter()
        .filter(|(timestamp, _, _)| {
            local_hour_of(*timestamp, &config.time_zone) == Some(local_hour)
        })
        .collect();
    let baseline_ready = baseline_age_seconds >= i64::from(config.learning_days) * 86_400
        && same_hour.len() >= config.minimum_same_hour_samples;
    let mut resolver_query_share = BTreeMap::new();
    let mut top_client_share = BTreeMap::new();
    for report in &members {
        if let Some(item) = report.operational.as_ref() {
            resolver_query_share.insert(
                report.id.clone(),
                if combined_queries == 0 {
                    0.0
                } else {
                    item.queries as f64 / combined_queries as f64
                },
            );
            top_client_share.insert(report.id.clone(), item.top_client_share);
        }
    }
    let mut observation = AggregateObservation {
        local_hour,
        utc_offset_minutes,
        combined_queries,
        combined_blocked_ratio,
        baseline_age_seconds,
        same_hour_samples: same_hour.len(),
        baseline_ready,
        query_rate_limit: None,
        blocked_ratio_limit: None,
        resolver_query_share,
        top_client_share,
    };
    let history: Vec<RateWindow> = readings
        .windows(2)
        .filter_map(|pair| {
            let hour = local_hour_of(pair[1].0, &config.time_zone)?;
            if hour != local_hour {
                return None;
            }
            window_between(pair[0], pair[1], hour)
        })
        .collect();
    let current = readings.last().and_then(|previous| {
        window_between(
            *previous,
            (now_unix_seconds, combined_queries, combined_blocked),
            local_hour,
        )
    });
    let (evaluations, limits) = behavioral_evaluations(
        &BehavioralSubject::aggregate(),
        profile,
        baseline_ready,
        &history,
        current,
        config.minimum_same_hour_samples,
    );
    observation.query_rate_limit = limits.query_rate;
    observation.blocked_ratio_limit = limits.blocked_ratio;
    Some(AggregateEvaluation {
        observation,
        evaluations,
    })
}

pub fn advance_condition(
    state: &mut ConditionState,
    evaluation: &mut ConditionEvaluation,
    observed_at: &str,
    run_id: &str,
    suppress_notifications: bool,
) -> Option<ConditionTransition> {
    state.kind = evaluation.kind.clone();
    state.severity = evaluation.severity;
    if evaluation.outcome == EvaluationOutcome::NotEvaluated {
        copy_state_to_evaluation(state, evaluation);
        return None;
    }
    state.last_observed_at = Some(observed_at.to_owned());
    let transition = match evaluation.outcome {
        EvaluationOutcome::Active => {
            state.consecutive_clear = 0;
            state.consecutive_active = state.consecutive_active.saturating_add(1);
            if state.first_observed_at.is_none() {
                state.first_observed_at = Some(observed_at.to_owned());
            }
            if state.lifecycle != ConditionLifecycle::Firing
                && state.consecutive_active >= evaluation.sustain_runs
            {
                state.lifecycle = ConditionLifecycle::Firing;
                state.last_transition_run = Some(run_id.to_owned());
                state.alert_delivery_state = if suppress_notifications {
                    AlertDeliveryState::Suppressed
                } else {
                    AlertDeliveryState::Pending
                };
                Some(ConditionTransition {
                    condition_id: evaluation.id.clone(),
                    kind: TransitionKind::Alert,
                    summary: evaluation.summary.clone(),
                })
            } else {
                if state.lifecycle == ConditionLifecycle::Clear {
                    state.lifecycle = ConditionLifecycle::Pending;
                }
                None
            }
        }
        EvaluationOutcome::Clear => {
            let was_firing = state.lifecycle == ConditionLifecycle::Firing;
            state.consecutive_active = 0;
            state.consecutive_clear = state.consecutive_clear.saturating_add(1);
            if state.consecutive_clear >= evaluation.recovery_runs {
                state.lifecycle = ConditionLifecycle::Clear;
                state.first_observed_at = None;
                if was_firing
                    && matches!(
                        state.alert_delivery_state,
                        AlertDeliveryState::Delivered | AlertDeliveryState::Suppressed
                    )
                {
                    state.last_transition_run = Some(run_id.to_owned());
                    state.alert_delivery_state = if suppress_notifications {
                        AlertDeliveryState::Suppressed
                    } else {
                        AlertDeliveryState::Pending
                    };
                    Some(ConditionTransition {
                        condition_id: evaluation.id.clone(),
                        kind: TransitionKind::Resolution,
                        summary: evaluation.summary.clone(),
                    })
                } else {
                    if !was_firing && state.alert_delivery_state == AlertDeliveryState::Pending {
                        state.alert_delivery_state = AlertDeliveryState::Never;
                    }
                    None
                }
            } else {
                None
            }
        }
        EvaluationOutcome::NotEvaluated => None,
    };
    copy_state_to_evaluation(state, evaluation);
    transition
}

fn copy_state_to_evaluation(state: &ConditionState, evaluation: &mut ConditionEvaluation) {
    evaluation.consecutive_active = state.consecutive_active;
    evaluation.consecutive_clear = state.consecutive_clear;
    evaluation.lifecycle = state.lifecycle;
    evaluation.notification_state = state.alert_delivery_state;
    evaluation
        .first_observed_at
        .clone_from(&state.first_observed_at);
}

fn threshold_evaluation(
    id: String,
    target: &TargetConfig,
    kind: &str,
    observed: f64,
    maximum: f64,
    active_summary: String,
    clear_summary: String,
    evidence: &str,
    sustain_runs: u32,
    recovery_runs: u32,
) -> ConditionEvaluation {
    evaluation(
        id,
        Some(target.id.clone()),
        kind,
        Severity::Warning,
        Verdict::from_flag(
            observed > maximum,
            ("above_threshold", active_summary),
            ("within_threshold", clear_summary),
        ),
        json!({ "maximum_seconds": maximum, "comparison": "strictly_greater" }),
        json!({ "seconds": observed }),
        evidence,
        true,
        sustain_runs,
        recovery_runs,
    )
}

fn boolean_evaluation<E: serde::Serialize, O: serde::Serialize>(
    id: String,
    target: &TargetConfig,
    kind: &str,
    severity: Severity,
    verdict: Verdict,
    expected: E,
    observed: O,
    evidence: &str,
    sustain_runs: u32,
    recovery_runs: u32,
) -> ConditionEvaluation {
    evaluation(
        id,
        Some(target.id.clone()),
        kind,
        severity,
        verdict,
        serde_json::to_value(expected).expect("serializing expected value cannot fail"),
        serde_json::to_value(observed).expect("serializing observed value cannot fail"),
        evidence,
        true,
        sustain_runs,
        recovery_runs,
    )
}

/// The part of an evaluation that varies from run to run.
///
/// `kind` names what was checked and is stable for a given condition id. A
/// `Verdict` says what the check found this time: the outcome, a machine
/// `reason` for the specific divergence, and a summary phrased to match the
/// outcome rather than always phrased as the failure.
#[derive(Debug)]
struct Verdict {
    outcome: EvaluationOutcome,
    reason: &'static str,
    summary: String,
}

impl Verdict {
    fn active(reason: &'static str, summary: String) -> Self {
        Self {
            outcome: EvaluationOutcome::Active,
            reason,
            summary,
        }
    }

    fn clear(reason: &'static str, summary: String) -> Self {
        Self {
            outcome: EvaluationOutcome::Clear,
            reason,
            summary,
        }
    }

    fn not_evaluated(reason: &'static str, summary: String) -> Self {
        Self {
            outcome: EvaluationOutcome::NotEvaluated,
            reason,
            summary,
        }
    }

    fn from_flag(
        active: bool,
        when_active: (&'static str, String),
        when_clear: (&'static str, String),
    ) -> Self {
        if active {
            Self::active(when_active.0, when_active.1)
        } else {
            Self::clear(when_clear.0, when_clear.1)
        }
    }
}

fn evaluation(
    id: String,
    target_id: Option<String>,
    kind: &str,
    severity: Severity,
    verdict: Verdict,
    expected: Value,
    observed: Value,
    evidence_source: &str,
    observation_complete: bool,
    sustain_runs: u32,
    recovery_runs: u32,
) -> ConditionEvaluation {
    ConditionEvaluation {
        id,
        target_id,
        kind: kind.to_owned(),
        reason: verdict.reason.to_owned(),
        severity,
        outcome: verdict.outcome,
        summary: verdict.summary,
        expected,
        observed,
        evidence_source: evidence_source.to_owned(),
        observation_complete,
        sustain_runs,
        recovery_runs,
        consecutive_active: 0,
        consecutive_clear: 0,
        lifecycle: ConditionLifecycle::Clear,
        notification_state: AlertDeliveryState::Never,
        first_observed_at: None,
    }
}

fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    crate::hex::encode(&digest)[..16].to_owned()
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;
    use serde_json::json;

    use super::{
        advance_condition, combined_readings, evaluate_aggregate, evaluate_target_behavior,
        local_time_bucket, robust_bounds, window_between,
    };
    use crate::config::{
        BehavioralBaselineConfig, ConditionProfile, PolicyConfig, RequiredFilter, RequiredRewrite,
        RequiredRewrites, TargetAuth, TargetConfig,
    };
    use crate::model::{
        AlertDeliveryState, ConditionEvaluation, ConditionLifecycle, ConditionState,
        DnsObservation, EvaluationOutcome, FilterObservation, OperationalObservation,
        RewriteObservation, Severity, TargetReport, TargetSample, TargetStatus, TransitionKind,
    };

    /// Condition identifiers embed this hash and latch state is keyed on the
    /// identifier, so a change here silently resets every latch on every
    /// deployment. Pinned against an independently computed SHA-256 prefix.
    #[test]
    fn short_hash_is_stable() {
        assert_eq!(
            super::short_hash("https://filters.invalid/required.txt"),
            "a0917584ced31967"
        );
    }

    #[test]
    fn robust_bounds_match_behavior_contract() {
        let (median, deviation) = robust_bounds(&[1.0, 2.0, 3.0]).expect("bounds");
        assert!((median - 2.0).abs() < f64::EPSILON);
        assert!((deviation - 1.4826).abs() < 1e-12);
        let (_, floor) = robust_bounds(&[2.0, 2.0, 2.0]).expect("bounds");
        assert!((floor - 1e-9).abs() < f64::EPSILON);
    }

    #[test]
    fn latch_alerts_once_and_resolves_once() {
        let mut evaluation = ConditionEvaluation {
            id: "target:a:test".to_owned(),
            target_id: Some("a".to_owned()),
            kind: "test".to_owned(),
            reason: "fixture".to_owned(),
            severity: Severity::Warning,
            outcome: EvaluationOutcome::Active,
            summary: "active".to_owned(),
            expected: json!(false),
            observed: json!(true),
            evidence_source: "fixture".to_owned(),
            observation_complete: true,
            sustain_runs: 2,
            recovery_runs: 1,
            consecutive_active: 0,
            consecutive_clear: 0,
            lifecycle: ConditionLifecycle::Clear,
            notification_state: AlertDeliveryState::Never,
            first_observed_at: None,
        };
        let mut state = ConditionState::from_evaluation(&evaluation);
        assert!(
            advance_condition(
                &mut state,
                &mut evaluation,
                "2026-01-01T00:00:00Z",
                "1",
                false
            )
            .is_none()
        );
        let alert = advance_condition(
            &mut state,
            &mut evaluation,
            "2026-01-01T00:05:00Z",
            "2",
            false,
        )
        .expect("alert");
        assert_eq!(alert.kind, TransitionKind::Alert);
        assert!(
            advance_condition(
                &mut state,
                &mut evaluation,
                "2026-01-01T00:10:00Z",
                "3",
                false
            )
            .is_none()
        );
        state.alert_delivery_state = AlertDeliveryState::Delivered;
        evaluation.outcome = EvaluationOutcome::Clear;
        let resolution = advance_condition(
            &mut state,
            &mut evaluation,
            "2026-01-01T00:15:00Z",
            "4",
            false,
        )
        .expect("resolution");
        assert_eq!(resolution.kind, TransitionKind::Resolution);
    }

    /// Eight days of a two-resolver group across the 09:00 local hour, at a
    /// steady 1.0 combined queries per second with a tenth blocked, sampled
    /// every 300 seconds. Each resolver contributes half.
    fn aggregate_history() -> Vec<TargetSample> {
        let mut targets = Vec::new();
        for day in 0..8i64 {
            for slot in 1..=12i64 {
                let queries = u64::try_from((13 - slot) * 300).expect("queries");
                for id in ["a", "b"] {
                    targets.push(TargetSample {
                        run_id: format!("run-{day}-{slot}"),
                        target_id: id.to_owned(),
                        timestamp: HOUR_NINE - day * 86_400 - slot * 300,
                        queries: queries / 2,
                        blocked: queries / 20,
                    });
                }
            }
        }
        targets.sort_by_key(|sample| sample.timestamp);
        targets
    }

    fn group_config() -> BehavioralBaselineConfig {
        BehavioralBaselineConfig {
            target_ids: vec!["a".to_owned(), "b".to_owned()],
            time_zone: "Europe/Amsterdam".to_owned(),
            learning_days: 7,
            minimum_same_hour_samples: 36,
        }
    }

    #[test]
    fn a_sawtooth_counter_yields_one_flat_rate() {
        // AdGuard resets its counter on the local hour, so the raw value ramps
        // from nothing to a full hour total and back. Differencing must read the
        // same rate at both ends of that ramp.
        let early = window_between((60, 60, 6), (360, 360, 36), 9).expect("early window");
        let late =
            window_between((3_000, 3_000, 300), (3_300, 3_300, 330), 9).expect("late window");
        assert!((early.query_rate - 1.0).abs() < 1e-9);
        assert!((late.query_rate - 1.0).abs() < 1e-9);
        assert!((early.blocked_ratio - late.blocked_ratio).abs() < 1e-9);
    }

    #[test]
    fn a_counter_reset_or_a_long_gap_produces_no_window() {
        assert_eq!(
            window_between((3_500, 3_500, 350), (3_800, 120, 12), 9),
            None,
            "a decreasing query counter is a reset",
        );
        assert_eq!(
            window_between((3_500, 3_500, 350), (3_800, 3_900, 12), 9),
            None,
            "a decreasing blocked counter is a reset even when queries rose",
        );
        assert_eq!(
            window_between((0, 0, 0), (900, 900, 90), 9),
            None,
            "a gap longer than one run interval spans missed runs",
        );
        assert_eq!(
            window_between((0, 100, 10), (300, 200, 150), 9),
            None,
            "more blocked than queried in a window is inconsistent",
        );
    }

    #[test]
    fn aggregate_rate_threshold_equality_is_clear_and_above_is_active() {
        let targets = aggregate_history();
        let config = group_config();
        let profile = profile();
        // The baseline rate is 1.0/s with no dispersion, so the limit is 3 x
        // median. 900 queries over the 300 second window is exactly 3.0/s.
        let at_limit = evaluate_aggregate(
            &config,
            &profile,
            &targets,
            &[target("a", 2_250, 225), target("b", 2_250, 225)],
            HOUR_NINE,
            9,
            60,
        )
        .expect("aggregate");
        assert!(at_limit.observation.baseline_ready);
        assert_eq!(at_limit.evaluations[0].id, "aggregate:query-rate");
        assert_eq!(at_limit.evaluations[0].outcome, EvaluationOutcome::Clear);
        let above_limit = evaluate_aggregate(
            &config,
            &profile,
            &targets,
            &[target("a", 2_251, 225), target("b", 2_250, 225)],
            HOUR_NINE,
            9,
            60,
        )
        .expect("aggregate");
        assert_eq!(
            above_limit.evaluations[0].outcome,
            EvaluationOutcome::Active
        );
    }

    #[test]
    fn blocking_collapse_is_active_and_survives_an_absolute_floor() {
        // Blocking stops entirely while every policy condition stays clear. The
        // cumulative blocked counter holds still while queries keep rising,
        // which is what a collapse looks like on a monotonic counter. A
        // deviation floor at or above the median cannot see this, because a
        // collapse to zero deviates by exactly the median and no more.
        let targets = aggregate_history();
        let collapsed = evaluate_aggregate(
            &group_config(),
            &profile(),
            &targets,
            &[target("a", 2_250, 180), target("b", 2_250, 180)],
            HOUR_NINE,
            9,
            60,
        )
        .expect("aggregate");
        let ratio = &collapsed.evaluations[1];
        let collapse = &collapsed.evaluations[2];
        assert_eq!(ratio.id, "aggregate:blocked-ratio");
        assert_eq!(
            ratio.outcome,
            EvaluationOutcome::Active,
            "a 0.10 baseline deviating to 0.00 exceeds the 0.04 floor",
        );
        assert_eq!(collapse.id, "aggregate:blocking-collapsed");
        assert_eq!(collapse.outcome, EvaluationOutcome::Active);
        assert_eq!(collapse.severity, Severity::Critical);
    }

    #[test]
    fn sustained_blocking_leaves_both_ratio_conditions_clear() {
        let targets = aggregate_history();
        let healthy = evaluate_aggregate(
            &group_config(),
            &profile(),
            &targets,
            &[target("a", 2_250, 225), target("b", 2_250, 225)],
            HOUR_NINE,
            9,
            60,
        )
        .expect("aggregate");
        assert_eq!(healthy.evaluations[1].outcome, EvaluationOutcome::Clear);
        assert_eq!(healthy.evaluations[2].outcome, EvaluationOutcome::Clear);
    }

    #[test]
    fn a_run_missing_a_group_member_is_not_summed_over() {
        // Summing whatever reported would read as traffic falling by that
        // member's share, which no resolver actually saw.
        let mut targets = aggregate_history();
        let complete = combined_readings(&group_config(), &targets).len();
        let dropped = targets[targets.len() - 1].run_id.clone();
        targets.retain(|sample| sample.run_id != dropped || sample.target_id != "b");
        assert_eq!(
            combined_readings(&group_config(), &targets).len(),
            complete - 1,
            "a run missing a declared member contributes no combined reading",
        );
    }

    #[test]
    fn a_duplicated_member_reading_does_not_complete_a_group() {
        // Two readings for one target must not satisfy a two-member group, which
        // counting readings rather than distinct members would allow.
        let config = group_config();
        let targets = aggregate_history();
        let complete = combined_readings(&config, &targets).len();
        let run = targets[targets.len() - 1].run_id.clone();

        let mut without_b: Vec<TargetSample> = targets
            .iter()
            .filter(|sample| sample.run_id != run || sample.target_id != "b")
            .cloned()
            .collect();
        assert_eq!(combined_readings(&config, &without_b).len(), complete - 1);

        let mut duplicate = without_b
            .iter()
            .find(|sample| sample.run_id == run)
            .expect("the remaining member")
            .clone();
        duplicate.queries += 1;
        without_b.push(duplicate);
        assert_eq!(
            combined_readings(&config, &without_b).len(),
            complete - 1,
            "a duplicate cannot stand in for the absent member",
        );
    }

    #[test]
    fn bundled_timezone_database_handles_amsterdam_dst_hours() {
        let first_repeated: Timestamp = "2026-10-25T00:30:00Z".parse().expect("timestamp");
        let second_repeated: Timestamp = "2026-10-25T01:30:00Z".parse().expect("timestamp");
        assert_eq!(
            local_time_bucket(first_repeated, "Europe/Amsterdam").expect("bucket"),
            (2, 120)
        );
        assert_eq!(
            local_time_bucket(second_repeated, "Europe/Amsterdam").expect("bucket"),
            (2, 60)
        );
        let before_skip: Timestamp = "2026-03-29T00:30:00Z".parse().expect("timestamp");
        let after_skip: Timestamp = "2026-03-29T01:30:00Z".parse().expect("timestamp");
        assert_eq!(
            local_time_bucket(before_skip, "Europe/Amsterdam").expect("bucket"),
            (1, 60)
        );
        assert_eq!(
            local_time_bucket(after_skip, "Europe/Amsterdam").expect("bucket"),
            (3, 120)
        );
    }

    #[test]
    fn ignores_extra_independent_policy_and_detects_stale_required_filter() {
        let target_config = target_config();
        let policy = PolicyConfig {
            protection_enabled: Some(true),
            upstream_mode: Some("load_balance".to_owned()),
            upstream_dns: Some(vec!["tls://resolver.invalid".to_owned()]),
            filters: vec![RequiredFilter {
                url: "https://filters.invalid/required.txt".to_owned(),
                enabled: true,
                maximum_age_hours: Some(72),
            }],
            rewrites: RequiredRewrites {
                enabled: Some(true),
                required: vec![RequiredRewrite {
                    domain: "required.invalid".to_owned(),
                    answer: "192.0.2.10".to_owned(),
                    enabled: true,
                }],
            },
        };
        let now = 1_800_000_000;
        let mut report = target("a", 100, 10);
        report.filters = vec![
            FilterObservation {
                url: "https://filters.invalid/required.txt".to_owned(),
                server_id: 1,
                enabled: true,
                rules_count: 100,
                last_updated: Some("synthetic".to_owned()),
                last_updated_unix_seconds: Some(now - 72 * 3_600),
            },
            FilterObservation {
                url: "https://filters.invalid/extra.txt".to_owned(),
                server_id: 2,
                enabled: true,
                rules_count: 100,
                last_updated: Some("synthetic".to_owned()),
                last_updated_unix_seconds: Some(now - 60),
            },
        ];
        report.rewrites = vec![
            RewriteObservation {
                domain: "required.invalid".to_owned(),
                answer: "192.0.2.10".to_owned(),
                enabled: true,
            },
            RewriteObservation {
                domain: "extra.invalid".to_owned(),
                answer: "192.0.2.20".to_owned(),
                enabled: true,
            },
        ];
        let healthy =
            super::evaluate_target(&target_config, Some(&policy), &profile(), &report, now);
        assert!(
            healthy
                .iter()
                .all(|evaluation| evaluation.outcome == EvaluationOutcome::Clear)
        );
        report.filters[0].last_updated_unix_seconds = Some(now - 72 * 3_600 - 1);
        let stale = super::evaluate_target(&target_config, Some(&policy), &profile(), &report, now);
        assert!(stale.iter().any(|evaluation| {
            evaluation.kind == "required_filter"
                && evaluation.reason == "stale"
                && evaluation.outcome == EvaluationOutcome::Active
        }));
        report.filters.clear();
        report.rewrites.clear();
        let missing =
            super::evaluate_target(&target_config, Some(&policy), &profile(), &report, now);
        assert!(missing.iter().any(|evaluation| {
            evaluation.kind == "required_filter"
                && evaluation.reason == "missing"
                && evaluation.outcome == EvaluationOutcome::Active
        }));
        assert!(missing.iter().any(|evaluation| {
            evaluation.kind == "required_rewrite"
                && evaluation.reason == "missing_or_disabled"
                && evaluation.outcome == EvaluationOutcome::Active
        }));
    }

    #[test]
    fn strict_latency_boundaries_and_protection_sustain_match_contract() {
        let target_config = target_config();
        let policy = PolicyConfig {
            protection_enabled: Some(true),
            upstream_mode: Some("load_balance".to_owned()),
            upstream_dns: Some(vec!["tls://resolver.invalid".to_owned()]),
            filters: Vec::new(),
            rewrites: RequiredRewrites {
                enabled: Some(true),
                required: Vec::new(),
            },
        };
        let mut report = target("a", 100, 10);
        let operational = report.operational.as_mut().expect("operational");
        operational.average_processing_seconds = 0.5;
        operational.maximum_upstream_seconds = 0.75;
        let at_limit = super::evaluate_target(
            &target_config,
            Some(&policy),
            &profile(),
            &report,
            1_800_000_000,
        );
        assert!(
            at_limit
                .iter()
                .filter(|evaluation| {
                    matches!(
                        evaluation.kind.as_str(),
                        "processing_latency" | "upstream_latency"
                    )
                })
                .all(|evaluation| evaluation.outcome == EvaluationOutcome::Clear)
        );
        let operational = report.operational.as_mut().expect("operational");
        operational.protection_enabled = false;
        operational.average_processing_seconds = 0.500_001;
        operational.maximum_upstream_seconds = 0.750_001;
        let above = super::evaluate_target(
            &target_config,
            Some(&policy),
            &profile(),
            &report,
            1_800_000_000,
        );
        let protection = above
            .iter()
            .find(|evaluation| evaluation.kind == "protection")
            .expect("protection");
        assert_eq!(protection.outcome, EvaluationOutcome::Active);
        assert_eq!(protection.sustain_runs, 2);
        assert!(
            above
                .iter()
                .filter(|evaluation| {
                    matches!(
                        evaluation.kind.as_str(),
                        "processing_latency" | "upstream_latency"
                    )
                })
                .all(|evaluation| evaluation.outcome == EvaluationOutcome::Active
                    && evaluation.sustain_runs == 4)
        );
    }

    #[test]
    fn no_policy_emits_no_policy_evaluations() {
        let evaluations = super::evaluate_target(
            &target_config(),
            None,
            &profile(),
            &target("a", 100, 10),
            1_800_000_000,
        );

        let identities: Vec<_> = evaluations
            .iter()
            .map(|evaluation| (evaluation.id.as_str(), evaluation.kind.as_str()))
            .collect();
        assert_eq!(
            identities,
            [
                ("target:a:api", "api"),
                ("target:a:processing-latency", "processing_latency"),
                ("target:a:upstream-latency", "upstream_latency"),
            ]
        );
        assert!(
            evaluations
                .iter()
                .all(|evaluation| evaluation.outcome == EvaluationOutcome::Clear)
        );
    }

    #[test]
    fn an_omitted_upstream_set_emits_no_upstream_set_evaluation() {
        let policy = PolicyConfig {
            upstream_mode: Some("load_balance".to_owned()),
            ..PolicyConfig::default()
        };

        let evaluations = super::evaluate_target(
            &target_config(),
            Some(&policy),
            &profile(),
            &target("a", 100, 10),
            1_800_000_000,
        );

        assert!(
            evaluations
                .iter()
                .any(|evaluation| evaluation.kind == "upstream_mode")
        );
        assert!(
            evaluations
                .iter()
                .all(|evaluation| evaluation.kind != "upstream_set")
        );
    }

    /// An entry present in the rewrite list does nothing while the resolver's
    /// global rewrite switch is off. Declaring only `required` is legal, so
    /// without this the whole report reads clear while no rewrite resolves.
    #[test]
    fn a_required_rewrite_is_not_clear_while_rewrites_are_switched_off() {
        let policy = PolicyConfig {
            rewrites: RequiredRewrites {
                enabled: None,
                required: vec![required_rewrite(
                    "service-b.example.invalid",
                    "192.0.2.10",
                    true,
                )],
            },
            ..PolicyConfig::default()
        };

        for switch in [Some(false), None] {
            let mut report = target("a", 100, 10);
            report.rewrites_enabled = switch;
            report.rewrites = vec![observed_rewrite(
                "service-b.example.invalid",
                "192.0.2.10",
                true,
            )];

            let evaluations = super::evaluate_target(
                &target_config(),
                Some(&policy),
                &profile(),
                &report,
                1_800_000_000,
            );

            let rewrite = evaluations
                .iter()
                .find(|evaluation| evaluation.kind == "required_rewrite")
                .expect("a required rewrite evaluation");
            assert_eq!(
                rewrite.outcome,
                EvaluationOutcome::Active,
                "switch {switch:?}"
            );
            assert_eq!(rewrite.reason, "globally_disabled", "switch {switch:?}");
            // The policy never declared the switch, so it stays absent.
            assert!(
                evaluations
                    .iter()
                    .all(|evaluation| evaluation.kind != "rewrite_settings")
            );
        }
    }

    /// A rewrite declared `enabled = false` is not meant to resolve, so the
    /// global switch being off cannot make it drift.
    #[test]
    fn a_rewrite_required_to_be_disabled_ignores_the_global_switch() {
        let policy = PolicyConfig {
            rewrites: RequiredRewrites {
                enabled: None,
                required: vec![required_rewrite(
                    "service-b.example.invalid",
                    "192.0.2.10",
                    false,
                )],
            },
            ..PolicyConfig::default()
        };
        let mut report = target("a", 100, 10);
        report.rewrites_enabled = Some(false);
        report.rewrites = vec![observed_rewrite(
            "service-b.example.invalid",
            "192.0.2.10",
            false,
        )];

        let evaluations = super::evaluate_target(
            &target_config(),
            Some(&policy),
            &profile(),
            &report,
            1_800_000_000,
        );

        let rewrite = evaluations
            .iter()
            .find(|evaluation| evaluation.kind == "required_rewrite")
            .expect("a required rewrite evaluation");
        assert_eq!(rewrite.outcome, EvaluationOutcome::Clear);
        assert_eq!(rewrite.reason, "matches_policy");
    }

    /// The declared value decides the outcome. `reason` still names the
    /// observed state, so a `protection_enabled = true` policy is unchanged.
    #[test]
    fn protection_is_judged_against_the_declared_value() {
        for (declared, observed, outcome, reason) in [
            (true, true, EvaluationOutcome::Clear, "enabled"),
            (true, false, EvaluationOutcome::Active, "disabled"),
            (false, false, EvaluationOutcome::Clear, "disabled"),
            (false, true, EvaluationOutcome::Active, "enabled"),
        ] {
            let policy = PolicyConfig {
                protection_enabled: Some(declared),
                ..PolicyConfig::default()
            };
            let mut report = target("a", 100, 10);
            report
                .operational
                .as_mut()
                .expect("operational")
                .protection_enabled = observed;

            let evaluation = super::evaluate_target(
                &target_config(),
                Some(&policy),
                &profile(),
                &report,
                1_800_000_000,
            )
            .into_iter()
            .find(|evaluation| evaluation.kind == "protection")
            .expect("a protection evaluation");

            assert_eq!(
                evaluation.outcome, outcome,
                "declared {declared}, observed {observed}"
            );
            assert_eq!(
                evaluation.reason, reason,
                "declared {declared}, observed {observed}"
            );
            assert_eq!(evaluation.id, "target:a:protection");
        }
    }

    #[test]
    fn a_required_rewrite_matches_after_normalization() {
        let policy = rewrite_policy(
            vec![required_rewrite(
                "Service-B.Example.Invalid.",
                "2001:0DB8::1",
                true,
            )],
            true,
        );

        let evaluations = rewrite_evaluations(
            &policy,
            vec![observed_rewrite(
                "service-b.example.invalid",
                "2001:db8::1",
                true,
            )],
        );

        assert_eq!(evaluations.len(), 2);
        assert!(
            evaluations
                .iter()
                .all(|evaluation| evaluation.outcome == EvaluationOutcome::Clear)
        );
    }

    #[test]
    fn unrelated_observed_rewrites_produce_no_findings() {
        let policy = rewrite_policy(
            vec![required_rewrite(
                "service-a.example.invalid",
                "192.0.2.10",
                true,
            )],
            true,
        );

        let evaluations = rewrite_evaluations(
            &policy,
            vec![
                observed_rewrite("service-a.example.invalid", "192.0.2.10", true),
                observed_rewrite("service-c.example.invalid", "192.0.2.30", false),
                observed_rewrite("service-d.example.invalid", "192.0.2.40", true),
            ],
        );

        assert_eq!(evaluations.len(), 2);
        assert!(
            evaluations
                .iter()
                .all(|evaluation| evaluation.outcome == EvaluationOutcome::Clear)
        );
    }

    #[test]
    fn a_disabled_required_rewrite_is_policy_drift() {
        let policy = rewrite_policy(
            vec![required_rewrite(
                "service-a.example.invalid",
                "192.0.2.10",
                true,
            )],
            true,
        );

        let evaluations = rewrite_evaluations(
            &policy,
            vec![observed_rewrite(
                "service-a.example.invalid",
                "192.0.2.10",
                false,
            )],
        );

        let drift = evaluations
            .iter()
            .find(|evaluation| evaluation.kind == "required_rewrite")
            .expect("a required rewrite evaluation");
        assert_eq!(drift.outcome, EvaluationOutcome::Active);
        assert_eq!(drift.observed["enabled"], json!(false));
    }

    #[test]
    fn a_required_rewrite_answering_differently_is_reported_as_absent() {
        let policy = rewrite_policy(
            vec![required_rewrite(
                "service-a.example.invalid",
                "192.0.2.10",
                true,
            )],
            true,
        );

        let evaluations = rewrite_evaluations(
            &policy,
            vec![observed_rewrite(
                "service-a.example.invalid",
                "192.0.2.99",
                true,
            )],
        );

        let drift = evaluations
            .iter()
            .find(|evaluation| evaluation.kind == "required_rewrite")
            .expect("a required rewrite evaluation");
        assert_eq!(drift.outcome, EvaluationOutcome::Active);
        assert_eq!(drift.observed, json!(null));
    }

    #[test]
    fn an_empty_rewrite_policy_only_evaluates_the_global_setting() {
        let policy = rewrite_policy(Vec::new(), true);

        let evaluations = rewrite_evaluations(
            &policy,
            vec![observed_rewrite(
                "service-c.example.invalid",
                "192.0.2.30",
                true,
            )],
        );

        assert_eq!(evaluations.len(), 1);
        assert_eq!(evaluations[0].kind, "rewrite_settings");
        assert_eq!(evaluations[0].outcome, EvaluationOutcome::Clear);
    }

    #[test]
    fn disabling_global_rewrite_handling_is_policy_drift() {
        let policy = rewrite_policy(Vec::new(), true);
        let mut report = target("a", 100, 10);
        report.rewrites_enabled = Some(false);

        let evaluations = super::evaluate_target(
            &target_config(),
            Some(&policy),
            &profile(),
            &report,
            1_800_000_000,
        );

        let settings = evaluations
            .iter()
            .find(|evaluation| evaluation.kind == "rewrite_settings")
            .expect("a rewrite settings evaluation");
        assert_eq!(settings.outcome, EvaluationOutcome::Active);
    }

    #[test]
    fn rewrite_condition_ids_ignore_declared_spelling() {
        let observed = vec![observed_rewrite(
            "service-a.example.invalid",
            "192.0.2.10",
            true,
        )];
        let canonical = rewrite_policy(
            vec![required_rewrite(
                "service-a.example.invalid",
                "192.0.2.10",
                true,
            )],
            true,
        );
        let respelled = rewrite_policy(
            vec![required_rewrite(
                "Service-A.Example.Invalid.",
                "192.0.2.10",
                true,
            )],
            true,
        );

        let left = rewrite_evaluations(&canonical, observed.clone());
        let right = rewrite_evaluations(&respelled, observed);

        let ids: fn(&[ConditionEvaluation]) -> Vec<String> = |evaluations| {
            evaluations
                .iter()
                .map(|evaluation| evaluation.id.clone())
                .collect()
        };
        assert_eq!(ids(&left), ids(&right));
    }

    #[test]
    fn not_evaluated_freezes_a_firing_latch() {
        let mut evaluation = ConditionEvaluation {
            id: "target:a:test".to_owned(),
            target_id: Some("a".to_owned()),
            kind: "test".to_owned(),
            reason: "fixture".to_owned(),
            severity: Severity::Warning,
            outcome: EvaluationOutcome::NotEvaluated,
            summary: "not evaluated".to_owned(),
            expected: json!(true),
            observed: json!(null),
            evidence_source: "fixture".to_owned(),
            observation_complete: false,
            sustain_runs: 4,
            recovery_runs: 1,
            consecutive_active: 0,
            consecutive_clear: 0,
            lifecycle: ConditionLifecycle::Clear,
            notification_state: AlertDeliveryState::Never,
            first_observed_at: None,
        };
        let mut state = ConditionState::from_evaluation(&evaluation);
        state.lifecycle = ConditionLifecycle::Firing;
        state.consecutive_active = 4;
        state.alert_delivery_state = AlertDeliveryState::Delivered;
        let before = state.clone();
        assert!(
            advance_condition(
                &mut state,
                &mut evaluation,
                "2026-01-01T00:00:00Z",
                "run",
                false,
            )
            .is_none()
        );
        assert_eq!(state.lifecycle, before.lifecycle);
        assert_eq!(state.consecutive_active, before.consecutive_active);
        assert_eq!(state.alert_delivery_state, before.alert_delivery_state);
    }

    /// Latch continuity depends on the condition id and nothing else. Kind,
    /// reason, and summary are presentation: editing any of them must not emit a
    /// transition, restart the counters, or lose when the condition started. See
    /// ADR 0010.
    #[test]
    fn presentation_changes_never_disturb_a_latch() {
        let mut evaluation = ConditionEvaluation {
            id: "target:a:filter:0123456789abcdef".to_owned(),
            target_id: Some("a".to_owned()),
            kind: "required_filter_stale".to_owned(),
            reason: "unrecorded".to_owned(),
            severity: Severity::Warning,
            outcome: EvaluationOutcome::Active,
            summary: "Resolver A has a stale required filter".to_owned(),
            expected: json!({ "enabled": true }),
            observed: json!({ "enabled": true }),
            evidence_source: "fixture".to_owned(),
            observation_complete: true,
            sustain_runs: 2,
            recovery_runs: 1,
            consecutive_active: 0,
            consecutive_clear: 0,
            lifecycle: ConditionLifecycle::Clear,
            notification_state: AlertDeliveryState::Never,
            first_observed_at: None,
        };
        let mut state = ConditionState::from_evaluation(&evaluation);

        // Two active runs to reach the sustain threshold, then delivery, which is
        // what the notification layer records once Pushover confirms.
        assert!(
            advance_condition(
                &mut state,
                &mut evaluation,
                "2026-01-01T00:00:00Z",
                "1",
                false
            )
            .is_none()
        );
        assert!(
            advance_condition(
                &mut state,
                &mut evaluation,
                "2026-01-01T00:05:00Z",
                "2",
                false
            )
            .is_some()
        );
        state.alert_delivery_state = AlertDeliveryState::Delivered;
        assert_eq!(state.lifecycle, ConditionLifecycle::Firing);
        let started = state.first_observed_at.clone();
        assert!(started.is_some());

        // The same condition, still active, now described differently.
        evaluation.kind = "required_filter".to_owned();
        evaluation.reason = "stale".to_owned();
        evaluation.summary = "Resolver A required filter is stale".to_owned();

        let transition = advance_condition(
            &mut state,
            &mut evaluation,
            "2026-01-01T00:10:00Z",
            "3",
            false,
        );

        assert!(transition.is_none(), "renaming must not re-alert");
        assert_eq!(state.lifecycle, ConditionLifecycle::Firing);
        assert_eq!(state.alert_delivery_state, AlertDeliveryState::Delivered);
        // The counter continues from where it was rather than restarting at one.
        assert_eq!(state.consecutive_active, 3);
        assert_eq!(state.first_observed_at, started);
        // The new description is adopted, so state reflects the current release.
        assert_eq!(state.kind, "required_filter");
    }

    /// Recorded from a live run before 0.1.1: one condition id reported
    /// `required_filter_stale` on one run and `required_filter_state_drift` on
    /// the next, so anything grouping by kind saw two conditions where there is
    /// one. The kind names what was checked and may not vary with the outcome;
    /// only the reason may.
    #[test]
    fn one_condition_id_keeps_one_kind_across_outcomes() {
        let target_config = target_config();
        let now = 1_800_000_000;
        let url = "https://filters.invalid/required.txt";
        let policy = PolicyConfig {
            protection_enabled: Some(true),
            upstream_mode: Some("load_balance".to_owned()),
            upstream_dns: Some(vec!["tls://resolver.invalid".to_owned()]),
            filters: vec![RequiredFilter {
                url: url.to_owned(),
                enabled: true,
                maximum_age_hours: Some(72),
            }],
            rewrites: RequiredRewrites {
                enabled: Some(true),
                required: Vec::new(),
            },
        };
        let seen = FilterObservation {
            url: url.to_owned(),
            server_id: 1,
            enabled: true,
            rules_count: 100,
            last_updated: Some("synthetic".to_owned()),
            last_updated_unix_seconds: Some(now - 3_600),
        };
        let stale = FilterObservation {
            last_updated_unix_seconds: Some(now - 72 * 3_600 - 1),
            ..seen.clone()
        };
        let wrong_state = FilterObservation {
            enabled: false,
            ..seen.clone()
        };

        let mut ids = Vec::new();
        let mut reasons = Vec::new();
        for filters in [vec![seen], vec![stale], vec![wrong_state], Vec::new()] {
            let mut report = target("a", 100, 10);
            report.filters = filters;
            let filter =
                super::evaluate_target(&target_config, Some(&policy), &profile(), &report, now)
                    .into_iter()
                    .find(|evaluation| evaluation.id.contains(":filter:"))
                    .expect("a required filter evaluation");
            assert_eq!(filter.kind, "required_filter");
            ids.push(filter.id);
            reasons.push(filter.reason);
        }
        assert!(
            ids.windows(2).all(|pair| pair[0] == pair[1]),
            "ids: {ids:?}"
        );
        reasons.sort();
        reasons.dedup();
        assert_eq!(reasons.len(), 4, "one reason per divergence");

        // The API condition shares one id between the reachable path and every
        // way of failing, so it must share one kind too.
        let mut unavailable = target("a", 100, 10);
        unavailable.status = TargetStatus::Unavailable;
        unavailable.complete = false;
        unavailable.operational = None;
        let api = |report: &TargetReport| {
            super::evaluate_target(&target_config, Some(&policy), &profile(), report, now)
                .into_iter()
                .find(|evaluation| evaluation.id == "target:a:api")
                .expect("an api evaluation")
        };
        let down = api(&unavailable);
        let up = api(&target("a", 100, 10));
        assert_eq!(down.kind, up.kind);
        assert_eq!(down.reason, "unavailable");
        assert_eq!(up.reason, "available");
    }

    /// Also recorded live: clear rows asserted the failure, so a passing filter
    /// 1.9 hours old read as "has a stale required filter" against a 72 hour
    /// limit. A summary states what the outcome is, never what it would have
    /// been.
    #[test]
    fn a_clear_evaluation_reads_as_the_pass() {
        let now = 1_800_000_000;
        let url = "https://filters.invalid/required.txt";
        let policy = PolicyConfig {
            protection_enabled: Some(true),
            upstream_mode: Some("load_balance".to_owned()),
            upstream_dns: Some(vec!["tls://resolver.invalid".to_owned()]),
            filters: vec![RequiredFilter {
                url: url.to_owned(),
                enabled: true,
                maximum_age_hours: Some(72),
            }],
            rewrites: RequiredRewrites {
                enabled: Some(true),
                required: vec![RequiredRewrite {
                    domain: "required.invalid".to_owned(),
                    answer: "192.0.2.10".to_owned(),
                    enabled: true,
                }],
            },
        };
        let mut report = target("a", 100, 10);
        report.filters = vec![FilterObservation {
            url: url.to_owned(),
            server_id: 1,
            enabled: true,
            rules_count: 100,
            last_updated: Some("synthetic".to_owned()),
            last_updated_unix_seconds: Some(now - 3_600),
        }];
        report.rewrites = vec![RewriteObservation {
            domain: "required.invalid".to_owned(),
            answer: "192.0.2.10".to_owned(),
            enabled: true,
        }];

        let evaluations =
            super::evaluate_target(&target_config(), Some(&policy), &profile(), &report, now);

        assert!(!evaluations.is_empty());
        for evaluation in &evaluations {
            assert_eq!(
                evaluation.outcome,
                EvaluationOutcome::Clear,
                "{} should be clear",
                evaluation.id
            );
            let summary = evaluation.summary.to_ascii_lowercase();
            for phrase in [
                "stale",
                "disabled",
                "differ",
                "missing",
                "slow",
                "failed",
                "unsupported",
                "anomalous",
                "wrong",
            ] {
                assert!(
                    !summary.contains(phrase),
                    "clear evaluation {} reads as the failure: {}",
                    evaluation.id,
                    evaluation.summary
                );
            }
        }
    }

    fn target_config() -> TargetConfig {
        TargetConfig {
            id: "a".to_owned(),
            name: "Resolver A".to_owned(),
            base_url: "https://resolver-a.invalid".to_owned(),
            auth: TargetAuth::Basic,
            username: Some("admin".to_owned()),
            password_file: Some("/run/credentials/password".into()),
            policy: Some("home".to_owned()),
            condition_profile: "current".to_owned(),
            allow_insecure_local_http: false,
        }
    }

    fn rewrite_policy(required: Vec<RequiredRewrite>, enabled: bool) -> PolicyConfig {
        PolicyConfig {
            protection_enabled: Some(true),
            upstream_mode: Some("load_balance".to_owned()),
            upstream_dns: Some(vec!["tls://resolver.invalid".to_owned()]),
            filters: Vec::new(),
            rewrites: RequiredRewrites {
                enabled: Some(enabled),
                required,
            },
        }
    }

    fn required_rewrite(domain: &str, answer: &str, enabled: bool) -> RequiredRewrite {
        RequiredRewrite {
            domain: domain.to_owned(),
            answer: answer.to_owned(),
            enabled,
        }
    }

    fn observed_rewrite(domain: &str, answer: &str, enabled: bool) -> RewriteObservation {
        RewriteObservation {
            domain: domain.to_owned(),
            answer: answer.to_owned(),
            enabled,
        }
    }

    fn rewrite_evaluations(
        policy: &PolicyConfig,
        observed: Vec<RewriteObservation>,
    ) -> Vec<ConditionEvaluation> {
        let mut report = target("a", 100, 10);
        report.rewrites = observed;
        super::evaluate_target(
            &target_config(),
            Some(policy),
            &profile(),
            &report,
            1_800_000_000,
        )
        .into_iter()
        .filter(|evaluation| evaluation.kind.contains("rewrite"))
        .collect()
    }

    fn target(id: &str, queries: u64, blocked: u64) -> TargetReport {
        TargetReport {
            id: id.to_owned(),
            name: id.to_owned(),
            status: TargetStatus::Complete,
            complete: true,
            server_version: Some("0.107.78".to_owned()),
            operational: Some(OperationalObservation {
                protection_enabled: true,
                queries,
                blocked,
                blocked_ratio: blocked as f64 / queries as f64,
                average_processing_seconds: 0.01,
                maximum_upstream_seconds: 0.02,
                top_client_share: 0.1,
            }),
            dns: Some(DnsObservation {
                upstream_mode: "load_balance".to_owned(),
                upstream_dns: vec!["tls://resolver.invalid".to_owned()],
            }),
            filtering_enabled: Some(true),
            rewrites_enabled: Some(true),
            upstreams: Vec::new(),
            filters: Vec::new(),
            rewrites: Vec::new(),
            error_kind: None,
            error_detail: None,
        }
    }

    /// 09:59 Amsterdam, so a sample and the 55 minutes before it share one
    /// local hour and land in the same baseline bucket.
    const HOUR_NINE: i64 = 1_800_003_540;

    /// Eight days of one resolver at a steady 1.0 queries per second with a
    /// tenth blocked, sampled every 300 seconds across the 09:00 hour.
    fn target_history(id: &str) -> Vec<TargetSample> {
        let mut samples = Vec::new();
        for day in 0..8i64 {
            for slot in 1..=12i64 {
                let queries = u64::try_from((13 - slot) * 300).expect("queries");
                samples.push(TargetSample {
                    run_id: format!("run-{day}-{slot}"),
                    target_id: id.to_owned(),
                    timestamp: HOUR_NINE - day * 86_400 - slot * 300,
                    queries,
                    blocked: queries / 10,
                });
            }
        }
        samples.sort_by_key(|sample| sample.timestamp);
        samples
    }

    fn behavioral_config() -> BehavioralBaselineConfig {
        BehavioralBaselineConfig {
            target_ids: vec!["a".to_owned()],
            time_zone: "Europe/Amsterdam".to_owned(),
            learning_days: 7,
            minimum_same_hour_samples: 36,
        }
    }

    #[test]
    fn a_target_outside_the_behavioral_group_gets_no_conditions() {
        // ADR 0011: nothing declared, nothing evaluated.
        let evaluations = evaluate_target_behavior(
            &behavioral_config(),
            &profile(),
            &target("b", 3_900, 390),
            &target_history("b"),
            HOUR_NINE,
            9,
        );
        assert!(
            evaluations.is_empty(),
            "target b is not named in target_ids",
        );
    }

    #[test]
    fn one_resolver_losing_blocking_is_visible_per_target() {
        // The dilution case: on the group total a single resolver dropping to
        // zero halves the combined ratio, which is inside normal variation. Per
        // target it is unambiguous. The cumulative blocked counter holds still
        // while queries keep rising, which is how a collapse reads on a
        // monotonic counter.
        let collapsed = evaluate_target_behavior(
            &behavioral_config(),
            &profile(),
            &target("a", 3_900, 360),
            &target_history("a"),
            HOUR_NINE,
            9,
        );
        let ids: Vec<_> = collapsed.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "target:a:query-rate",
                "target:a:blocked-ratio",
                "target:a:blocking-collapsed",
            ],
        );
        assert_eq!(collapsed[0].outcome, EvaluationOutcome::Clear);
        assert_eq!(collapsed[1].outcome, EvaluationOutcome::Active);
        assert_eq!(collapsed[2].outcome, EvaluationOutcome::Active);
        assert_eq!(collapsed[2].severity, Severity::Critical);
        assert_eq!(collapsed[2].target_id.as_deref(), Some("a"));

        let healthy = evaluate_target_behavior(
            &behavioral_config(),
            &profile(),
            &target("a", 3_900, 390),
            &target_history("a"),
            HOUR_NINE,
            9,
        );
        assert_eq!(healthy[1].outcome, EvaluationOutcome::Clear);
        assert_eq!(healthy[2].outcome, EvaluationOutcome::Clear);
    }

    /// Eight days across the 09:00 hour where every window holds `per_window`
    /// queries, so a small value leaves the ratio baseline empty while the rate
    /// baseline is fully populated.
    fn thin_target_history(id: &str, per_window: u64) -> Vec<TargetSample> {
        let mut samples = Vec::new();
        for day in 0..8i64 {
            for slot in 1..=12i64 {
                let queries = u64::try_from(13 - slot).expect("slot") * per_window;
                samples.push(TargetSample {
                    run_id: format!("run-{day}-{slot}"),
                    target_id: id.to_owned(),
                    timestamp: HOUR_NINE - day * 86_400 - slot * 300,
                    queries,
                    blocked: queries / 10,
                });
            }
        }
        samples.sort_by_key(|sample| sample.timestamp);
        samples
    }

    #[test]
    fn a_sparse_ratio_baseline_does_not_suppress_the_query_rate_condition() {
        // Every window is under the 100-query minimum, so no window carries a
        // comparable ratio. The rate baseline is still fully populated and must
        // be judged on its own.
        let history = thin_target_history("a", 60);
        let evaluations = evaluate_target_behavior(
            &behavioral_config(),
            &profile(),
            &target("a", 780, 78),
            &history,
            HOUR_NINE,
            9,
        );
        assert_eq!(evaluations[0].id, "target:a:query-rate");
        assert_ne!(
            evaluations[0].outcome,
            EvaluationOutcome::NotEvaluated,
            "a sparse ratio population must not suppress the rate condition",
        );
        for evaluation in &evaluations[1..3] {
            assert_eq!(evaluation.outcome, EvaluationOutcome::NotEvaluated);
            assert_eq!(evaluation.reason, "baseline_learning");
        }
    }

    #[test]
    fn a_thin_ratio_baseline_is_not_compared_against() {
        // One eligible window is enough for a median and a deviation floor, so
        // without an independent count a critical condition would judge live
        // traffic against a single historical point.
        let mut history = thin_target_history("a", 60);
        let last = history.len() - 1;
        history[last].queries += 5_000;
        history[last].blocked += 500;
        let evaluations = evaluate_target_behavior(
            &behavioral_config(),
            &profile(),
            &target("a", 6_500, 650),
            &history,
            HOUR_NINE,
            9,
        );
        let collapse = &evaluations[2];
        assert_eq!(collapse.id, "target:a:blocking-collapsed");
        assert_eq!(
            collapse.outcome,
            EvaluationOutcome::NotEvaluated,
            "one eligible window is not a baseline",
        );
        assert_eq!(collapse.reason, "baseline_learning");
    }

    #[test]
    fn a_trained_baseline_missing_a_window_is_not_reported_as_learning() {
        // The history is complete; only the latest pair is unusable. Reporting
        // that as learning would hide a resolver whose counter keeps resetting.
        let evaluations = evaluate_target_behavior(
            &behavioral_config(),
            &profile(),
            &target("a", 120, 12),
            &target_history("a"),
            HOUR_NINE,
            9,
        );
        for evaluation in &evaluations {
            assert_eq!(evaluation.outcome, EvaluationOutcome::NotEvaluated);
            assert_eq!(
                evaluation.reason, "rate_window_unavailable",
                "a trained baseline with no current window is not learning",
            );
        }
    }

    #[test]
    fn a_window_below_the_query_minimum_reports_its_own_reason() {
        let evaluations = evaluate_target_behavior(
            &behavioral_config(),
            &profile(),
            &target("a", 3_650, 365),
            &target_history("a"),
            HOUR_NINE,
            9,
        );
        assert_ne!(evaluations[0].outcome, EvaluationOutcome::NotEvaluated);
        for evaluation in &evaluations[1..3] {
            assert_eq!(evaluation.outcome, EvaluationOutcome::NotEvaluated);
            assert_eq!(evaluation.reason, "window_too_small");
        }
    }

    #[test]
    fn a_target_whose_latest_pair_spans_a_reset_is_not_evaluated() {
        // The current reading is below the previous one, so AdGuard reset its
        // counter between them and the elapsed traffic is unknowable.
        let evaluations = evaluate_target_behavior(
            &behavioral_config(),
            &profile(),
            &target("a", 120, 12),
            &target_history("a"),
            HOUR_NINE,
            9,
        );
        assert!(
            evaluations
                .iter()
                .all(|item| item.outcome == EvaluationOutcome::NotEvaluated),
            "a reset must not increment, clear, or resolve a latch",
        );
    }

    fn profile() -> ConditionProfile {
        ConditionProfile {
            authentication_rejected_sustain_runs: 1,
            api_unavailable_sustain_runs: 4,
            invalid_response_sustain_runs: 1,
            unsupported_version_sustain_runs: 1,
            protection_disabled_sustain_runs: 2,
            processing_latency_sustain_runs: 4,
            upstream_latency_sustain_runs: 4,
            policy_drift_sustain_runs: 4,
            behavioral_anomaly_sustain_runs: 4,
            recovery_runs: 1,
            authentication_retry_seconds: 900,
            processing_latency_ms: 500,
            upstream_latency_ms: 750,
        }
    }
}
