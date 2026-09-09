use std::io::Write;

use anyhow::anyhow;
use sentinel_core::{ConditionEvaluation, EvaluationOutcome, RunReport};

use crate::OutputFormat;

pub(crate) fn output_reports(reports: &[RunReport], format: OutputFormat) -> anyhow::Result<()> {
    write_reports(&mut std::io::stdout().lock(), reports, format, false)
}

pub(crate) fn write_reports(
    output: &mut impl Write,
    reports: &[RunReport],
    format: OutputFormat,
    explain: bool,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => {
            let report = reports
                .first()
                .ok_or_else(|| anyhow!("no report is available to render"))?;
            writeln!(output, "{}", serde_json::to_string_pretty(report)?)?;
        }
        OutputFormat::Jsonl => {
            for report in reports {
                writeln!(output, "{}", serde_json::to_string(report)?)?;
            }
        }
        OutputFormat::Human => {
            for (index, report) in reports.iter().enumerate() {
                if index > 0 {
                    writeln!(output)?;
                }
                human_report(output, report, explain)?;
            }
        }
    }
    Ok(())
}

fn human_report(output: &mut impl Write, report: &RunReport, explain: bool) -> anyhow::Result<()> {
    writeln!(
        output,
        "run={} completed={} status={:?} complete_targets={}/{} exit={}",
        report.run_id,
        report.completed_at,
        report.run_status,
        report.complete_targets,
        report.expected_targets,
        report.exit.code,
    )?;
    for target in &report.targets {
        if let Some(observation) = target.operational.as_ref().filter(|_| target.complete) {
            writeln!(
                output,
                "{} [{}]: queries={} blocked={:.1}% processing={:.0}ms upstream_max={:.0}ms",
                target.name,
                target.id,
                observation.queries,
                observation.blocked_ratio * 100.0,
                observation.average_processing_seconds * 1_000.0,
                observation.maximum_upstream_seconds * 1_000.0,
            )?;
        } else {
            writeln!(
                output,
                "{} [{}]: incomplete ({:?}; {})",
                target.name,
                target.id,
                target.status,
                target.error_kind.as_deref().unwrap_or("unrecorded error")
            )?;
        }
        baseline(output, report, Some(&target.id), &target.id)?;
    }
    baseline(output, report, None, "group")?;
    if let Some(aggregate) = &report.aggregate {
        writeln!(
            output,
            "group history: age={}s local_hour={}",
            aggregate.baseline_age_seconds, aggregate.local_hour
        )?;
    }
    for finding in &report.findings {
        writeln!(
            output,
            "finding [{:?}/{:?}] {} {}/{}: {}",
            finding.severity,
            finding.lifecycle,
            finding.id,
            finding.kind,
            finding.reason,
            finding.summary
        )?;
    }
    if report.notifications.is_empty() {
        writeln!(output, "notifications: none originated in this run")?;
    }
    for notification in &report.notifications {
        writeln!(
            output,
            "notification {} [{:?}/{:?}]: conditions={}{}",
            notification.id,
            notification.transition,
            notification.status,
            notification.condition_ids.join(","),
            notification
                .error_class
                .as_ref()
                .map_or_else(String::new, |error| format!(" error={error}")),
        )?;
    }
    for activity in &report.delivery_activity {
        let notification = &activity.notification;
        writeln!(
            output,
            "delivery {:?} attempt={} origin_run={} notification={} [{:?}/{:?}]: conditions={}{}",
            activity.action,
            activity.attempt_id,
            activity.origin_run_id,
            notification.id,
            notification.transition,
            notification.status,
            notification.condition_ids.join(","),
            notification
                .error_class
                .as_ref()
                .map_or_else(String::new, |error| format!(" error={error}")),
        )?;
    }
    if explain {
        for evaluation in &report.evaluations {
            explain_condition(output, evaluation)?;
        }
    }
    Ok(())
}

fn baseline(
    output: &mut impl Write,
    report: &RunReport,
    target_id: Option<&str>,
    subject: &str,
) -> anyhow::Result<()> {
    let population = |kinds: &[&str]| {
        report.evaluations.iter().find(|evaluation| {
            evaluation.target_id.as_deref() == target_id
                && kinds.contains(&evaluation.kind.as_str())
        })
    };
    let rate = population(&["query_rate", "combined_query_rate"]);
    let ratio = population(&["blocked_ratio", "combined_blocked_ratio"]);
    if rate.is_some() || ratio.is_some() {
        writeln!(
            output,
            "baseline [{subject}]: rate={}; ratio={}",
            baseline_status(rate),
            baseline_status(ratio)
        )?;
    }
    Ok(())
}

fn baseline_status(evaluation: Option<&ConditionEvaluation>) -> &'static str {
    let Some(evaluation) = evaluation else {
        return "unrecorded";
    };
    match (evaluation.outcome, evaluation.reason.as_str()) {
        (EvaluationOutcome::NotEvaluated, "baseline_learning") => "learning",
        (EvaluationOutcome::NotEvaluated, "rate_window_unavailable") => "ready, window unavailable",
        (EvaluationOutcome::NotEvaluated, "window_too_small") => "ready, window too small",
        (EvaluationOutcome::NotEvaluated, _) => "not evaluated",
        _ => "ready",
    }
}

fn explain_condition(
    output: &mut impl Write,
    evaluation: &ConditionEvaluation,
) -> anyhow::Result<()> {
    writeln!(
        output,
        "condition {} [{:?}/{:?}]: {} ({})",
        evaluation.id,
        evaluation.outcome,
        evaluation.lifecycle,
        evaluation.summary,
        evaluation.reason
    )?;
    writeln!(output, "  expected: {}", evaluation.expected)?;
    writeln!(output, "  observed: {}", evaluation.observed)?;
    writeln!(
        output,
        "  sustain={}/{} recovery={}/{} notification={:?}{}",
        evaluation.consecutive_active,
        evaluation.sustain_runs,
        evaluation.consecutive_clear,
        evaluation.recovery_runs,
        evaluation.notification_state,
        if evaluation.outcome == EvaluationOutcome::NotEvaluated {
            " (counters held)"
        } else {
            ""
        },
    )?;
    writeln!(
        output,
        "  evidence: {}; observation_complete={}",
        evaluation.evidence_source, evaluation.observation_complete
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sentinel_core::{
        AlertDeliveryState, ConditionLifecycle, DeliveryAction, DeliveryActivity, DnsObservation,
        ExitReport, NotificationReport, NotificationStatus, OperationalObservation, RunHealth,
        RunMode, RunStatus, Severity, TargetReport, TargetStatus, TransitionKind,
    };
    use serde_json::json;

    use super::*;

    fn evaluation(kind: &str, target: Option<&str>, reason: &str) -> ConditionEvaluation {
        ConditionEvaluation {
            id: format!("{}:{kind}", target.unwrap_or("aggregate")),
            target_id: target.map(str::to_owned),
            kind: kind.to_owned(),
            reason: reason.to_owned(),
            severity: Severity::Warning,
            outcome: EvaluationOutcome::NotEvaluated,
            summary: "No comparison is available".to_owned(),
            expected: json!({"minimum_same_hour_windows": 8}),
            observed: json!({"same_hour_windows": 3, "baseline_ready": false, "window_available": true}),
            evidence_source: "synthetic counter windows".to_owned(),
            observation_complete: false,
            sustain_runs: 4,
            recovery_runs: 2,
            consecutive_active: 2,
            consecutive_clear: 0,
            lifecycle: ConditionLifecycle::Pending,
            notification_state: AlertDeliveryState::Never,
            first_observed_at: None,
        }
    }

    fn report(evaluations: Vec<ConditionEvaluation>) -> RunReport {
        RunReport {
            schema_version: 1,
            run_id: "synthetic-run".to_owned(),
            mode: RunMode::DryRun,
            started_at: "2026-01-01T00:00:00Z".to_owned(),
            completed_at: "2026-01-01T00:00:01Z".to_owned(),
            config_sha256: "0".repeat(64),
            state_schema_version: 1,
            run_status: RunStatus::Complete,
            expected_targets: 1,
            complete_targets: 1,
            minimum_complete_targets: 1,
            targets: vec![TargetReport {
                id: "resolver-a".to_owned(),
                name: "Resolver A".to_owned(),
                status: TargetStatus::Complete,
                complete: true,
                server_version: Some("0.107.78".to_owned()),
                operational: Some(OperationalObservation {
                    protection_enabled: true,
                    queries: 1000,
                    blocked: 200,
                    blocked_ratio: 0.2,
                    average_processing_seconds: 0.01,
                    maximum_upstream_seconds: 0.02,
                    top_client_share: 0.5,
                }),
                dns: Some(DnsObservation {
                    upstream_mode: "load_balance".to_owned(),
                    upstream_dns: vec!["192.0.2.53".to_owned()],
                }),
                filtering_enabled: Some(true),
                rewrites_enabled: Some(true),
                upstreams: vec![],
                filters: vec![],
                rewrites: vec![],
                error_kind: None,
                error_detail: None,
            }],
            aggregate: None,
            evaluations,
            findings: vec![],
            transitions: vec![],
            notifications: vec![],
            delivery_activity: vec![],
            health: RunHealth {
                minimum_complete_targets: 1,
                complete_targets: 1,
                met: true,
                issues: vec![],
            },
            exit: ExitReport {
                code: 0,
                reason: "observation completed".to_owned(),
            },
        }
    }

    fn human(report: &RunReport, explain: bool) -> String {
        let mut output = Vec::new();
        write_reports(
            &mut output,
            std::slice::from_ref(report),
            OutputFormat::Human,
            explain,
        )
        .unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn trained_rate_does_not_hide_learning_ratio_or_an_incomplete_target() {
        let mut rate = evaluation("combined_query_rate", None, "within_baseline");
        rate.outcome = EvaluationOutcome::Clear;
        let mut report = report(vec![
            rate,
            evaluation("combined_blocked_ratio", None, "baseline_learning"),
        ]);
        report.targets.push(TargetReport::incomplete(
            "resolver-b",
            "Resolver B",
            TargetStatus::Unavailable,
            "transport",
            "synthetic connection failure",
        ));
        report.expected_targets = 2;
        report.run_status = RunStatus::Partial;
        let output = human(&report, false);
        assert!(output.contains("Resolver A [resolver-a]: queries=1000 blocked=20.0%"));
        assert!(output.contains("Resolver B [resolver-b]: incomplete (Unavailable; transport)"));
        assert!(output.contains("baseline [group]: rate=ready; ratio=learning"));
        assert!(!output.contains("condition aggregate:"));
        assert!(!output.contains("queries=0"));
    }

    #[test]
    fn learning_and_counter_reset_evidence_remain_distinct() {
        let learning = evaluation("query_rate", Some("resolver-a"), "baseline_learning");
        let mut reset = learning.clone();
        reset.reason = "rate_window_unavailable".to_owned();
        reset.observed =
            json!({"same_hour_windows": 12, "baseline_ready": true, "window_available": false});
        let learning_output = human(&report(vec![learning]), true);
        let reset_output = human(&report(vec![reset]), true);
        assert!(learning_output.contains("rate=learning; ratio=unrecorded"));
        assert!(learning_output.contains("\"minimum_same_hour_windows\":8"));
        assert!(learning_output.contains("\"same_hour_windows\":3"));
        assert!(reset_output.contains("rate=ready, window unavailable"));
        assert!(reset_output.contains("(rate_window_unavailable)"));
        assert!(reset_output.contains("\"window_available\":false"));
        assert!(
            reset_output.contains("sustain=2/4 recovery=0/2 notification=Never (counters held)")
        );
    }

    #[test]
    fn explain_shows_active_measurement_threshold_and_recovery_progress() {
        let mut condition = evaluation("query_rate", Some("resolver-a"), "above_baseline");
        condition.outcome = EvaluationOutcome::Active;
        condition.summary = "Resolver A query rate is anomalously high".to_owned();
        condition.observation_complete = true;
        condition.expected = json!({"maximum_queries_per_second": 10.0});
        condition.observed = json!({"queries_per_second": 15.0, "window_seconds": 60});
        let active = human(&report(vec![condition.clone()]), true);
        assert!(active.contains("[Active/Pending]"));
        assert!(active.contains("expected: {\"maximum_queries_per_second\":10.0}"));
        assert!(active.contains("\"queries_per_second\":15.0"));
        assert!(!active.contains("counters held"));
        condition.outcome = EvaluationOutcome::Clear;
        condition.reason = "within_baseline".to_owned();
        condition.summary = "Resolver A query rate is within baseline".to_owned();
        condition.consecutive_active = 0;
        condition.consecutive_clear = 1;
        condition.lifecycle = ConditionLifecycle::Firing;
        condition.notification_state = AlertDeliveryState::Delivered;
        let recovery = human(&report(vec![condition]), true);
        assert!(recovery.contains("[Clear/Firing]"));
        assert!(recovery.contains("sustain=0/4 recovery=1/2 notification=Delivered"));
    }

    #[test]
    fn low_traffic_and_ambiguous_delivery_are_visible_without_explain() {
        let mut report = report(vec![evaluation(
            "blocked_ratio",
            Some("resolver-a"),
            "window_too_small",
        )]);
        report.notifications.push(NotificationReport {
            id: "notification-a".to_owned(),
            transition: TransitionKind::Alert,
            condition_ids: vec!["resolver-a:query_rate".to_owned()],
            status: NotificationStatus::Unknown,
            remote_request_id: None,
            error_class: Some("timeout".to_owned()),
        });
        let output = human(&report, false);
        assert!(output.contains("rate=unrecorded; ratio=ready, window too small"));
        assert!(output.contains("notification notification-a [Alert/Unknown]: conditions=resolver-a:query_rate error=timeout"));
    }

    #[test]
    fn structured_output_preserves_the_report() {
        let report = report(vec![]);
        for format in [OutputFormat::Json, OutputFormat::Jsonl] {
            let mut output = Vec::new();
            write_reports(&mut output, std::slice::from_ref(&report), format, false).unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(parsed, serde_json::to_value(&report).unwrap());
        }
    }

    #[test]
    fn current_delivery_failure_points_to_older_notification_and_attempt() {
        let mut report = report(vec![]);
        report.run_id = "current-run".to_owned();
        report.exit.code = 4;
        report.exit.reason = "notification delivery was not confirmed".to_owned();
        for (action, status, error, attempt) in [
            (
                DeliveryAction::Attempt,
                NotificationStatus::Retryable,
                "connection_failed",
                "attempt-a",
            ),
            (
                DeliveryAction::Recovered,
                NotificationStatus::Unknown,
                "process_interrupted_after_possible_transmission",
                "attempt-b",
            ),
        ] {
            report.delivery_activity.push(DeliveryActivity {
                attempt_id: attempt.to_owned(),
                origin_run_id: "older-run".to_owned(),
                action,
                notification: NotificationReport {
                    id: format!("notification-{attempt}"),
                    transition: TransitionKind::Alert,
                    condition_ids: vec!["resolver-a:query_rate".to_owned()],
                    status,
                    remote_request_id: None,
                    error_class: Some(error.to_owned()),
                },
            });
        }
        let output = human(&report, false);
        assert!(output.contains("exit=4"));
        assert!(output.contains("notifications: none originated in this run"));
        assert!(output.contains("delivery Attempt attempt=attempt-a origin_run=older-run notification=notification-attempt-a [Alert/Retryable]"));
        assert!(output.contains("delivery Recovered attempt=attempt-b origin_run=older-run notification=notification-attempt-b [Alert/Unknown]"));
        assert!(output.contains(
            "conditions=resolver-a:query_rate error=process_interrupted_after_possible_transmission"
        ));
        assert!(report.notifications.is_empty());
    }
}
