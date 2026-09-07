use rusqlite::{Connection, params};
use sentinel_core::{
    AlertDeliveryState, ConditionEvaluation, ConditionLifecycle, ConditionTransition, Config,
    NotificationStatus, OutboxMessage, RunMode, RunReport, TransitionKind,
};
use tempfile::tempdir;

use super::{NotificationAttemptOutcome, StateStore, build_outbox, schema};

const START: &str = "2026-01-01T00:00:00Z";
const CUTOFF: &str = "2025-12-01T00:00:00Z";

fn config() -> Config {
    serde_json::from_value(serde_json::json!({"schema_version": 1, "targets": []})).expect("config")
}

fn evaluation(id: &str, active: bool) -> ConditionEvaluation {
    serde_json::from_value(serde_json::json!({
        "id": id, "target_id": null, "kind": "synthetic", "reason": "synthetic",
        "severity": "warning", "outcome": if active { "active" } else { "clear" },
        "summary": format!("{id} is {}", if active { "active" } else { "clear" }),
        "expected": null, "observed": null, "evidence_source": "synthetic",
        "observation_complete": true, "sustain_runs": 1, "recovery_runs": 1,
        "consecutive_active": 0, "consecutive_clear": 0, "lifecycle": "clear",
        "notification_state": "never", "first_observed_at": null
    }))
    .expect("evaluation")
}

fn commit(
    store: &mut StateStore,
    id: &str,
    second: u32,
    evaluations: Vec<ConditionEvaluation>,
) -> Vec<OutboxMessage> {
    let mut report = empty_report();
    report.run_id = id.to_owned();
    report.started_at = format!("2026-01-01T00:00:{second:02}Z");
    report.completed_at.clone_from(&report.started_at);
    report.evaluations = evaluations;
    store
        .commit_run(
            &mut report,
            &config(),
            1_767_225_600 + i64::from(second),
            CUTOFF,
            false,
        )
        .expect("commit run")
}

fn deliver(store: &mut StateStore, message: &OutboxMessage, second: u32) {
    let now = format!("2026-01-01T00:00:{second:02}Z");
    let run_id = store.load_reports(1, None).expect("current run")[0]
        .run_id
        .clone();
    let attempt = store
        .begin_notification_attempt(message, &now, &run_id)
        .expect("begin delivery");
    store
        .record_notification_attempt(
            &attempt,
            &now,
            &NotificationAttemptOutcome::Delivered {
                http_status: 200,
                remote_request_id: "synthetic-request".to_owned(),
            },
        )
        .expect("deliver");
}

fn retry(store: &mut StateStore, message: &OutboxMessage, second: u32) {
    let now = format!("2026-01-01T00:00:{second:02}Z");
    let run_id = store.load_reports(1, None).expect("current run")[0]
        .run_id
        .clone();
    let attempt = store
        .begin_notification_attempt(message, &now, &run_id)
        .expect("begin retryable delivery");
    store
        .record_notification_attempt(
            &attempt,
            &now,
            &NotificationAttemptOutcome::Retryable {
                http_status: Some(429),
                error_class: "synthetic-rate-limit".to_owned(),
            },
        )
        .expect("retryable");
}

fn legacy(path: &std::path::Path) -> Connection {
    let connection = Connection::open(path).expect("legacy database");
    connection
        .execute_batch(schema::V1)
        .expect("released schema");
    connection.execute("INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (1, 'initial', ?1, ?2)",
        params![schema::checksum(1), START]).expect("released migration checksum");
    legacy_run(&connection, "legacy-run", "live", START);
    connection
}

fn legacy_run(connection: &Connection, id: &str, mode: &str, timestamp: &str) {
    connection.execute("INSERT INTO runs(id, started_at, completed_at, mode, config_sha256, status, expected_targets, complete_targets, minimum_targets, exit_code)
        VALUES (?1, ?2, ?2, ?3, 'sha256:synthetic', 'complete', 0, 0, 0, 0)", params![id, timestamp, mode]).expect("legacy run");
}

fn legacy_batch(connection: &Connection, status: &str, members: &[(&str, String)], body: &str) {
    connection.execute("INSERT INTO notification_outbox(id, run_id, transition, title, message, priority, status, created_at)
        VALUES ('legacy-alert', 'legacy-run', 'alert', 'Synthetic', ?1, 0, ?2, ?3)", params![body, status, START]).expect("legacy outbox");
    for (id, summary) in members {
        let mut evidence = evaluation(id, true);
        evidence.summary.clone_from(summary);
        evidence.lifecycle = ConditionLifecycle::Firing;
        evidence.notification_state = if status == "delivered" {
            AlertDeliveryState::Delivered
        } else {
            AlertDeliveryState::Pending
        };
        connection.execute("INSERT INTO condition_evaluations(run_id, condition_id, outcome, expected_json, observed_json, evidence_json, complete)
            VALUES ('legacy-run', ?1, 'active', 'null', 'null', ?2, 1)", params![id, serde_json::to_string(&evidence).expect("evidence")]).expect("legacy evaluation");
        connection.execute("INSERT INTO condition_state(condition_id, target_id, kind, severity, lifecycle, first_observed_at, last_observed_at, active_count, clear_count, alert_delivery_state, last_transition_run)
            VALUES (?1, NULL, 'synthetic', 'warning', 'firing', ?2, ?2, 1, 0, ?3, 'legacy-run')",
            params![id, START, if status == "delivered" { "delivered" } else { "pending" }]).expect("legacy latch");
        connection.execute("INSERT INTO notification_conditions(notification_id, condition_id) VALUES ('legacy-alert', ?1)", [id]).expect("legacy member");
    }
    if status == "delivered" {
        connection.execute("UPDATE notification_outbox SET delivered_at = ?1, remote_request_id = 'synthetic-request' WHERE id = 'legacy-alert'", [START]).expect("legacy confirmation");
        connection.execute("INSERT INTO notification_attempts(id, notification_id, started_at, completed_at, outcome, http_status, remote_request_id)
            VALUES ('legacy-attempt', 'legacy-alert', ?1, ?1, 'delivered', 200, 'synthetic-request')", [START]).expect("legacy delivered attempt");
    }
}

fn empty_report() -> RunReport {
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "run_id": "synthetic-run",
        "mode": "live",
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:00:01Z",
        "config_sha256": "sha256:synthetic",
        "state_schema_version": 1,
        "run_status": "complete",
        "expected_targets": 0,
        "complete_targets": 0,
        "minimum_complete_targets": 0,
        "targets": [], "aggregate": null, "evaluations": [], "findings": [],
        "transitions": [], "notifications": [],
        "health": {"minimum_complete_targets": 0, "complete_targets": 0,
                   "met": true, "issues": []},
        "exit": {"code": 0, "reason": "observation completed"}
    }))
    .expect("synthetic report")
}

#[test]
fn a_writer_excludes_another_writer_but_allows_reports() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("state.sqlite");
    let writer = StateStore::open(&path).expect("first writer");
    let second = StateStore::open(&path).expect_err("overlapping writer must fail");
    assert!(second.to_string().contains("already in use"));
    let reader = StateStore::open_existing(&path).expect("concurrent reader");
    assert!(reader.load_reports(1, None).expect("reports").is_empty());
    drop(reader);
    drop(writer);
    StateStore::open(&path).expect("ownership released");
}

#[cfg(unix)]
#[test]
fn a_symlink_alias_cannot_bypass_writer_ownership() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("state.sqlite");
    let alias = directory.path().join("alias.sqlite");
    let _writer = StateStore::open(&path).expect("writer");
    std::os::unix::fs::symlink(&path, &alias).expect("alias");
    assert!(StateStore::open(&alias).is_err());
}

#[test]
fn every_batched_condition_is_visible_in_its_own_message() {
    let transitions: Vec<_> = (0..30)
        .map(|index| ConditionTransition {
            condition_id: format!("condition-{index:02}"),
            kind: TransitionKind::Alert,
            summary: format!("Condition {index:02}: {}", "synthetic finding ".repeat(8)),
        })
        .collect();
    let batches = build_outbox(&empty_report(), &transitions, false);
    let mut delivered = Vec::new();
    for batch in &batches {
        assert!(batch.message.chars().count() <= 1_024);
        for condition_id in &batch.condition_ids {
            let transition = transitions
                .iter()
                .find(|transition| &transition.condition_id == condition_id)
                .expect("known transition");
            assert!(batch.message.contains(&transition.summary));
            delivered.push(condition_id.as_str());
        }
    }
    let expected: Vec<_> = transitions
        .iter()
        .map(|transition| transition.condition_id.as_str())
        .collect();
    assert_eq!(delivered, expected);
    assert!(batches.len() > 1);
}

#[test]
fn an_oversized_unicode_summary_is_explicitly_abbreviated() {
    let transitions = vec![ConditionTransition {
        condition_id: "condition".to_owned(),
        kind: TransitionKind::Alert,
        summary: "synthetic échec 🌍 ".repeat(200),
    }];
    let batches = build_outbox(&empty_report(), &transitions, false);
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].condition_ids, ["condition"]);
    assert!(batches[0].message.chars().count() <= 1_024);
    assert!(batches[0].message.ends_with("[truncated; see report]"));
}

#[test]
fn explicit_migration_preserves_a_private_v1_backup_and_quarantines_unsent_history() {
    for status in ["pending", "retryable"] {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("state.sqlite");
        let connection = legacy(&path);
        legacy_batch(
            &connection,
            status,
            &[("condition", "condition is active".to_owned())],
            "- condition is active",
        );
        connection.execute("INSERT INTO target_observations(run_id, target_id, target_name, status, complete, queries, blocked)
            VALUES ('legacy-run', 'resolver', 'Resolver', 'complete', 1, ?1, ?1)", [i64::MAX]).expect("legacy counter");
        drop(connection);
        assert!(matches!(
            StateStore::open(&path),
            Err(super::StoreError::MigrationRequired)
        ));
        assert!(matches!(
            StateStore::open_existing(&path),
            Err(super::StoreError::MigrationRequired)
        ));
        let (mut store, backup) = StateStore::migrate(&path).expect("migrate");
        let backup = backup.expect("backup before upgrade");
        let saved = Connection::open(&backup).expect("backup connection");
        schema::validate(&saved, 1).expect("untouched v1 backup");
        assert_eq!(
            saved
                .query_row("SELECT status FROM notification_outbox", [], |row| row
                    .get::<_, String>(
                    0
                ))
                .expect("old status"),
            status
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&backup)
                    .expect("backup metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(
            store
                .load_target_samples(0)
                .expect("ambiguous v1 saturation excluded from rate samples")
                .is_empty()
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT queries FROM target_observations", [], |row| row
                    .get::<_, String>(
                    0
                ))
                .expect("preserved historical count"),
            i64::MAX.to_string()
        );
        assert!(
            store
                .pending_outbox("2026-01-02T00:00:00Z")
                .expect("no replay")
                .is_empty()
        );
        let reports = store.load_reports(1, None).expect("migrated report");
        assert_eq!(
            reports[0].notifications[0].status,
            NotificationStatus::Unknown
        );
        assert_eq!(
            reports[0].evaluations[0].notification_state,
            AlertDeliveryState::Unknown
        );
        assert!(
            commit(
                &mut store,
                "recovery",
                1,
                vec![evaluation("condition", false)]
            )
            .is_empty()
        );
        drop(store);
        assert!(
            StateStore::migrate(&path)
                .expect("idempotent migration")
                .1
                .is_none()
        );
    }
}

#[test]
fn migration_never_assigns_a_truncated_prefix_to_a_later_member() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("state.sqlite");
    let connection = legacy(&path);
    let long = "x".repeat(1_100);
    let prefix = "x".repeat(1_022);
    legacy_batch(
        &connection,
        "delivered",
        &[("a", long), ("b", prefix.clone())],
        &format!("- {prefix}"),
    );
    drop(connection);
    let (mut store, _) = StateStore::migrate(&path).expect("migrate");
    let reports = store.load_reports(1, None).expect("report");
    assert_eq!(
        reports[0].notifications[0].status,
        NotificationStatus::Unknown
    );
    assert!(
        reports[0]
            .evaluations
            .iter()
            .all(|evaluation| evaluation.notification_state == AlertDeliveryState::Unknown)
    );
    assert!(
        commit(
            &mut store,
            "recovery",
            1,
            vec![evaluation("a", false), evaluation("b", false)]
        )
        .is_empty()
    );
}

#[test]
fn migration_keeps_proven_visible_delivery_for_the_current_episode() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("state.sqlite");
    let connection = legacy(&path);
    legacy_batch(
        &connection,
        "delivered",
        &[("condition", "condition is active".to_owned())],
        "- condition is active",
    );
    drop(connection);
    let (mut store, _) = StateStore::migrate(&path).expect("migrate");
    let resolution = commit(
        &mut store,
        "recovery",
        1,
        vec![evaluation("condition", false)],
    );
    assert_eq!(resolution.len(), 1);
    assert_eq!(resolution[0].transition, TransitionKind::Resolution);
    deliver(&mut store, &resolution[0], 2);
    assert_eq!(
        store.load_reports(1, None).expect("report")[0].evaluations[0].notification_state,
        AlertDeliveryState::Resolved
    );
}

#[test]
fn invalid_legacy_state_rolls_back_every_migration_change() {
    for fault in ["mixed_mode", "timestamp", "foreign_key"] {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("state.sqlite");
        let connection = legacy(&path);
        match fault {
            "mixed_mode" => legacy_run(&connection, "dry", "dry_run", START),
            "timestamp" => {
                connection
                    .execute("UPDATE runs SET completed_at = 'invalid'", [])
                    .expect("fault");
            }
            _ => {
                connection.execute_batch("PRAGMA foreign_keys = OFF; INSERT INTO notification_conditions(notification_id, condition_id) VALUES ('absent', 'condition');").expect("fault");
            }
        }
        drop(connection);
        assert!(StateStore::migrate(&path).is_err(), "{fault}");
        let saved = Connection::open(&path).expect("failed migration source");
        schema::validate(&saved, 1).expect("still v1");
        assert_eq!(saved.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 'state_identity' OR name LIKE '%_v2'", [], |row| row.get::<_, i64>(0)).expect("new tables"), 0);
        assert_eq!(saved.query_row("SELECT type FROM pragma_table_info('target_observations') WHERE name = 'queries'", [], |row| row.get::<_, String>(0)).expect("old type"), "INTEGER");
    }
}

#[test]
fn disk_full_initialization_and_migration_are_atomic() {
    let mut connection = Connection::open_in_memory().expect("memory database");
    connection
        .execute_batch("PRAGMA page_size = 512; PRAGMA max_page_count = 2;")
        .expect("small disk limit");
    assert!(schema::initialize(&mut connection).is_err());
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .expect("version"),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .expect("tables"),
        0
    );
    connection
        .execute_batch("PRAGMA max_page_count = 10000;")
        .expect("restore capacity");
    schema::initialize(&mut connection).expect("retry fresh initialization");

    let directory = tempdir().expect("tempdir");
    let mut legacy = legacy(&directory.path().join("state.sqlite"));
    let pages: i64 = legacy
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .expect("page count");
    legacy
        .pragma_update(None, "max_page_count", pages)
        .expect("no headroom");
    assert!(schema::migrate(&mut legacy).is_err());
    schema::validate(&legacy, 1).expect("migration rolled back");
    assert_eq!(
        legacy
            .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
            .expect("foreign keys"),
        1
    );
    legacy
        .pragma_update(None, "max_page_count", 10000)
        .expect("restore migration capacity");
    schema::migrate(&mut legacy).expect("retry migration");
}

#[test]
fn a_failed_run_commit_preserves_the_callers_report_latches_and_mode() {
    let directory = tempdir().expect("tempdir");
    let mut store = StateStore::open(&directory.path().join("state.sqlite")).expect("store");
    store.connection.execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON notification_outbox BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END;").expect("fault trigger");
    let mut report = empty_report();
    report.evaluations = vec![evaluation("condition", true)];
    let before = serde_json::to_value(&report).expect("before");
    assert!(
        store
            .commit_run(&mut report, &config(), 0, CUTOFF, false)
            .is_err()
    );
    assert_eq!(serde_json::to_value(&report).expect("after"), before);
    assert_eq!(store.connection.query_row("SELECT (SELECT COUNT(*) FROM runs) + (SELECT COUNT(*) FROM condition_state) + (SELECT COUNT(*) FROM state_identity)", [], |row| row.get::<_, i64>(0)).expect("no partial writes"), 0);
    store
        .connection
        .execute_batch("DROP TRIGGER reject_outbox;")
        .expect("remove fault");
    report.mode = RunMode::DryRun;
    store
        .commit_run(&mut report, &config(), 0, CUTOFF, true)
        .expect("retry with unused mode");
}

#[test]
fn a_failed_delivery_result_commit_remains_in_flight_then_recovers_as_unknown() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("state.sqlite");
    let mut store = StateStore::open(&path).expect("store");
    let messages = commit(&mut store, "alert", 1, vec![evaluation("condition", true)]);
    let attempt = store
        .begin_notification_attempt(&messages[0], "2026-01-01T00:00:02Z", "alert")
        .expect("durable intent");
    store.connection.execute_batch("CREATE TRIGGER reject_delivery BEFORE UPDATE ON condition_state BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END;").expect("fault trigger");
    assert!(
        store
            .record_notification_attempt(
                &attempt,
                "2026-01-01T00:00:03Z",
                &NotificationAttemptOutcome::Delivered {
                    http_status: 200,
                    remote_request_id: "synthetic-request".to_owned(),
                }
            )
            .is_err()
    );
    assert_eq!(
        store.load_reports(1, None).expect("report")[0].notifications[0].status,
        NotificationStatus::InFlight
    );
    assert_eq!(
        store
            .connection
            .query_row("SELECT outcome FROM notification_attempts", [], |row| {
                row.get::<_, String>(0)
            })
            .expect("attempt"),
        "in_flight"
    );
    store
        .connection
        .execute_batch("DROP TRIGGER reject_delivery;")
        .expect("remove fault");
    drop(store);
    let mut store = StateStore::open(&path).expect("restart");
    assert_eq!(
        store
            .recover_interrupted_attempts("2026-01-01T00:00:04Z")
            .expect("recover")
            .len(),
        1
    );
    let report = store
        .load_reports(1, None)
        .expect("unknown report")
        .remove(0);
    assert_eq!(report.notifications[0].status, NotificationStatus::Unknown);
    assert_eq!(
        report.evaluations[0].notification_state,
        AlertDeliveryState::Unknown
    );
    assert!(
        store
            .pending_outbox("2026-01-02T00:00:00Z")
            .expect("no replay")
            .is_empty()
    );
    assert!(
        store
            .recover_interrupted_attempts("2026-01-01T00:00:05Z")
            .expect("idempotent recovery")
            .is_empty()
    );
}

#[test]
fn recurrence_cancels_an_old_resolution_before_the_new_alert_fires() {
    let directory = tempdir().expect("tempdir");
    let mut store = StateStore::open(&directory.path().join("state.sqlite")).expect("store");
    let alert = commit(
        &mut store,
        "first-alert",
        1,
        vec![evaluation("condition", true)],
    )
    .remove(0);
    deliver(&mut store, &alert, 2);
    let resolution = commit(
        &mut store,
        "first-clear",
        3,
        vec![evaluation("condition", false)],
    )
    .remove(0);
    retry(&mut store, &resolution, 4);
    let mut recurring = evaluation("condition", true);
    recurring.sustain_runs = 2;
    assert!(commit(&mut store, "new-pending", 5, vec![recurring.clone()]).is_empty());
    assert!(
        store
            .pending_outbox("2026-01-01T00:00:09Z")
            .expect("old resolution gone")
            .is_empty()
    );
    assert!(
        store
            .begin_notification_attempt(&resolution, "2026-01-01T00:00:09Z", "new-pending")
            .is_err()
    );
    let new_alert = commit(&mut store, "new-alert", 10, vec![recurring]).remove(0);
    deliver(&mut store, &new_alert, 11);
    let new_resolution = commit(
        &mut store,
        "new-clear",
        12,
        vec![evaluation("condition", false)],
    )
    .remove(0);
    assert_eq!(new_resolution.transition, TransitionKind::Resolution);
    let reports = store.load_reports(10, None).expect("history");
    assert_eq!(
        reports
            .iter()
            .find(|report| report.run_id == "first-clear")
            .expect("first clear")
            .notifications[0]
            .status,
        NotificationStatus::Cancelled
    );
}

#[test]
fn partial_batch_recovery_preserves_original_evidence_and_survivor_backoff() {
    let directory = tempdir().expect("tempdir");
    let mut store = StateStore::open(&directory.path().join("state.sqlite")).expect("store");
    let batch = commit(
        &mut store,
        "alert",
        1,
        vec![evaluation("a", true), evaluation("b", true)],
    )
    .remove(0);
    retry(&mut store, &batch, 2);
    let mut changed = evaluation("b", true);
    changed.summary = "b has a different current reading".to_owned();
    commit(
        &mut store,
        "partial-recovery",
        3,
        vec![evaluation("a", false), changed],
    );
    assert!(
        store
            .pending_outbox("2026-01-01T00:00:06.999999999Z")
            .expect("backoff")
            .is_empty()
    );
    let replacement = store
        .pending_outbox("2026-01-01T00:00:07Z")
        .expect("survivor")
        .remove(0);
    assert_eq!(replacement.condition_ids, ["b"]);
    assert_eq!(replacement.message, "- b is active");
    deliver(&mut store, &replacement, 7);
    let history = store.load_reports(10, None).expect("history");
    let original_run = history
        .iter()
        .find(|report| report.run_id == "alert")
        .expect("original run");
    assert_eq!(original_run.transitions.len(), 2);
    assert_eq!(original_run.notifications.len(), 2);
    let original = original_run
        .notifications
        .iter()
        .find(|notification| notification.id == batch.id)
        .expect("cancelled batch");
    assert_eq!(original.status, NotificationStatus::Cancelled);
    assert_eq!(original.condition_ids, ["a", "b"]);
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT message FROM notification_outbox WHERE id = ?1",
                [&batch.id],
                |row| row.get::<_, String>(0)
            )
            .expect("original payload"),
        batch.message
    );
    assert_eq!(
        original_run
            .evaluations
            .iter()
            .find(|evaluation| evaluation.id == "b")
            .expect("b")
            .notification_state,
        AlertDeliveryState::Delivered
    );
}

#[test]
fn unknown_delivery_evidence_survives_retention_and_mode_survives_an_empty_history() {
    let directory = tempdir().expect("tempdir");
    let mut store = StateStore::open(&directory.path().join("state.sqlite")).expect("store");
    let message = commit(&mut store, "alert", 1, vec![evaluation("condition", true)]).remove(0);
    let attempt = store
        .begin_notification_attempt(&message, "2026-01-01T00:00:02Z", "alert")
        .expect("attempt");
    store
        .record_notification_attempt(
            &attempt,
            "2026-01-01T00:00:03Z",
            &NotificationAttemptOutcome::Unknown {
                error_class: "synthetic ambiguity".to_owned(),
            },
        )
        .expect("unknown");
    commit(&mut store, "ordinary", 4, vec![]);
    let transaction = store.connection.transaction().expect("retention");
    super::prune_runs(&transaction, "2026-02-01T00:00:00.000000000Z").expect("prune");
    transaction.commit().expect("commit retention");
    let history = store.load_reports(10, None).expect("retained evidence");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].run_id, "alert");
    assert_eq!(
        history[0].notifications[0].status,
        NotificationStatus::Unknown
    );
    assert_eq!(
        store
            .connection
            .query_row("SELECT COUNT(*) FROM notification_attempts", [], |row| row
                .get::<_, i64>(
                0
            ))
            .expect("retained attempt"),
        1
    );
    // Simulate operator-managed historical removal: mode is durable metadata,
    // independent of retention and condition history.
    store
        .connection
        .execute("DELETE FROM runs", [])
        .expect("remove history");
    assert!(store.ensure_run_mode(RunMode::DryRun).is_err());
    store.ensure_run_mode(RunMode::Live).expect("same mode");
}

#[test]
fn fractional_timestamps_order_filter_and_reject_clock_regression() {
    let directory = tempdir().expect("tempdir");
    let mut store = StateStore::open(&directory.path().join("state.sqlite")).expect("store");
    for (id, timestamp) in [
        ("whole", START),
        ("fraction", "2026-01-01T00:00:00.1Z"),
        ("tie", "2026-01-01T01:00:00.100000000+01:00"),
    ] {
        let mut report = empty_report();
        report.run_id = id.to_owned();
        report.started_at = timestamp.to_owned();
        report.completed_at = timestamp.to_owned();
        store
            .commit_run(&mut report, &config(), 0, CUTOFF, false)
            .expect("timestamp commit");
    }
    let reports = store
        .load_reports(10, Some("2026-01-01T01:00:00.1+01:00"))
        .expect("since by instant");
    assert_eq!(
        reports
            .iter()
            .map(|report| report.run_id.as_str())
            .collect::<Vec<_>>(),
        ["tie", "fraction"]
    );
    let mut report = empty_report();
    report.run_id = "regressed".to_owned();
    report.started_at = "2026-01-01T00:00:00.099999999Z".to_owned();
    assert!(
        store
            .commit_run(&mut report, &config(), 0, CUTOFF, false)
            .is_err()
    );
    assert_eq!(store.load_reports(10, None).expect("unchanged").len(), 3);
}

#[test]
fn migration_requires_the_original_delivery_acknowledgment() {
    for fault in ["missing_request", "missing_attempt"] {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("state.sqlite");
        let connection = legacy(&path);
        legacy_batch(
            &connection,
            "delivered",
            &[("condition", "condition is active".to_owned())],
            "- condition is active",
        );
        if fault == "missing_request" {
            connection
                .execute("UPDATE notification_outbox SET remote_request_id = ''", [])
                .expect("missing acknowledgment");
        } else {
            connection
                .execute("DELETE FROM notification_attempts", [])
                .expect("missing attempt");
        }
        drop(connection);
        let (mut store, _) = StateStore::migrate(&path).expect("migrate");
        assert_eq!(
            store.load_reports(1, None).expect("report")[0].notifications[0].status,
            NotificationStatus::Unknown,
            "{fault}"
        );
        assert!(
            commit(
                &mut store,
                "recovery",
                1,
                vec![evaluation("condition", false)]
            )
            .is_empty()
        );
    }
}

#[test]
fn migration_does_not_restore_resolved_after_quarantining_a_legacy_resolution() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("state.sqlite");
    let connection = legacy(&path);
    legacy_batch(
        &connection,
        "delivered",
        &[("condition", "condition is clear".to_owned())],
        "- condition is clear",
    );
    let mut evidence = evaluation("condition", false);
    evidence.notification_state = AlertDeliveryState::Resolved;
    connection
        .execute(
            "UPDATE condition_evaluations SET outcome = 'clear', evidence_json = ?1",
            [serde_json::to_string(&evidence).expect("resolution evidence")],
        )
        .expect("legacy clear evidence");
    connection
        .execute_batch(
            "UPDATE notification_outbox SET transition = 'resolution', remote_request_id = '';
        UPDATE condition_state SET lifecycle = 'clear', alert_delivery_state = 'resolved';",
        )
        .expect("unproven legacy resolution");
    drop(connection);
    let (store, _) = StateStore::migrate(&path).expect("migrate");
    let report = store.load_reports(1, None).expect("report").remove(0);
    assert_eq!(report.notifications[0].status, NotificationStatus::Unknown);
    assert_eq!(
        report.evaluations[0].notification_state,
        AlertDeliveryState::Unknown
    );
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT alert_delivery_state FROM condition_state",
                [],
                |row| row.get::<_, String>(0)
            )
            .expect("delivery latch"),
        "unknown"
    );
}

#[test]
fn a_stale_completion_cannot_update_a_newer_episode() {
    let directory = tempdir().expect("tempdir");
    let mut store = StateStore::open(&directory.path().join("state.sqlite")).expect("store");
    let alert = commit(
        &mut store,
        "first-alert",
        1,
        vec![evaluation("condition", true)],
    )
    .remove(0);
    deliver(&mut store, &alert, 2);
    let resolution = commit(
        &mut store,
        "first-clear",
        3,
        vec![evaluation("condition", false)],
    )
    .remove(0);
    let attempt = store
        .begin_notification_attempt(&resolution, "2026-01-01T00:00:04Z", "first-clear")
        .expect("old resolution in flight");
    let mut recurring = evaluation("condition", true);
    recurring.sustain_runs = 2;
    commit(&mut store, "new-episode", 5, vec![recurring]);
    store
        .record_notification_attempt(
            &attempt,
            "2026-01-01T00:00:06Z",
            &NotificationAttemptOutcome::Delivered {
                http_status: 200,
                remote_request_id: "synthetic-request".to_owned(),
            },
        )
        .expect("late result for old episode");
    store
        .refresh_run_delivery("new-episode")
        .expect("refresh new report");
    let reports = store.load_reports(10, None).expect("history");
    assert_eq!(
        reports[0].evaluations[0].lifecycle,
        ConditionLifecycle::Pending
    );
    assert_eq!(
        reports[0].evaluations[0].notification_state,
        AlertDeliveryState::Never
    );
    let old = reports
        .iter()
        .find(|report| report.run_id == "first-clear")
        .expect("old resolution");
    assert_eq!(
        old.evaluations[0].notification_state,
        AlertDeliveryState::Resolved
    );
    assert_eq!(old.notifications[0].status, NotificationStatus::Delivered);
}

#[test]
fn delivery_activity_keeps_each_runs_outcome_and_survives_origin_retention() {
    let directory = tempdir().expect("tempdir");
    let mut store = StateStore::open(&directory.path().join("state.sqlite")).expect("store");
    let message = commit(&mut store, "origin", 1, vec![evaluation("condition", true)]).remove(0);
    retry(&mut store, &message, 2);
    // The condition is no longer configured; current evaluations cannot explain
    // this older message's failure. Activity must carry its origin explicitly.
    commit(&mut store, "retry-run", 10, vec![]);
    retry(&mut store, &message, 10);
    let report = store
        .load_reports(1, None)
        .expect("current retry report")
        .remove(0);
    assert_eq!(
        report.exit.code, 4,
        "result and failure exit commit together"
    );
    assert!(report.notifications.is_empty());
    assert!(report.transitions.is_empty());
    assert_eq!(report.delivery_activity[0].origin_run_id, "origin");
    assert_eq!(
        report.delivery_activity[0].notification.status,
        NotificationStatus::Retryable
    );
    commit(&mut store, "delivered-run", 20, vec![]);
    deliver(&mut store, &message, 20);
    let reports = store.load_reports(10, None).expect("history");
    let retry_report = reports
        .iter()
        .find(|report| report.run_id == "retry-run")
        .expect("retry snapshot");
    assert_eq!(
        retry_report.delivery_activity[0].notification.status,
        NotificationStatus::Retryable
    );
    let transaction = store.connection.transaction().expect("retention");
    super::prune_runs(&transaction, "2026-01-01T00:00:15.000000000Z")
        .expect("prune delivered origin");
    transaction.commit().expect("commit retention");
    let retained = store
        .load_reports(10, None)
        .expect("recent activity survives");
    assert_eq!(retained.len(), 1);
    assert!(retained[0].notifications.is_empty());
    assert_eq!(retained[0].delivery_activity[0].origin_run_id, "origin");
    assert_eq!(
        retained[0].delivery_activity[0].notification.status,
        NotificationStatus::Delivered
    );
}

#[test]
fn ambiguous_legacy_counts_restart_only_the_affected_targets_learning_history() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("state.sqlite");
    let connection = legacy(&path);
    legacy_run(&connection, "ambiguous", "live", "2026-01-01T00:05:00Z");
    for (run, target, count) in [
        ("legacy-run", "resolver-a", 100_i64),
        ("legacy-run", "resolver-b", 100),
        ("ambiguous", "resolver-a", i64::MAX),
        ("ambiguous", "resolver-b", 150),
    ] {
        connection.execute(
            "INSERT INTO target_observations(run_id, target_id, target_name, status, complete, queries, blocked)
             VALUES (?1, ?2, 'Synthetic resolver', 'complete', 1, ?3, ?3)",
            params![run, target, count],
        ).expect("legacy reading");
    }
    drop(connection);
    let (store, _) = StateStore::migrate(&path).expect("migrate legacy saturation");
    let after_barrier = store
        .load_target_samples(0)
        .expect("samples after ambiguous reading");
    assert!(
        after_barrier
            .iter()
            .all(|sample| sample.target_id == "resolver-b"),
        "A=100 must not survive as the predecessor of the first exact reading after B=inexact"
    );
    assert_eq!(
        after_barrier.len(),
        2,
        "another target keeps its exact history"
    );

    legacy_run(
        &store.connection,
        "first-exact",
        "live",
        "2026-01-01T00:10:00.000000000Z",
    );
    store.connection.execute(
        "INSERT INTO target_observations(run_id, target_id, target_name, status, complete, queries, blocked)
         VALUES ('first-exact', 'resolver-a', 'Synthetic resolver', 'complete', 1, '200', '200')", [],
    ).expect("C=200 after migration");
    let after_c = store.load_target_samples(0).expect("history after C");
    let affected: Vec<_> = after_c
        .iter()
        .filter(|sample| sample.target_id == "resolver-a")
        .collect();
    assert_eq!(
        affected.len(),
        1,
        "A/B/C must not become a fabricated A-to-C window"
    );
    assert_eq!(affected[0].run_id, "first-exact");
    assert_eq!(affected[0].queries, 200);

    let signed_max = u64::try_from(i64::MAX).expect("nonnegative signed maximum");
    for (id, timestamp, count) in [
        ("second-exact", "2026-01-01T00:15:00.000000000Z", 300),
        (
            "exact-signed-max",
            "2026-01-01T00:20:00.000000000Z",
            signed_max,
        ),
        (
            "exact-unsigned-max",
            "2026-01-01T00:25:00.000000000Z",
            u64::MAX,
        ),
    ] {
        legacy_run(&store.connection, id, "live", timestamp);
        store.connection.execute(
            "INSERT INTO target_observations(run_id, target_id, target_name, status, complete, queries, blocked)
             VALUES (?1, 'resolver-a', 'Synthetic resolver', 'complete', 1, ?2, ?2)",
            params![id, count.to_string()],
        ).expect("exact v2 reading");
    }
    let resumed = store.load_target_samples(0).expect("resumed exact history");
    assert_eq!(
        resumed
            .iter()
            .filter(|sample| sample.target_id == "resolver-a")
            .map(|sample| sample.queries)
            .collect::<Vec<_>>(),
        [200, 300, signed_max, u64::MAX]
    );
    assert_eq!(
        resumed
            .iter()
            .filter(|sample| sample.target_id == "resolver-b")
            .count(),
        2
    );
}

#[test]
fn inexact_history_barriers_use_full_timestamps_then_run_order() {
    let directory = tempdir().expect("tempdir");
    let store = StateStore::open(&directory.path().join("state.sqlite")).expect("store");
    for (id, fraction, exact) in [
        ("before", "100000000", true),
        ("tied-before", "500000000", true),
        ("later", "700000000", true),
        ("barrier", "500000000", false),
        ("tied-after", "500000000", true),
    ] {
        legacy_run(
            &store.connection,
            id,
            "live",
            &format!("2026-01-01T00:00:00.{fraction}Z"),
        );
        store.connection.execute(
            "INSERT INTO target_observations(run_id, target_id, target_name, status, complete, queries, blocked, counters_exact)
             VALUES (?1, 'resolver-a', 'Synthetic resolver', 'complete', 1, '100', '100', ?2)",
            params![id, exact],
        ).expect("reading");
    }
    let samples = store.load_target_samples(0).expect("ordered exact segment");
    assert_eq!(
        samples
            .iter()
            .map(|sample| sample.run_id.as_str())
            .collect::<Vec<_>>(),
        ["tied-after", "later"]
    );
}

#[test]
fn retention_keeps_the_latest_precision_barrier_when_old_delivery_evidence_survives() {
    let directory = tempdir().expect("tempdir");
    let mut store = StateStore::open(&directory.path().join("state.sqlite")).expect("store");
    for (id, second, exact, count) in [
        ("a", 0, true, "100"),
        ("old-barrier", 1, false, "9223372036854775807"),
        ("barrier", 2, false, "9223372036854775807"),
        ("c", 3, true, "200"),
    ] {
        let timestamp = format!("2026-01-01T00:00:{second:02}.000000000Z");
        legacy_run(&store.connection, id, "live", &timestamp);
        store.connection.execute("INSERT INTO target_observations(run_id, target_id, target_name, status, complete, queries, blocked, counters_exact)
            VALUES (?1, 'resolver', 'Synthetic resolver', 'complete', 1, ?2, ?2, ?3)", params![id, count, exact]).expect("reading");
        if exact {
            store.connection.execute("INSERT INTO notification_outbox(id, run_id, transition, title, message, priority, status, created_at)
                VALUES (?1, ?1, 'alert', 'Synthetic', 'Synthetic', 0, 'unknown', ?2)", params![id, timestamp]).expect("retained delivery evidence");
        }
    }
    let transaction = store.connection.transaction().expect("retention");
    super::prune_runs(&transaction, "2026-01-02T00:00:00.000000000Z")
        .expect("prune old observations");
    transaction.commit().expect("prune committed");
    // A wider configured retention window must not revive an A->C measurement
    // after an ordinary prune forgot the counter reset between those samples.
    let samples = store
        .load_target_samples(0)
        .expect("expanded history window");
    assert_eq!(
        samples
            .iter()
            .map(|sample| sample.run_id.as_str())
            .collect::<Vec<_>>(),
        ["c"]
    );
    assert_eq!(
        store
            .load_reports(10, None)
            .expect("latest barrier retained")
            .iter()
            .map(|report| report.run_id.as_str())
            .collect::<Vec<_>>(),
        ["c", "barrier", "a"]
    );
}
