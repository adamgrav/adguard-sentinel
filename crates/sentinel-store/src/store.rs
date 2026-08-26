use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use sentinel_core::{
    AggregateObservation, AlertDeliveryState, BaselineSample, ConditionEvaluation,
    ConditionLifecycle, ConditionState, ConditionTransition, Config, DnsObservation, ExitReport,
    FilterObservation, Finding, NotificationReport, NotificationStatus, OperationalObservation,
    OutboxMessage, RewriteObservation, RunHealth, RunReport, TargetReport, TargetRuntimeState,
    TargetSample, TargetStatus, TransitionKind, UpstreamObservation, advance_condition,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const SCHEMA: &str = include_str!("../../../schemas/state-v1.sql");
const STATE_VERSION: i64 = 1;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("state path has no parent directory: {0}")]
    MissingParent(PathBuf),
    #[error("state parent directory does not exist: {0}")]
    ParentMissing(PathBuf),
    #[error("cannot open or use state database")]
    Sqlite(#[from] rusqlite::Error),
    #[error("state schema version {observed} is unsupported; expected {expected}")]
    UnsupportedVersion { observed: i64, expected: i64 },
    #[error("unversioned nonempty SQLite state is not supported")]
    UnversionedState,
    #[error("cannot update state file permissions: {0}")]
    Permissions(std::io::Error),
    #[error("state contains invalid serialized data: {0}")]
    InvalidData(String),
    #[error("cannot read state-adjacent data")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub enum NotificationAttemptOutcome {
    Delivered {
        http_status: u16,
        remote_request_id: String,
    },
    Retryable {
        http_status: Option<u16>,
        error_class: String,
    },
    Failed {
        http_status: Option<u16>,
        remote_request_id: Option<String>,
        error_class: String,
    },
    Unknown {
        error_class: String,
    },
}

#[derive(Debug)]
pub struct StateStore {
    pub(crate) connection: Connection,
    path: PathBuf,
}

pub fn canonical_state_schema() -> &'static str {
    SCHEMA
}

impl StateStore {
    pub fn open_existing(path: &Path) -> Result<Self, StoreError> {
        if !path.is_file() {
            return Err(StoreError::InvalidData(format!(
                "state database does not exist: {}",
                path.display()
            )));
        }
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")?;
        validate_schema(&connection)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let parent = path
            .parent()
            .ok_or_else(|| StoreError::MissingParent(path.to_path_buf()))?;
        if !parent.exists() {
            return Err(StoreError::ParentMissing(parent.to_path_buf()));
        }
        let existed = path.exists();
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL; PRAGMA trusted_schema = OFF;",
        )?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 0 {
            let table_count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            if table_count != 0 {
                return Err(StoreError::UnversionedState);
            }
            connection.execute_batch(SCHEMA)?;
            let applied_at = Timestamp::now().to_string();
            connection.execute(
                "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (?1, ?2, ?3, ?4)",
                params![STATE_VERSION, "initial", schema_checksum(), applied_at],
            )?;
        } else if version != STATE_VERSION {
            return Err(StoreError::UnsupportedVersion {
                observed: version,
                expected: STATE_VERSION,
            });
        }
        validate_schema(&connection)?;
        if !existed {
            set_private_permissions(path)?;
        }
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn schema_version(&self) -> u32 {
        u32::try_from(STATE_VERSION).expect("state version is nonnegative")
    }

    pub fn ensure_run_mode(&self, mode: sentinel_core::RunMode) -> Result<(), StoreError> {
        let requested = encode(mode)?;
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT mode FROM runs WHERE mode IN ('live', 'dry_run') LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if existing.as_deref().is_some_and(|value| value != requested) {
            return Err(StoreError::InvalidData(format!(
                "state database is bound to {existing:?} runs and cannot be used for {requested:?}"
            )));
        }
        Ok(())
    }

    pub fn load_baseline_samples(
        &self,
        cutoff_unix_seconds: i64,
    ) -> Result<Vec<BaselineSample>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT r.completed_at, a.local_hour, a.combined_queries, a.combined_blocked_ratio
             FROM aggregate_observations a
             JOIN runs r ON r.id = a.run_id
             ORDER BY r.completed_at ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let timestamp: String = row.get(0)?;
            let local_hour: i64 = row.get(1)?;
            let combined_queries: i64 = row.get(2)?;
            let combined_blocked_ratio: f64 = row.get(3)?;
            Ok((
                timestamp,
                local_hour,
                combined_queries,
                combined_blocked_ratio,
            ))
        })?;
        let mut samples = Vec::new();
        for row in rows {
            let (timestamp, local_hour, combined_queries, combined_blocked_ratio) = row?;
            let timestamp = parse_timestamp(&timestamp)?;
            if timestamp < cutoff_unix_seconds {
                continue;
            }
            samples.push(BaselineSample {
                timestamp,
                local_hour: u8::try_from(local_hour).map_err(|_| {
                    StoreError::InvalidData("local hour is out of range".to_owned())
                })?,
                combined_queries: u64::try_from(combined_queries).map_err(|_| {
                    StoreError::InvalidData("combined query count is negative".to_owned())
                })?,
                combined_blocked_ratio,
            });
        }
        Ok(samples)
    }

    /// Loads per-target statistics readings inside the retention window,
    /// oldest first, for deriving per-target behavioural rates.
    ///
    /// Only complete observations are returned: an incomplete one has no
    /// counter to difference against, and treating a missing reading as a
    /// value would invent traffic that was never observed.
    pub fn load_target_samples(
        &self,
        cutoff_unix_seconds: i64,
    ) -> Result<Vec<TargetSample>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT r.completed_at, t.target_id, t.queries, t.blocked
             FROM target_observations t
             JOIN runs r ON r.id = t.run_id
             WHERE t.complete = 1 AND t.queries IS NOT NULL AND t.blocked IS NOT NULL
             ORDER BY r.completed_at ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let timestamp: String = row.get(0)?;
            let target_id: String = row.get(1)?;
            let queries: i64 = row.get(2)?;
            let blocked: i64 = row.get(3)?;
            Ok((timestamp, target_id, queries, blocked))
        })?;
        let mut samples = Vec::new();
        for row in rows {
            let (timestamp, target_id, queries, blocked) = row?;
            let timestamp = parse_timestamp(&timestamp)?;
            if timestamp < cutoff_unix_seconds {
                continue;
            }
            samples.push(TargetSample {
                target_id,
                timestamp,
                queries: u64::try_from(queries).map_err(|_| {
                    StoreError::InvalidData("target query count is negative".to_owned())
                })?,
                blocked: u64::try_from(blocked).map_err(|_| {
                    StoreError::InvalidData("target blocked count is negative".to_owned())
                })?,
            });
        }
        Ok(samples)
    }

    pub fn target_runtime_state(
        &self,
        target_id: &str,
    ) -> Result<Option<TargetRuntimeState>, StoreError> {
        self.connection
            .query_row(
                "SELECT auth_failed_at, auth_retry_after FROM target_runtime_state WHERE target_id = ?1",
                [target_id],
                |row| {
                    Ok(TargetRuntimeState {
                        target_id: target_id.to_owned(),
                        auth_failed_at: row.get(0)?,
                        auth_retry_after: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn latest_completed_unix_seconds(&self) -> Result<Option<i64>, StoreError> {
        let latest: Option<String> =
            self.connection
                .query_row("SELECT MAX(completed_at) FROM runs", [], |row| row.get(0))?;
        latest.map(|value| parse_timestamp(&value)).transpose()
    }

    pub fn commit_run(
        &mut self,
        report: &mut RunReport,
        config: &Config,
        now_unix_seconds: i64,
        retention_cutoff: &str,
        suppress_notifications: bool,
    ) -> Result<Vec<OutboxMessage>, StoreError> {
        let transaction = self.connection.transaction()?;
        let mut transitions = Vec::new();
        let mut states = Vec::new();
        for evaluation in &mut report.evaluations {
            let mut state = load_condition_state(&transaction, evaluation)?
                .unwrap_or_else(|| ConditionState::from_evaluation(evaluation));
            let previous_delivery = state.alert_delivery_state;
            let transition = advance_condition(
                &mut state,
                evaluation,
                &report.completed_at,
                &report.run_id,
                suppress_notifications,
            );
            if evaluation.outcome == sentinel_core::EvaluationOutcome::Clear
                && state.lifecycle == ConditionLifecycle::Clear
                && previous_delivery == AlertDeliveryState::Pending
            {
                remove_condition_from_pending_alerts(&transaction, &evaluation.id)?;
                state.alert_delivery_state = AlertDeliveryState::Never;
                evaluation.notification_state = AlertDeliveryState::Never;
            }
            if let Some(transition) = transition {
                transitions.push(transition);
            }
            states.push(state);
        }
        transitions.sort_by(|left, right| {
            (transition_order(left.kind), &left.condition_id)
                .cmp(&(transition_order(right.kind), &right.condition_id))
        });
        report.transitions.clone_from(&transitions);
        report.findings = report
            .evaluations
            .iter()
            .filter(|evaluation| evaluation.outcome == sentinel_core::EvaluationOutcome::Active)
            .map(Finding::from)
            .collect();
        report
            .findings
            .sort_by(|left, right| left.id.cmp(&right.id));
        let outbox = build_outbox(report, &transitions, suppress_notifications);
        report.notifications = outbox
            .iter()
            .map(|message| NotificationReport {
                id: message.id.clone(),
                transition: message.transition,
                condition_ids: message.condition_ids.clone(),
                status: message.status,
                remote_request_id: None,
                error_class: None,
            })
            .collect();

        insert_run(&transaction, report)?;
        insert_targets(&transaction, report)?;
        insert_aggregate(&transaction, report)?;
        insert_evaluations(&transaction, report)?;
        for state in &states {
            upsert_condition_state(&transaction, state)?;
        }
        update_runtime_states(&transaction, report, config, now_unix_seconds)?;
        insert_outbox(&transaction, &outbox, &report.completed_at)?;
        prune_runs(&transaction, retention_cutoff)?;
        transaction.commit()?;
        Ok(outbox)
    }

    pub fn pending_outbox(&self, now: &str) -> Result<Vec<OutboxMessage>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, run_id, transition, title, message, priority, status
             FROM notification_outbox
             WHERE status IN ('pending', 'retryable')
               AND (next_retry_at IS NULL OR next_retry_at <= ?1)
             ORDER BY created_at ASC, id ASC",
        )?;
        let rows = statement.query_map([now], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;
        let mut messages = Vec::new();
        for row in rows {
            let (id, run_id, transition, title, message, priority, status) = row?;
            messages.push(OutboxMessage {
                condition_ids: load_notification_conditions(&self.connection, &id)?,
                id,
                run_id,
                transition: decode(&transition)?,
                title,
                message,
                priority: i8::try_from(priority)
                    .map_err(|_| StoreError::InvalidData("priority out of range".to_owned()))?,
                status: decode(&status)?,
            });
        }
        Ok(messages)
    }

    pub fn record_notification_attempt(
        &mut self,
        message: &OutboxMessage,
        started_at: &str,
        completed_at: &str,
        outcome: &NotificationAttemptOutcome,
    ) -> Result<NotificationReport, StoreError> {
        let transaction = self.connection.transaction()?;
        let (status, outcome_label, http_status, remote_request_id, error_class) = match outcome {
            NotificationAttemptOutcome::Delivered {
                http_status,
                remote_request_id,
            } => (
                NotificationStatus::Delivered,
                "delivered",
                Some(i64::from(*http_status)),
                Some(remote_request_id.clone()),
                None,
            ),
            NotificationAttemptOutcome::Retryable {
                http_status,
                error_class,
            } => (
                NotificationStatus::Retryable,
                "retryable",
                http_status.map(i64::from),
                None,
                Some(error_class.clone()),
            ),
            NotificationAttemptOutcome::Failed {
                http_status,
                remote_request_id,
                error_class,
            } => (
                NotificationStatus::Failed,
                "failed",
                http_status.map(i64::from),
                remote_request_id.clone(),
                Some(error_class.clone()),
            ),
            NotificationAttemptOutcome::Unknown { error_class } => (
                NotificationStatus::Unknown,
                "unknown",
                None,
                None,
                Some(error_class.clone()),
            ),
        };
        transaction.execute(
            "INSERT INTO notification_attempts(
               id, notification_id, started_at, completed_at, outcome, http_status, remote_request_id, error_class
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                Uuid::new_v4().to_string(),
                message.id,
                started_at,
                completed_at,
                outcome_label,
                http_status,
                remote_request_id,
                error_class,
            ],
        )?;
        let delivered_at = if status == NotificationStatus::Delivered {
            Some(completed_at)
        } else {
            None
        };
        let next_retry_at = if status == NotificationStatus::Retryable {
            let completed = completed_at.parse::<Timestamp>().map_err(|error| {
                StoreError::InvalidData(format!("invalid attempt timestamp: {error}"))
            })?;
            Some(
                Timestamp::new(completed.as_second().saturating_add(5), 0)
                    .map_err(|error| StoreError::InvalidData(error.to_string()))?
                    .to_string(),
            )
        } else {
            None
        };
        transaction.execute(
            "UPDATE notification_outbox
             SET status = ?2, delivered_at = ?3, remote_request_id = ?4, error_class = ?5,
                 next_retry_at = ?6
             WHERE id = ?1",
            params![
                message.id,
                encode(status)?,
                delivered_at,
                remote_request_id,
                error_class,
                next_retry_at,
            ],
        )?;
        let delivery_state = match status {
            NotificationStatus::Delivered if message.transition == TransitionKind::Alert => {
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
        if let Some(delivery_state) = delivery_state {
            for condition_id in &message.condition_ids {
                transaction.execute(
                    "UPDATE condition_state SET alert_delivery_state = ?2 WHERE condition_id = ?1",
                    params![condition_id, encode(delivery_state)?],
                )?;
                let serialized: Option<String> = transaction
                    .query_row(
                        "SELECT evidence_json FROM condition_evaluations
                         WHERE run_id = ?1 AND condition_id = ?2",
                        params![message.run_id, condition_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(serialized) = serialized {
                    let mut evaluation: ConditionEvaluation = serde_json::from_str(&serialized)
                        .map_err(|error| StoreError::InvalidData(error.to_string()))?;
                    evaluation.notification_state = delivery_state;
                    transaction.execute(
                        "UPDATE condition_evaluations SET evidence_json = ?3
                         WHERE run_id = ?1 AND condition_id = ?2",
                        params![
                            message.run_id,
                            condition_id,
                            serde_json::to_string(&evaluation)
                                .map_err(|error| StoreError::InvalidData(error.to_string()))?,
                        ],
                    )?;
                }
            }
        }
        transaction.commit()?;
        Ok(NotificationReport {
            id: message.id.clone(),
            transition: message.transition,
            condition_ids: message.condition_ids.clone(),
            status,
            remote_request_id,
            error_class,
        })
    }

    pub fn update_run_exit(&self, run_id: &str, exit_code: u8) -> Result<(), StoreError> {
        self.connection.execute(
            "UPDATE runs SET exit_code = ?2 WHERE id = ?1",
            params![run_id, i64::from(exit_code)],
        )?;
        Ok(())
    }

    pub fn load_reports(
        &self,
        limit: usize,
        since: Option<&str>,
    ) -> Result<Vec<RunReport>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id FROM runs
             WHERE (?1 IS NULL OR completed_at >= ?1)
             ORDER BY completed_at DESC
             LIMIT ?2",
        )?;
        let ids = statement
            .query_map(
                params![since, i64::try_from(limit).unwrap_or(i64::MAX)],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter().map(|id| self.load_report(&id)).collect()
    }

    fn load_report(&self, run_id: &str) -> Result<RunReport, StoreError> {
        let (
            started_at,
            completed_at,
            mode,
            config_sha256,
            run_status,
            expected_targets,
            complete_targets,
            minimum_targets,
            exit_code,
        ) = self.connection.query_row(
            "SELECT started_at, completed_at, mode, config_sha256, status,
                    expected_targets, complete_targets, minimum_targets, exit_code
             FROM runs WHERE id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )?;
        let expected_targets = usize_from_i64(expected_targets, "expected target count")?;
        let complete_targets = usize_from_i64(complete_targets, "complete target count")?;
        let minimum_targets = usize_from_i64(minimum_targets, "minimum target count")?;
        let exit_code = u8::try_from(exit_code)
            .map_err(|_| StoreError::InvalidData("exit code out of range".to_owned()))?;
        let evaluations = load_evaluations(&self.connection, run_id)?;
        let findings = evaluations
            .iter()
            .filter(|evaluation| evaluation.outcome == sentinel_core::EvaluationOutcome::Active)
            .map(Finding::from)
            .collect();
        let notifications = load_notification_reports(&self.connection, run_id)?;
        let transitions = load_transitions(&self.connection, run_id, &evaluations)?;
        let met = complete_targets >= minimum_targets;
        Ok(RunReport {
            schema_version: sentinel_core::REPORT_SCHEMA_VERSION,
            run_id: run_id.to_owned(),
            mode: decode(&mode)?,
            started_at,
            completed_at,
            config_sha256,
            state_schema_version: self.schema_version(),
            run_status: decode(&run_status)?,
            expected_targets,
            complete_targets,
            minimum_complete_targets: minimum_targets,
            targets: load_targets(&self.connection, run_id)?,
            aggregate: load_aggregate(&self.connection, run_id)?,
            evaluations,
            findings,
            transitions,
            notifications,
            health: RunHealth {
                minimum_complete_targets: minimum_targets,
                complete_targets,
                met,
                issues: if met {
                    Vec::new()
                } else {
                    vec!["minimum complete target count was not met".to_owned()]
                },
            },
            exit: ExitReport {
                code: exit_code,
                reason: exit_reason(exit_code).to_owned(),
            },
        })
    }
}

fn validate_schema(connection: &Connection) -> Result<(), StoreError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != STATE_VERSION {
        return Err(StoreError::UnsupportedVersion {
            observed: version,
            expected: STATE_VERSION,
        });
    }
    let stored_checksum: Option<String> = connection
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version = ?1",
            [STATE_VERSION],
            |row| row.get(0),
        )
        .optional()?;
    let expected_checksum = schema_checksum();
    if stored_checksum.as_deref() != Some(expected_checksum.as_str()) {
        return Err(StoreError::InvalidData(
            "state migration checksum is absent or does not match schema v1".to_owned(),
        ));
    }
    Ok(())
}

fn insert_run(transaction: &Transaction<'_>, report: &RunReport) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO runs(
           id, started_at, completed_at, mode, config_sha256, status,
           expected_targets, complete_targets, minimum_targets, exit_code
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            report.run_id,
            report.started_at,
            report.completed_at,
            encode(report.mode)?,
            report.config_sha256,
            encode(report.run_status)?,
            i64_from_usize(report.expected_targets)?,
            i64_from_usize(report.complete_targets)?,
            i64_from_usize(report.minimum_complete_targets)?,
            i64::from(report.exit.code),
        ],
    )?;
    Ok(())
}

fn prune_runs(transaction: &Transaction<'_>, retention_cutoff: &str) -> Result<(), StoreError> {
    transaction.execute(
        "DELETE FROM runs WHERE completed_at < ?1",
        [retention_cutoff],
    )?;
    Ok(())
}

fn insert_targets(transaction: &Transaction<'_>, report: &RunReport) -> Result<(), StoreError> {
    for target in &report.targets {
        let operational = target.operational.as_ref();
        transaction.execute(
            "INSERT INTO target_observations(
               run_id, target_id, target_name, status, complete, server_version,
               protection_enabled, queries, blocked, blocked_ratio,
               average_processing_seconds, maximum_upstream_seconds, top_client_share,
               dns_upstream_mode, dns_upstream_json, filtering_enabled, rewrites_enabled,
               error_kind, error_detail
             ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
               ?14, ?15, ?16, ?17, ?18, ?19
             )",
            params![
                report.run_id,
                target.id,
                target.name,
                encode(target.status)?,
                bool_i64(target.complete),
                target.server_version,
                operational.map(|value| bool_i64(value.protection_enabled)),
                operational.map(|value| i64::try_from(value.queries).unwrap_or(i64::MAX)),
                operational.map(|value| i64::try_from(value.blocked).unwrap_or(i64::MAX)),
                operational.map(|value| value.blocked_ratio),
                operational.map(|value| value.average_processing_seconds),
                operational.map(|value| value.maximum_upstream_seconds),
                operational.map(|value| value.top_client_share),
                target
                    .dns
                    .as_ref()
                    .map(|value| value.upstream_mode.as_str()),
                target
                    .dns
                    .as_ref()
                    .map(|value| serde_json::to_string(&value.upstream_dns))
                    .transpose()
                    .map_err(|error| StoreError::InvalidData(error.to_string()))?,
                target.filtering_enabled.map(bool_i64),
                target.rewrites_enabled.map(bool_i64),
                target.error_kind,
                target.error_detail,
            ],
        )?;
        for (ordinal, upstream) in target.upstreams.iter().enumerate() {
            transaction.execute(
                "INSERT INTO upstream_observations(
                   run_id, target_id, ordinal, upstream_identity, average_seconds
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    report.run_id,
                    target.id,
                    i64_from_usize(ordinal)?,
                    upstream.identity,
                    upstream.average_seconds,
                ],
            )?;
        }
        for filter in &target.filters {
            transaction.execute(
                "INSERT INTO filter_observations(
                   run_id, target_id, filter_url, server_id, enabled, rules_count,
                   last_updated, last_updated_unix_seconds
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    report.run_id,
                    target.id,
                    filter.url,
                    filter.server_id,
                    bool_i64(filter.enabled),
                    i64::try_from(filter.rules_count).unwrap_or(i64::MAX),
                    filter.last_updated,
                    filter.last_updated_unix_seconds,
                ],
            )?;
        }
        for rewrite in &target.rewrites {
            transaction.execute(
                "INSERT INTO rewrite_observations(
                   run_id, target_id, domain, answer, enabled
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    report.run_id,
                    target.id,
                    rewrite.domain,
                    rewrite.answer,
                    bool_i64(rewrite.enabled),
                ],
            )?;
        }
    }
    Ok(())
}

fn insert_aggregate(transaction: &Transaction<'_>, report: &RunReport) -> Result<(), StoreError> {
    if let Some(aggregate) = &report.aggregate {
        transaction.execute(
            "INSERT INTO aggregate_observations(
               run_id, local_hour, utc_offset_minutes, combined_queries,
               combined_blocked_ratio, baseline_age_seconds, same_hour_samples,
               baseline_ready, volume_limit, ratio_limit, resolver_query_share_json,
               top_client_share_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                report.run_id,
                i64::from(aggregate.local_hour),
                i64::from(aggregate.utc_offset_minutes),
                i64::try_from(aggregate.combined_queries).unwrap_or(i64::MAX),
                aggregate.combined_blocked_ratio,
                aggregate.baseline_age_seconds,
                i64_from_usize(aggregate.same_hour_samples)?,
                bool_i64(aggregate.baseline_ready),
                aggregate.volume_limit,
                aggregate.ratio_limit,
                serde_json::to_string(&aggregate.resolver_query_share)
                    .map_err(|error| StoreError::InvalidData(error.to_string()))?,
                serde_json::to_string(&aggregate.top_client_share)
                    .map_err(|error| StoreError::InvalidData(error.to_string()))?,
            ],
        )?;
    }
    Ok(())
}

fn insert_evaluations(transaction: &Transaction<'_>, report: &RunReport) -> Result<(), StoreError> {
    for evaluation in &report.evaluations {
        transaction.execute(
            "INSERT INTO condition_evaluations(
               run_id, condition_id, outcome, expected_json, observed_json,
               evidence_json, complete
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                report.run_id,
                evaluation.id,
                encode(evaluation.outcome)?,
                serde_json::to_string(&evaluation.expected)
                    .map_err(|error| StoreError::InvalidData(error.to_string()))?,
                serde_json::to_string(&evaluation.observed)
                    .map_err(|error| StoreError::InvalidData(error.to_string()))?,
                serde_json::to_string(evaluation)
                    .map_err(|error| StoreError::InvalidData(error.to_string()))?,
                bool_i64(evaluation.observation_complete),
            ],
        )?;
    }
    Ok(())
}

fn update_runtime_states(
    transaction: &Transaction<'_>,
    report: &RunReport,
    config: &Config,
    now_unix_seconds: i64,
) -> Result<(), StoreError> {
    for target_report in &report.targets {
        match target_report.status {
            TargetStatus::AuthenticationRejected => {
                let target = config
                    .targets
                    .iter()
                    .find(|target| target.id == target_report.id)
                    .ok_or_else(|| {
                        StoreError::InvalidData("target missing from config".to_owned())
                    })?;
                let profile = config
                    .condition_profiles
                    .get(&target.condition_profile)
                    .ok_or_else(|| {
                        StoreError::InvalidData("condition profile missing".to_owned())
                    })?;
                let retry_after = now_unix_seconds.saturating_add(
                    i64::try_from(profile.authentication_retry_seconds).unwrap_or(i64::MAX),
                );
                transaction.execute(
                    "INSERT INTO target_runtime_state(target_id, auth_failed_at, auth_retry_after)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(target_id) DO UPDATE SET
                       auth_failed_at = excluded.auth_failed_at,
                       auth_retry_after = excluded.auth_retry_after",
                    params![target_report.id, now_unix_seconds, retry_after],
                )?;
            }
            TargetStatus::Complete => {
                transaction.execute(
                    "DELETE FROM target_runtime_state WHERE target_id = ?1",
                    [&target_report.id],
                )?;
            }
            TargetStatus::AuthenticationCooldown
            | TargetStatus::Unavailable
            | TargetStatus::InvalidResponse
            | TargetStatus::UnsupportedVersion
            | TargetStatus::ResponseTooLarge => {}
        }
    }
    Ok(())
}

fn build_outbox(
    report: &RunReport,
    transitions: &[ConditionTransition],
    suppressed: bool,
) -> Vec<OutboxMessage> {
    let mut messages = Vec::new();
    for kind in [TransitionKind::Alert, TransitionKind::Resolution] {
        let selected: Vec<_> = transitions
            .iter()
            .filter(|transition| transition.kind == kind)
            .collect();
        if selected.is_empty() {
            continue;
        }
        let condition_ids = selected
            .iter()
            .map(|transition| transition.condition_id.clone())
            .collect::<Vec<_>>();
        let lines = selected
            .iter()
            .map(|transition| format!("- {}", transition.summary))
            .collect::<Vec<_>>()
            .join("\n");
        messages.push(OutboxMessage {
            id: Uuid::new_v4().to_string(),
            run_id: report.run_id.clone(),
            transition: kind,
            title: if kind == TransitionKind::Alert {
                "AdGuard anomaly detected".to_owned()
            } else {
                "AdGuard anomaly resolved".to_owned()
            },
            message: truncate_chars(&lines, 1_024),
            priority: if kind == TransitionKind::Alert { 0 } else { -1 },
            status: if suppressed {
                NotificationStatus::Suppressed
            } else {
                NotificationStatus::Pending
            },
            condition_ids,
        });
    }
    messages
}

fn insert_outbox(
    transaction: &Transaction<'_>,
    outbox: &[OutboxMessage],
    created_at: &str,
) -> Result<(), StoreError> {
    for message in outbox {
        transaction.execute(
            "INSERT INTO notification_outbox(
               id, run_id, transition, title, message, priority, status, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                message.id,
                message.run_id,
                encode(message.transition)?,
                message.title,
                message.message,
                i64::from(message.priority),
                encode(message.status)?,
                created_at,
            ],
        )?;
        for condition_id in &message.condition_ids {
            transaction.execute(
                "INSERT INTO notification_conditions(notification_id, condition_id) VALUES (?1, ?2)",
                params![message.id, condition_id],
            )?;
        }
    }
    Ok(())
}

fn load_condition_state(
    transaction: &Transaction<'_>,
    evaluation: &ConditionEvaluation,
) -> Result<Option<ConditionState>, StoreError> {
    transaction
        .query_row(
            "SELECT target_id, kind, severity, lifecycle, first_observed_at,
                    last_observed_at, active_count, clear_count, alert_delivery_state,
                    last_transition_run
             FROM condition_state WHERE condition_id = ?1",
            [&evaluation.id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(ConditionState {
                id: evaluation.id.clone(),
                target_id: row.0,
                kind: row.1,
                severity: decode(&row.2)?,
                lifecycle: decode(&row.3)?,
                first_observed_at: row.4,
                last_observed_at: row.5,
                // The state schema pins these column names; the model spells
                // the same values consecutive_active and consecutive_clear.
                consecutive_active: u32_from_i64(row.6, "active count")?,
                consecutive_clear: u32_from_i64(row.7, "clear count")?,
                alert_delivery_state: decode(&row.8)?,
                last_transition_run: row.9,
            })
        })
        .transpose()
}

pub(crate) fn upsert_condition_state(
    transaction: &Transaction<'_>,
    state: &ConditionState,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO condition_state(
           condition_id, target_id, kind, severity, lifecycle, first_observed_at,
           last_observed_at, active_count, clear_count, alert_delivery_state,
           last_transition_run
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(condition_id) DO UPDATE SET
           target_id = excluded.target_id,
           kind = excluded.kind,
           severity = excluded.severity,
           lifecycle = excluded.lifecycle,
           first_observed_at = excluded.first_observed_at,
           last_observed_at = excluded.last_observed_at,
           active_count = excluded.active_count,
           clear_count = excluded.clear_count,
           alert_delivery_state = excluded.alert_delivery_state,
           last_transition_run = excluded.last_transition_run",
        params![
            state.id,
            state.target_id,
            state.kind,
            encode(state.severity)?,
            encode(state.lifecycle)?,
            state.first_observed_at,
            state.last_observed_at,
            i64::from(state.consecutive_active),
            i64::from(state.consecutive_clear),
            encode(state.alert_delivery_state)?,
            state.last_transition_run,
        ],
    )?;
    Ok(())
}

fn remove_condition_from_pending_alerts(
    transaction: &Transaction<'_>,
    condition_id: &str,
) -> Result<(), StoreError> {
    let mut statement = transaction.prepare(
        "SELECT n.id
         FROM notification_outbox n
         JOIN notification_conditions c ON c.notification_id = n.id
         WHERE c.condition_id = ?1 AND n.transition = 'alert'
           AND n.status IN ('pending', 'retryable')",
    )?;
    let notification_ids = statement
        .query_map([condition_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for notification_id in notification_ids {
        transaction.execute(
            "DELETE FROM notification_conditions
             WHERE notification_id = ?1 AND condition_id = ?2",
            params![notification_id, condition_id],
        )?;
        let remaining: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM notification_conditions WHERE notification_id = ?1",
            [&notification_id],
            |row| row.get(0),
        )?;
        if remaining == 0 {
            transaction.execute(
                "UPDATE notification_outbox SET status = 'cancelled' WHERE id = ?1",
                [&notification_id],
            )?;
        } else {
            let condition_ids = load_notification_conditions(transaction, &notification_id)?;
            let mut lines = Vec::new();
            for remaining_id in condition_ids {
                let serialized: String = transaction.query_row(
                    "SELECT e.evidence_json
                     FROM condition_evaluations e
                     JOIN runs r ON r.id = e.run_id
                     WHERE e.condition_id = ?1
                     ORDER BY r.completed_at DESC LIMIT 1",
                    [&remaining_id],
                    |row| row.get(0),
                )?;
                let evaluation: ConditionEvaluation = serde_json::from_str(&serialized)
                    .map_err(|error| StoreError::InvalidData(error.to_string()))?;
                lines.push(format!("- {}", evaluation.summary));
            }
            transaction.execute(
                "UPDATE notification_outbox SET message = ?2 WHERE id = ?1",
                params![notification_id, truncate_chars(&lines.join("\n"), 1_024)],
            )?;
        }
    }
    Ok(())
}

fn load_targets(connection: &Connection, run_id: &str) -> Result<Vec<TargetReport>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT target_id, target_name, status, complete, server_version,
                protection_enabled, queries, blocked, blocked_ratio,
                average_processing_seconds, maximum_upstream_seconds, top_client_share,
                dns_upstream_mode, dns_upstream_json, filtering_enabled, rewrites_enabled,
                error_kind, error_detail
         FROM target_observations WHERE run_id = ?1 ORDER BY target_id",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<i64>>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, Option<f64>>(8)?,
            row.get::<_, Option<f64>>(9)?,
            row.get::<_, Option<f64>>(10)?,
            row.get::<_, Option<f64>>(11)?,
            row.get::<_, Option<String>>(12)?,
            row.get::<_, Option<String>>(13)?,
            row.get::<_, Option<i64>>(14)?,
            row.get::<_, Option<i64>>(15)?,
            row.get::<_, Option<String>>(16)?,
            row.get::<_, Option<String>>(17)?,
        ))
    })?;
    let mut targets = Vec::new();
    for row in rows {
        let row = row?;
        let operational = match (row.5, row.6, row.7, row.8, row.9, row.10, row.11) {
            (
                Some(protection),
                Some(queries),
                Some(blocked),
                Some(ratio),
                Some(processing),
                Some(upstream),
                Some(client),
            ) => Some(OperationalObservation {
                protection_enabled: protection != 0,
                queries: u64_from_i64(queries, "query count")?,
                blocked: u64_from_i64(blocked, "blocked count")?,
                blocked_ratio: ratio,
                average_processing_seconds: processing,
                maximum_upstream_seconds: upstream,
                top_client_share: client,
            }),
            _ => None,
        };
        let dns = match (row.12, row.13) {
            (Some(mode), Some(upstreams)) => Some(DnsObservation {
                upstream_mode: mode,
                upstream_dns: serde_json::from_str(&upstreams)
                    .map_err(|error| StoreError::InvalidData(error.to_string()))?,
            }),
            _ => None,
        };
        let target_id = row.0;
        targets.push(TargetReport {
            id: target_id.clone(),
            name: row.1,
            status: decode(&row.2)?,
            complete: row.3 != 0,
            server_version: row.4,
            operational,
            dns,
            filtering_enabled: row.14.map(|value| value != 0),
            rewrites_enabled: row.15.map(|value| value != 0),
            upstreams: load_upstreams(connection, run_id, &target_id)?,
            filters: load_filters(connection, run_id, &target_id)?,
            rewrites: load_rewrites(connection, run_id, &target_id)?,
            error_kind: row.16,
            error_detail: row.17,
        });
    }
    Ok(targets)
}

fn load_upstreams(
    connection: &Connection,
    run_id: &str,
    target_id: &str,
) -> Result<Vec<UpstreamObservation>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT upstream_identity, average_seconds FROM upstream_observations
         WHERE run_id = ?1 AND target_id = ?2 ORDER BY ordinal",
    )?;
    statement
        .query_map(params![run_id, target_id], |row| {
            Ok(UpstreamObservation {
                identity: row.get(0)?,
                average_seconds: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

fn load_filters(
    connection: &Connection,
    run_id: &str,
    target_id: &str,
) -> Result<Vec<FilterObservation>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT filter_url, server_id, enabled, rules_count, last_updated,
                last_updated_unix_seconds
         FROM filter_observations WHERE run_id = ?1 AND target_id = ?2
         ORDER BY filter_url",
    )?;
    let rows = statement.query_map(params![run_id, target_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<i64>>(5)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        Ok(FilterObservation {
            url: row.0,
            server_id: row.1,
            enabled: row.2 != 0,
            rules_count: u64_from_i64(row.3, "rules count")?,
            last_updated: row.4,
            last_updated_unix_seconds: row.5,
        })
    })
    .collect()
}

fn load_rewrites(
    connection: &Connection,
    run_id: &str,
    target_id: &str,
) -> Result<Vec<RewriteObservation>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT domain, answer, enabled FROM rewrite_observations
         WHERE run_id = ?1 AND target_id = ?2 ORDER BY domain, answer",
    )?;
    statement
        .query_map(params![run_id, target_id], |row| {
            Ok(RewriteObservation {
                domain: row.get(0)?,
                answer: row.get(1)?,
                enabled: row.get::<_, i64>(2)? != 0,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

fn load_aggregate(
    connection: &Connection,
    run_id: &str,
) -> Result<Option<AggregateObservation>, StoreError> {
    let row = connection
        .query_row(
            "SELECT local_hour, utc_offset_minutes, combined_queries,
                    combined_blocked_ratio, baseline_age_seconds, same_hour_samples,
                    baseline_ready, volume_limit, ratio_limit,
                    resolver_query_share_json, top_client_share_json
             FROM aggregate_observations WHERE run_id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, f64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<f64>>(7)?,
                    row.get::<_, Option<f64>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        Ok(AggregateObservation {
            local_hour: u8::try_from(row.0)
                .map_err(|_| StoreError::InvalidData("local hour out of range".to_owned()))?,
            utc_offset_minutes: i32::try_from(row.1)
                .map_err(|_| StoreError::InvalidData("UTC offset out of range".to_owned()))?,
            combined_queries: u64_from_i64(row.2, "combined query count")?,
            combined_blocked_ratio: row.3,
            baseline_age_seconds: row.4,
            same_hour_samples: usize_from_i64(row.5, "same-hour sample count")?,
            baseline_ready: row.6 != 0,
            volume_limit: row.7,
            ratio_limit: row.8,
            resolver_query_share: serde_json::from_str(&row.9)
                .map_err(|error| StoreError::InvalidData(error.to_string()))?,
            top_client_share: serde_json::from_str(&row.10)
                .map_err(|error| StoreError::InvalidData(error.to_string()))?,
        })
    })
    .transpose()
}

fn load_evaluations(
    connection: &Connection,
    run_id: &str,
) -> Result<Vec<ConditionEvaluation>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT evidence_json FROM condition_evaluations
         WHERE run_id = ?1 ORDER BY condition_id",
    )?;
    let rows = statement.query_map([run_id], |row| row.get::<_, String>(0))?;
    rows.map(|row| {
        serde_json::from_str(&row?).map_err(|error| StoreError::InvalidData(error.to_string()))
    })
    .collect()
}

fn load_notification_reports(
    connection: &Connection,
    run_id: &str,
) -> Result<Vec<NotificationReport>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT id, transition, status, remote_request_id, error_class
         FROM notification_outbox WHERE run_id = ?1 ORDER BY created_at, id",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        Ok(NotificationReport {
            condition_ids: load_notification_conditions(connection, &row.0)?,
            id: row.0,
            transition: decode(&row.1)?,
            status: decode(&row.2)?,
            remote_request_id: row.3,
            error_class: row.4,
        })
    })
    .collect()
}

fn load_transitions(
    connection: &Connection,
    run_id: &str,
    evaluations: &[ConditionEvaluation],
) -> Result<Vec<ConditionTransition>, StoreError> {
    let summaries: BTreeMap<_, _> = evaluations
        .iter()
        .map(|evaluation| (evaluation.id.as_str(), evaluation.summary.as_str()))
        .collect();
    let mut statement = connection.prepare(
        "SELECT n.transition, c.condition_id
         FROM notification_outbox n
         JOIN notification_conditions c ON c.notification_id = n.id
         WHERE n.run_id = ?1 ORDER BY n.created_at, c.condition_id",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    rows.map(|row| {
        let (kind, condition_id) = row?;
        Ok(ConditionTransition {
            summary: summaries
                .get(condition_id.as_str())
                .copied()
                .unwrap_or("condition transition")
                .to_owned(),
            condition_id,
            kind: decode(&kind)?,
        })
    })
    .collect()
}

fn load_notification_conditions(
    connection: &Connection,
    notification_id: &str,
) -> Result<Vec<String>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT condition_id FROM notification_conditions
         WHERE notification_id = ?1 ORDER BY condition_id",
    )?;
    statement
        .query_map([notification_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

fn parse_timestamp(value: &str) -> Result<i64, StoreError> {
    value
        .parse::<Timestamp>()
        .map(Timestamp::as_second)
        .map_err(|error| StoreError::InvalidData(format!("invalid timestamp: {error}")))
}

fn schema_checksum() -> String {
    let digest = Sha256::digest(SCHEMA.as_bytes());
    format!("sha256:{}", sentinel_core::hex::encode(&digest))
}

fn set_private_permissions(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(StoreError::Permissions)?;
    }
    Ok(())
}

fn encode<T: Serialize>(value: T) -> Result<String, StoreError> {
    let value =
        serde_json::to_value(value).map_err(|error| StoreError::InvalidData(error.to_string()))?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| StoreError::InvalidData("enum did not serialize as a string".to_owned()))
}

fn decode<T: DeserializeOwned>(value: &str) -> Result<T, StoreError> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|error| StoreError::InvalidData(error.to_string()))
}

fn bool_i64(value: bool) -> i64 {
    i64::from(value)
}

fn i64_from_usize(value: usize) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::InvalidData("value exceeds SQLite integer".to_owned()))
}

fn usize_from_i64(value: i64, label: &str) -> Result<usize, StoreError> {
    usize::try_from(value).map_err(|_| StoreError::InvalidData(format!("{label} is negative")))
}

fn u32_from_i64(value: i64, label: &str) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|_| StoreError::InvalidData(format!("{label} is out of range")))
}

fn u64_from_i64(value: i64, label: &str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::InvalidData(format!("{label} is negative")))
}

fn transition_order(kind: TransitionKind) -> u8 {
    u8::from(kind != TransitionKind::Alert)
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
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
    use rusqlite::params;
    use sentinel_core::{NotificationStatus, OutboxMessage, TransitionKind};
    use tempfile::tempdir;

    use super::{NotificationAttemptOutcome, StateStore, StoreError, prune_runs};

    #[test]
    fn schema_checksum_is_stable() {
        // Independently computed: shasum -a 256 schemas/state-v1.sql. Every
        // existing database carries this value and is validated against it on
        // open, so it may only change when the schema itself does.
        assert_eq!(
            super::schema_checksum(),
            "sha256:c20114ff4e503f57ec4d0da4c9e667ed1158efae9a0b4eb7738f7fef9ca29c1d"
        );
    }

    #[test]
    fn creates_version_one_database_with_private_permissions() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("state.sqlite");
        let store = StateStore::open(&path).expect("store");
        assert_eq!(store.schema_version(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn refuses_a_future_state_schema() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("state.sqlite");
        let store = StateStore::open(&path).expect("store");
        store
            .connection
            .execute_batch("PRAGMA user_version = 2")
            .expect("set version");
        drop(store);
        let error = StateStore::open(&path).expect_err("future schema must fail");
        assert!(matches!(error, StoreError::UnsupportedVersion { .. }));
    }

    #[test]
    fn interrupted_run_transaction_never_appears_complete() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("state.sqlite");
        let mut store = StateStore::open(&path).expect("store");
        {
            let transaction = store.connection.transaction().expect("transaction");
            transaction
                .execute(
                    "INSERT INTO runs(
                       id, started_at, completed_at, mode, config_sha256, status,
                       expected_targets, complete_targets, minimum_targets, exit_code
                     ) VALUES (?1, ?2, ?2, 'dry_run', 'sha256:synthetic', 'complete', 1, 1, 1, 0)",
                    params!["interrupted", "2026-01-01T00:00:00Z"],
                )
                .expect("insert");
        }
        let count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn prevents_live_and_dry_runs_from_sharing_state() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("state.sqlite");
        let store = StateStore::open(&path).expect("store");
        store
            .connection
            .execute(
                "INSERT INTO runs(
                   id, started_at, completed_at, mode, config_sha256, status,
                   expected_targets, complete_targets, minimum_targets, exit_code
                 ) VALUES (?1, ?2, ?2, 'dry_run', 'sha256:synthetic', 'complete', 1, 1, 1, 0)",
                params!["dry-run", "2026-01-01T00:00:00Z"],
            )
            .expect("insert");
        store
            .ensure_run_mode(sentinel_core::RunMode::DryRun)
            .expect("same mode");
        let error = store
            .ensure_run_mode(sentinel_core::RunMode::Live)
            .expect_err("mixed mode must fail");
        assert!(error.to_string().contains("cannot be used"));
    }

    #[test]
    fn retention_pruning_keeps_the_inclusive_cutoff() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("state.sqlite");
        let mut store = StateStore::open(&path).expect("store");
        for (id, completed_at) in [
            ("old", "2026-01-01T00:00:00Z"),
            ("cutoff", "2026-01-02T00:00:00Z"),
            ("new", "2026-01-03T00:00:00Z"),
        ] {
            store
                .connection
                .execute(
                    "INSERT INTO runs(
                       id, started_at, completed_at, mode, config_sha256, status,
                       expected_targets, complete_targets, minimum_targets, exit_code
                     ) VALUES (?1, ?2, ?2, 'dry_run', 'sha256:synthetic', 'complete', 1, 1, 1, 0)",
                    params![id, completed_at],
                )
                .expect("insert");
        }
        let transaction = store.connection.transaction().expect("transaction");
        prune_runs(&transaction, "2026-01-02T00:00:00Z").expect("prune");
        transaction.commit().expect("commit");
        let ids = store
            .connection
            .prepare("SELECT id FROM runs ORDER BY id")
            .expect("statement")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("ids");
        assert_eq!(ids, vec!["cutoff".to_owned(), "new".to_owned()]);
    }

    #[test]
    fn retryable_notification_obeys_backoff_then_can_deliver() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("state.sqlite");
        let mut store = StateStore::open(&path).expect("store");
        store
            .connection
            .execute(
                "INSERT INTO runs(
                   id, started_at, completed_at, mode, config_sha256, status,
                   expected_targets, complete_targets, minimum_targets, exit_code
                 ) VALUES ('run', ?1, ?1, 'live', 'sha256:synthetic', 'complete', 1, 1, 1, 0)",
                ["2026-01-01T00:00:00Z"],
            )
            .expect("run");
        store
            .connection
            .execute(
                "INSERT INTO notification_outbox(
                   id, run_id, transition, title, message, priority, status, created_at
                 ) VALUES ('notification', 'run', 'alert', 'title', '- summary', 0, 'pending', ?1)",
                ["2026-01-01T00:00:00Z"],
            )
            .expect("outbox");
        store
            .connection
            .execute(
                "INSERT INTO notification_conditions(notification_id, condition_id)
                 VALUES ('notification', 'target:a:test')",
                [],
            )
            .expect("condition");
        let message = OutboxMessage {
            id: "notification".to_owned(),
            run_id: "run".to_owned(),
            transition: TransitionKind::Alert,
            title: "title".to_owned(),
            message: "- summary".to_owned(),
            priority: 0,
            status: NotificationStatus::Pending,
            condition_ids: vec!["target:a:test".to_owned()],
        };
        store
            .record_notification_attempt(
                &message,
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:01Z",
                &NotificationAttemptOutcome::Retryable {
                    http_status: Some(503),
                    error_class: "synthetic".to_owned(),
                },
            )
            .expect("retryable");
        assert!(
            store
                .pending_outbox("2026-01-01T00:00:05Z")
                .expect("pending")
                .is_empty()
        );
        assert_eq!(
            store
                .pending_outbox("2026-01-01T00:00:06Z")
                .expect("pending")
                .len(),
            1
        );
        store
            .record_notification_attempt(
                &message,
                "2026-01-01T00:00:06Z",
                "2026-01-01T00:00:07Z",
                &NotificationAttemptOutcome::Delivered {
                    http_status: 200,
                    remote_request_id: "synthetic-request".to_owned(),
                },
            )
            .expect("delivered");
        assert!(
            store
                .pending_outbox("2026-01-01T00:10:00Z")
                .expect("pending")
                .is_empty()
        );
    }
}
