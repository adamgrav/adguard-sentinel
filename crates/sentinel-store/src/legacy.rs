use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use rusqlite::{Transaction, params};
use sentinel_core::{
    AlertDeliveryState, ConditionLifecycle, ConditionState, Config, Severity, TargetStatus,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::store::{StateStore, StoreError, upsert_condition_state};

const MAX_LEGACY_BYTES: u64 = 16 * 1_048_576;

#[derive(Clone, Debug)]
pub struct LegacyImportSummary {
    pub source_sha256: String,
    pub samples: usize,
    pub conditions: usize,
    pub auth_cooldowns: usize,
    pub latest_targets: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyState {
    version: u32,
    #[serde(default)]
    samples: Vec<LegacySample>,
    #[serde(default)]
    conditions: BTreeMap<String, LegacyCondition>,
    #[serde(default)]
    auth_failures: BTreeMap<String, i64>,
    latest: Option<LegacyLatest>,
    last_successful_run: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySample {
    timestamp: i64,
    local_hour: i64,
    combined_queries: u64,
    combined_blocked_ratio: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCondition {
    consecutive: u32,
    notified: bool,
    summary: String,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct LegacyLatest {
    timestamp: i64,
    #[serde(default)]
    targets: BTreeMap<String, LegacyTarget>,
    baseline_ready: bool,
    learning_age_days: Option<f64>,
    combined_queries: Option<u64>,
    combined_blocked_ratio: Option<f64>,
    resolver_query_share: Option<BTreeMap<String, f64>>,
    top_client_share: Option<BTreeMap<String, f64>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyTarget {
    protection_enabled: bool,
    queries: u64,
    blocked: u64,
    blocked_ratio: f64,
    average_processing_seconds: f64,
    maximum_upstream_seconds: f64,
    top_client_share: f64,
}

impl StateStore {
    pub fn import_legacy_json(
        source: &Path,
        destination: &Path,
        config: &Config,
        imported_at: &str,
    ) -> Result<LegacyImportSummary, StoreError> {
        if destination.exists() {
            return Err(StoreError::InvalidData(format!(
                "destination already exists: {}",
                destination.display()
            )));
        }
        let metadata = fs::metadata(source)?;
        if !metadata.is_file() || metadata.len() > MAX_LEGACY_BYTES {
            return Err(StoreError::InvalidData(
                "legacy source must be a regular file no larger than 16 MiB".to_owned(),
            ));
        }
        let bytes = fs::read(source)?;
        let source_sha256 = format!("sha256:{:x}", Sha256::digest(&bytes));
        let legacy: LegacyState = serde_json::from_slice(&bytes)
            .map_err(|error| StoreError::InvalidData(format!("invalid legacy JSON: {error}")))?;
        validate_legacy(&legacy, config)?;

        let temporary = temporary_state_path(destination)?;
        if temporary.exists() {
            return Err(StoreError::InvalidData(format!(
                "temporary import destination already exists: {}",
                temporary.display()
            )));
        }
        let result: Result<(), StoreError> = (|| {
            let mut store = StateStore::open(&temporary)?;
            let transaction = store.connection.transaction()?;
            let target_mapping: BTreeMap<_, _> = config
                .targets
                .iter()
                .map(|target| (target.name.clone(), target.id.clone()))
                .collect();
            transaction.execute(
                "INSERT INTO legacy_imports(
                   id, source_sha256, source_version, imported_at, target_mapping_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    Uuid::new_v4().to_string(),
                    source_sha256,
                    i64::from(legacy.version),
                    imported_at,
                    serde_json::to_string(&target_mapping)
                        .map_err(|error| StoreError::InvalidData(error.to_string()))?,
                ],
            )?;
            import_samples(&transaction, &legacy, &source_sha256)?;
            let import_run_id =
                import_latest(&transaction, &legacy, config, imported_at, &source_sha256)?;
            import_conditions(&transaction, &legacy, config, &import_run_id, imported_at)?;
            import_auth_cooldowns(&transaction, &legacy, config)?;
            transaction.commit()?;
            drop(store);
            fs::rename(&temporary, destination)?;
            Ok(())
        })();
        if result.is_err() && temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        Ok(LegacyImportSummary {
            source_sha256,
            samples: legacy.samples.len(),
            conditions: legacy.conditions.len(),
            auth_cooldowns: legacy.auth_failures.len(),
            latest_targets: legacy
                .latest
                .as_ref()
                .map_or(0, |latest| latest.targets.len()),
        })
    }
}

fn validate_legacy(legacy: &LegacyState, config: &Config) -> Result<(), StoreError> {
    if legacy.version != 1 {
        return Err(StoreError::InvalidData(format!(
            "legacy state version {} is unsupported",
            legacy.version
        )));
    }
    for sample in &legacy.samples {
        if sample.timestamp < 0
            || !(0..=23).contains(&sample.local_hour)
            || !valid_ratio(sample.combined_blocked_ratio)
        {
            return Err(StoreError::InvalidData(
                "legacy sample contains invalid timestamp, hour, or ratio".to_owned(),
            ));
        }
    }
    let target_names: BTreeSet<_> = config
        .targets
        .iter()
        .map(|target| target.name.as_str())
        .collect();
    for (name, timestamp) in &legacy.auth_failures {
        if !target_names.contains(name.as_str()) || *timestamp < 0 {
            return Err(StoreError::InvalidData(
                "legacy authentication cooldown has an unknown target or timestamp".to_owned(),
            ));
        }
    }
    for key in legacy.conditions.keys() {
        map_condition_id(key, config)?;
    }
    if let Some(latest) = &legacy.latest {
        if latest.timestamp < 0
            || (latest.baseline_ready && latest.combined_queries.is_none())
            || (latest.combined_queries.is_none() && latest.combined_blocked_ratio.is_some())
            || latest
                .learning_age_days
                .is_some_and(|value| !value.is_finite() || value < 0.0)
            || latest
                .combined_blocked_ratio
                .is_some_and(|value| !valid_ratio(value))
            || latest
                .resolver_query_share
                .as_ref()
                .is_some_and(|values| values.values().any(|value| !valid_ratio(*value)))
            || latest
                .top_client_share
                .as_ref()
                .is_some_and(|values| values.values().any(|value| !valid_ratio(*value)))
        {
            return Err(StoreError::InvalidData(
                "legacy latest aggregate contains invalid data".to_owned(),
            ));
        }
        for (name, target) in &latest.targets {
            if !target_names.contains(name.as_str()) {
                return Err(StoreError::InvalidData(format!(
                    "legacy latest contains unknown target {name:?}"
                )));
            }
            if target.blocked > target.queries
                || !valid_ratio(target.blocked_ratio)
                || !valid_nonnegative(target.average_processing_seconds)
                || !valid_nonnegative(target.maximum_upstream_seconds)
                || !valid_ratio(target.top_client_share)
            {
                return Err(StoreError::InvalidData(format!(
                    "legacy target {name:?} contains invalid data"
                )));
            }
        }
    }
    if legacy.last_successful_run.is_some_and(|value| value < 0) {
        return Err(StoreError::InvalidData(
            "legacy last_successful_run is negative".to_owned(),
        ));
    }
    Ok(())
}

fn import_samples(
    transaction: &Transaction<'_>,
    legacy: &LegacyState,
    source_sha256: &str,
) -> Result<(), StoreError> {
    for (index, sample) in legacy.samples.iter().enumerate() {
        let timestamp = timestamp_string(sample.timestamp)?;
        let run_id = format!("legacy-sample-{}-{index}", sample.timestamp);
        transaction.execute(
            "INSERT INTO runs(
               id, started_at, completed_at, mode, config_sha256, status,
               expected_targets, complete_targets, minimum_targets, exit_code
             ) VALUES (?1, ?2, ?2, 'legacy_import', ?3, 'legacy_import', 0, 0, 0, 0)",
            params![run_id, timestamp, source_sha256],
        )?;
        transaction.execute(
            "INSERT INTO aggregate_observations(
               run_id, local_hour, utc_offset_minutes, combined_queries,
               combined_blocked_ratio, baseline_age_seconds, same_hour_samples,
               baseline_ready, volume_limit, ratio_limit, resolver_query_share_json,
               top_client_share_json
             ) VALUES (?1, ?2, 0, ?3, ?4, 0, 0, 0, NULL, NULL, '{}', '{}')",
            params![
                run_id,
                sample.local_hour,
                i64::try_from(sample.combined_queries).unwrap_or(i64::MAX),
                sample.combined_blocked_ratio,
            ],
        )?;
    }
    Ok(())
}

fn import_latest(
    transaction: &Transaction<'_>,
    legacy: &LegacyState,
    config: &Config,
    imported_at: &str,
    source_sha256: &str,
) -> Result<String, StoreError> {
    let run_id = format!("legacy-import-{}", Uuid::new_v4());
    let completed_at = legacy
        .latest
        .as_ref()
        .map(|latest| timestamp_string(latest.timestamp))
        .transpose()?
        .unwrap_or_else(|| imported_at.to_owned());
    let complete_targets = legacy
        .latest
        .as_ref()
        .map_or(0, |latest| latest.targets.len());
    transaction.execute(
        "INSERT INTO runs(
           id, started_at, completed_at, mode, config_sha256, status,
           expected_targets, complete_targets, minimum_targets, exit_code
         ) VALUES (?1, ?2, ?2, 'legacy_import', ?3, 'legacy_import', ?4, ?5, 0, 0)",
        params![
            run_id,
            completed_at,
            source_sha256,
            i64::try_from(config.targets.len()).unwrap_or(i64::MAX),
            i64::try_from(complete_targets).unwrap_or(i64::MAX),
        ],
    )?;
    for target in &config.targets {
        let observed = legacy
            .latest
            .as_ref()
            .and_then(|latest| latest.targets.get(&target.name));
        let status = if observed.is_some() {
            TargetStatus::Complete
        } else {
            TargetStatus::Unavailable
        };
        transaction.execute(
            "INSERT INTO target_observations(
               run_id, target_id, target_name, status, complete, protection_enabled,
               queries, blocked, blocked_ratio, average_processing_seconds,
               maximum_upstream_seconds, top_client_share, error_kind, error_detail
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                run_id,
                target.id,
                target.name,
                enum_string(status)?,
                i64::from(observed.is_some()),
                observed.map(|value| i64::from(value.protection_enabled)),
                observed.map(|value| i64::try_from(value.queries).unwrap_or(i64::MAX)),
                observed.map(|value| i64::try_from(value.blocked).unwrap_or(i64::MAX)),
                observed.map(|value| value.blocked_ratio),
                observed.map(|value| value.average_processing_seconds),
                observed.map(|value| value.maximum_upstream_seconds),
                observed.map(|value| value.top_client_share),
                observed.is_none().then_some("legacy_missing_target"),
                observed
                    .is_none()
                    .then_some("target was absent from the legacy latest snapshot"),
            ],
        )?;
    }
    Ok(run_id)
}

fn import_conditions(
    transaction: &Transaction<'_>,
    legacy: &LegacyState,
    config: &Config,
    import_run_id: &str,
    imported_at: &str,
) -> Result<(), StoreError> {
    for (legacy_id, condition) in &legacy.conditions {
        let (id, target_id, kind, severity) = map_condition_id(legacy_id, config)?;
        let state = ConditionState {
            id: id.clone(),
            target_id,
            kind,
            severity,
            lifecycle: if condition.notified {
                ConditionLifecycle::Firing
            } else if condition.consecutive > 0 {
                ConditionLifecycle::Pending
            } else {
                ConditionLifecycle::Clear
            },
            first_observed_at: None,
            last_observed_at: Some(imported_at.to_owned()),
            active_count: condition.consecutive,
            clear_count: 0,
            alert_delivery_state: if condition.notified {
                AlertDeliveryState::AssumedDeliveredLegacy
            } else {
                AlertDeliveryState::Never
            },
            last_transition_run: condition.notified.then(|| import_run_id.to_owned()),
        };
        upsert_condition_state(transaction, &state)?;
        if condition.notified {
            let notification_id = Uuid::new_v4().to_string();
            transaction.execute(
                "INSERT INTO notification_outbox(
                   id, run_id, transition, title, message, priority, status,
                   created_at, delivered_at, error_class
                 ) VALUES (?1, ?2, 'alert', 'AdGuard anomaly detected', ?3, 0,
                           'delivered', ?4, ?4, 'assumed_delivered_legacy')",
                params![
                    notification_id,
                    import_run_id,
                    format!("- {}: {}", condition.summary, condition.detail),
                    imported_at,
                ],
            )?;
            transaction.execute(
                "INSERT INTO notification_conditions(notification_id, condition_id) VALUES (?1, ?2)",
                params![notification_id, id],
            )?;
        }
    }
    Ok(())
}

fn import_auth_cooldowns(
    transaction: &Transaction<'_>,
    legacy: &LegacyState,
    config: &Config,
) -> Result<(), StoreError> {
    for (name, failed_at) in &legacy.auth_failures {
        let target = config
            .targets
            .iter()
            .find(|target| target.name == *name)
            .ok_or_else(|| StoreError::InvalidData("legacy auth target is unknown".to_owned()))?;
        let profile = config
            .condition_profiles
            .get(&target.condition_profile)
            .ok_or_else(|| {
                StoreError::InvalidData("target condition profile is unknown".to_owned())
            })?;
        let retry_after = failed_at.saturating_add(
            i64::try_from(profile.authentication_retry_seconds).unwrap_or(i64::MAX),
        );
        transaction.execute(
            "INSERT INTO target_runtime_state(target_id, auth_failed_at, auth_retry_after)
             VALUES (?1, ?2, ?3)",
            params![target.id, failed_at, retry_after],
        )?;
    }
    Ok(())
}

fn map_condition_id(
    legacy_id: &str,
    config: &Config,
) -> Result<(String, Option<String>, String, Severity), StoreError> {
    if matches!(
        legacy_id,
        "aggregate:query-spike" | "aggregate:blocked-ratio"
    ) {
        let kind = if legacy_id.ends_with("query-spike") {
            "combined_query_volume_anomaly"
        } else {
            "combined_blocked_ratio_anomaly"
        };
        return Ok((
            legacy_id.to_owned(),
            None,
            kind.to_owned(),
            Severity::Warning,
        ));
    }
    let mut parts = legacy_id.split(':');
    let prefix = parts.next();
    let name = parts.next();
    let suffix = parts.next();
    if prefix != Some("target") || parts.next().is_some() {
        return Err(StoreError::InvalidData(format!(
            "unknown legacy condition {legacy_id:?}"
        )));
    }
    let name =
        name.ok_or_else(|| StoreError::InvalidData("legacy condition has no target".to_owned()))?;
    let target = config
        .targets
        .iter()
        .find(|target| target.name == name)
        .ok_or_else(|| {
            StoreError::InvalidData(format!("unknown legacy condition target {name:?}"))
        })?;
    let (new_suffix, kind, severity) = match suffix {
        Some("api") => ("api", "api", Severity::Warning),
        Some("protection") => ("protection", "protection_disabled", Severity::Critical),
        Some("processing-latency") => (
            "processing-latency",
            "processing_latency",
            Severity::Warning,
        ),
        Some("upstream-latency") => ("upstream-latency", "upstream_latency", Severity::Warning),
        _ => {
            return Err(StoreError::InvalidData(format!(
                "unknown legacy condition {legacy_id:?}"
            )));
        }
    };
    Ok((
        format!("target:{}:{new_suffix}", target.id),
        Some(target.id.clone()),
        kind.to_owned(),
        severity,
    ))
}

fn temporary_state_path(destination: &Path) -> Result<PathBuf, StoreError> {
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| StoreError::InvalidData("destination filename is not UTF-8".to_owned()))?;
    Ok(destination.with_file_name(format!(".{file_name}.import.tmp")))
}

fn timestamp_string(seconds: i64) -> Result<String, StoreError> {
    Timestamp::new(seconds, 0)
        .map(|timestamp| timestamp.to_string())
        .map_err(|error| StoreError::InvalidData(format!("invalid legacy timestamp: {error}")))
}

fn valid_ratio(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn valid_nonnegative(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

fn enum_string<T: serde::Serialize>(value: T) -> Result<String, StoreError> {
    let value =
        serde_json::to_value(value).map_err(|error| StoreError::InvalidData(error.to_string()))?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| StoreError::InvalidData("enum did not serialize to string".to_owned()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use sentinel_core::config::{
        BehavioralBaselineConfig, ConditionProfile, Config, NotificationConfig,
        NotificationProvider, ObservationConfig, PolicyConfig, RequiredRewrites, StateConfig,
        TargetConfig,
    };
    use tempfile::tempdir;

    use super::StateStore;

    #[test]
    fn rejects_invalid_legacy_without_creating_destination() {
        let directory = tempdir().expect("tempdir");
        let source = directory.path().join("legacy.json");
        let destination = directory.path().join("state.sqlite");
        fs::write(&source, r#"{"version":1,"samples":[{"timestamp":1,"local_hour":99,"combined_queries":1,"combined_blocked_ratio":0.1}],"conditions":{},"auth_failures":{}}"#).expect("write");
        let error = StateStore::import_legacy_json(
            &source,
            &destination,
            &config(directory.path().join("secret")),
            "2026-01-01T00:00:00Z",
        )
        .expect_err("must reject");
        assert!(error.to_string().contains("legacy sample"));
        assert!(!destination.exists());
    }

    #[test]
    fn imports_valid_legacy_state_without_changing_source() {
        let directory = tempdir().expect("tempdir");
        let source = directory.path().join("legacy.json");
        let destination = directory.path().join("state.sqlite");
        let content = r#"{
          "version": 1,
          "samples": [{
            "timestamp": 1700000000,
            "local_hour": 12,
            "combined_queries": 100,
            "combined_blocked_ratio": 0.1
          }],
          "conditions": {
            "target:Resolver A:api": {
              "consecutive": 1,
              "notified": true,
              "summary": "Resolver A API authentication failed",
              "detail": "synthetic"
            }
          },
          "auth_failures": {"Resolver A": 1700000000},
          "latest": {
            "timestamp": 1700000000,
            "targets": {
              "Resolver A": {
                "protection_enabled": true,
                "queries": 100,
                "blocked": 10,
                "blocked_ratio": 0.1,
                "average_processing_seconds": 0.01,
                "maximum_upstream_seconds": 0.02,
                "top_client_share": 0.2
              }
            },
            "baseline_ready": false,
            "learning_age_days": 0.0,
            "combined_queries": 100,
            "combined_blocked_ratio": 0.1,
            "resolver_query_share": {"Resolver A": 1.0},
            "top_client_share": {"Resolver A": 0.2}
          },
          "last_successful_run": 1700000000
        }"#;
        fs::write(&source, content).expect("write");
        let summary = StateStore::import_legacy_json(
            &source,
            &destination,
            &config(directory.path().join("secret")),
            "2026-01-01T00:00:00Z",
        )
        .expect("valid import");
        assert_eq!(summary.samples, 1);
        assert_eq!(summary.conditions, 1);
        assert_eq!(fs::read_to_string(&source).expect("source"), content);
        let store = StateStore::open(&destination).expect("imported state");
        assert_eq!(
            store
                .target_runtime_state("resolver-a")
                .expect("runtime state")
                .expect("cooldown")
                .auth_retry_after,
            Some(1_700_000_900)
        );
        let delivery: String = store
            .connection
            .query_row(
                "SELECT alert_delivery_state FROM condition_state WHERE condition_id = 'target:resolver-a:api'",
                [],
                |row| row.get(0),
            )
            .expect("condition");
        assert_eq!(delivery, "assumed_delivered_legacy");
    }

    fn config(password_file: PathBuf) -> Config {
        let profile = ConditionProfile {
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
        };
        Config {
            schema_version: 1,
            state: StateConfig {
                path: PathBuf::from("/tmp/state.sqlite"),
                retention_days: 21,
            },
            observation: ObservationConfig {
                request_timeout_ms: 5_000,
                notification_timeout_ms: 15_000,
                max_response_bytes: 4_194_304,
                stats_lookback_ms: 3_600_000,
                target_concurrency: 1,
                minimum_complete_targets: 1,
                adguard_version_requirement: ">=0.107.78,<0.108.0".to_owned(),
            },
            behavioral_baseline: BehavioralBaselineConfig {
                target_ids: vec!["resolver-a".to_owned()],
                time_zone: "Europe/Amsterdam".to_owned(),
                learning_days: 7,
                minimum_same_hour_samples: 36,
            },
            condition_profiles: [("current".to_owned(), profile)].into(),
            notifications: NotificationConfig {
                provider: NotificationProvider::Disabled,
                pushover: None,
            },
            policies: [(
                "test".to_owned(),
                PolicyConfig {
                    protection_enabled: true,
                    upstream_mode: "load_balance".to_owned(),
                    upstream_dns: vec!["tls://resolver.invalid".to_owned()],
                    filters: Vec::new(),
                    rewrites: RequiredRewrites {
                        enabled: true,
                        required: Vec::new(),
                    },
                },
            )]
            .into(),
            targets: vec![TargetConfig {
                id: "resolver-a".to_owned(),
                name: "Resolver A".to_owned(),
                base_url: "https://resolver-a.invalid".to_owned(),
                username: "admin".to_owned(),
                password_file,
                policy: "test".to_owned(),
                condition_profile: "current".to_owned(),
                allow_insecure_local_http: false,
            }],
        }
    }
}
