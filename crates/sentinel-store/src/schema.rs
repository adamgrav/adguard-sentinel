use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::{StoreError, canonical_timestamp};

pub(super) const VERSION: i64 = 3;
pub(super) const V1: &str = include_str!("../../../schemas/state-v1.sql");

/// Migration names recorded in `schema_migrations`, indexed by version - 1.
const NAMES: [&str; 3] = ["initial", "durable-delivery", "upstream-response-counts"];

/// A STRICT TEXT column holding a canonical unsigned 64-bit decimal integer.
fn unsigned_text_column(column: &str, nullable: bool) -> String {
    let required = if nullable { "" } else { " NOT NULL" };
    let valid = format!(
        "({column} = '0' OR (substr({column}, 1, 1) BETWEEN '1' AND '9' \
         AND {column} NOT GLOB '*[^0-9]*' AND (length({column}) < 20 \
         OR (length({column}) = 20 AND {column} <= '18446744073709551615'))))"
    );
    let valid = if nullable {
        format!("{column} IS NULL OR {valid}")
    } else {
        valid
    };
    format!("{column} TEXT{required} CHECK ({valid})")
}

/// The current schema; `print-schema state --version 3` generates the
/// checked-in review artifact.
///
/// V3 adds each upstream's response count. Observations recorded before v3
/// keep a NULL count, which latency windows treat as unknown rather than zero.
pub(super) fn current_sql() -> String {
    v2_sql()
        .replace(
            "  average_seconds REAL NOT NULL CHECK (average_seconds >= 0),\n",
            &format!(
                "  average_seconds REAL NOT NULL CHECK (average_seconds >= 0),\n  {},\n",
                unsigned_text_column("responses", true)
            ),
        )
        .replace("PRAGMA user_version = 2;", "PRAGMA user_version = 3;")
}

/// The released v2 schema, derived from the immutable v1 schema. Released v2
/// databases store this derivation's checksum, so it must not change.
pub(super) fn v2_sql() -> String {
    let mut sql = V1.to_owned();
    for (column, nullable) in [
        ("queries", true),
        ("blocked", true),
        ("rules_count", false),
        ("combined_queries", false),
    ] {
        let required = if nullable { "" } else { " NOT NULL" };
        let old = format!("{column} INTEGER{required} CHECK ({column} >= 0)");
        sql = sql.replace(&old, &unsigned_text_column(column, nullable));
    }
    sql = sql.replace(
        "last_transition_run TEXT\n",
        "last_transition_run TEXT,\n  episode_id TEXT\n",
    );
    sql = sql.replace(
        "  blocked_ratio REAL,",
        "  counters_exact INTEGER NOT NULL DEFAULT 1 CHECK (counters_exact IN (0, 1)),\n  blocked_ratio REAL,",
    );
    sql = sql.replace(
        "  exit_code INTEGER NOT NULL CHECK (exit_code BETWEEN 0 AND 5)",
        "  exit_code INTEGER NOT NULL CHECK (exit_code BETWEEN 0 AND 5),\n  health_issues_json TEXT NOT NULL DEFAULT '[]',\n  delivery_activity_json TEXT NOT NULL DEFAULT '[]'",
    );
    sql = sql.replace(
        "  evidence_json TEXT NOT NULL,\n  complete INTEGER",
        "  evidence_json TEXT NOT NULL,\n  episode_id TEXT,\n  complete INTEGER",
    );
    sql = sql.replace(
        "'pending', 'suppressed', 'delivered', 'retryable', 'failed', 'unknown', 'cancelled'",
        "'pending', 'in_flight', 'suppressed', 'delivered', 'retryable', 'failed', 'unknown', 'cancelled'",
    );
    sql = sql.replace(
        "  error_class TEXT\n) STRICT;\n\nCREATE TABLE notification_conditions",
        "  error_class TEXT,\n  attempt_id TEXT\n) STRICT;\n\nCREATE TABLE notification_conditions",
    );
    sql = sql.replace(
        "  condition_id TEXT NOT NULL,\n  PRIMARY KEY (notification_id, condition_id)",
        "  condition_id TEXT NOT NULL,\n  episode_id TEXT NOT NULL,\n  summary TEXT NOT NULL,\n  PRIMARY KEY (notification_id, condition_id)",
    );
    // A NULL completion is the durable indication that a send may be in progress.
    sql = sql.replace(
        "  completed_at TEXT NOT NULL,\n  outcome TEXT NOT NULL,",
        "  completed_at TEXT,\n  outcome TEXT NOT NULL CHECK (outcome IN ('in_flight', 'delivered', 'retryable', 'failed', 'unknown')),",
    );
    sql = sql.replace(
        "  notification_id TEXT NOT NULL REFERENCES notification_outbox(id) ON DELETE CASCADE,\n  started_at TEXT NOT NULL,",
        "  notification_id TEXT NOT NULL REFERENCES notification_outbox(id) ON DELETE CASCADE,\n  executing_run_id TEXT NOT NULL,\n  started_at TEXT NOT NULL,",
    );
    sql.replace(
        "PRAGMA user_version = 1;",
        "CREATE TABLE state_identity (\n  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\n  run_mode TEXT NOT NULL CHECK (run_mode IN ('live', 'dry_run'))\n) STRICT;\n\nPRAGMA user_version = 2;",
    )
}

pub(super) fn checksum(version: i64) -> String {
    let sql = match version {
        1 => V1.to_owned(),
        2 => v2_sql(),
        _ => current_sql(),
    };
    let digest = Sha256::digest(sql.as_bytes());
    format!("sha256:{}", sentinel_core::hex::encode(&digest))
}

pub(super) fn validate(connection: &Connection, expected: i64) -> Result<(), StoreError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != expected {
        return Err(StoreError::UnsupportedVersion {
            observed: version,
            expected,
        });
    }
    for migration in 1..=expected {
        let stored: Option<String> = connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = ?1",
                [migration],
                |row| row.get(0),
            )
            .optional()?;
        if stored.as_deref() != Some(checksum(migration).as_str()) {
            return Err(StoreError::InvalidData(format!(
                "state migration checksum is absent or does not match schema v{migration}"
            )));
        }
    }
    Ok(())
}

pub(super) fn initialize(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction()?;
    // Connection pragmas have already been set, outside the transaction.
    let sql = current_sql()
        .replace("PRAGMA foreign_keys = ON;\n", "")
        .replace("PRAGMA synchronous = FULL;\n", "");
    transaction.execute_batch(&sql)?;
    let applied = format!("{:.9}", jiff::Timestamp::now());
    for version in 1..=VERSION {
        transaction.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (?1, ?2, ?3, ?4)",
            params![version, migration_name(version), checksum(version), applied],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn migration_name(version: i64) -> &'static str {
    usize::try_from(version - 1)
        .ok()
        .and_then(|index| NAMES.get(index))
        .copied()
        .unwrap_or("unknown")
}

/// Upgrades released v1 or v2 state to the current version in one transaction.
pub(super) fn migrate(connection: &mut Connection, from: i64) -> Result<(), StoreError> {
    if !(1..VERSION).contains(&from) {
        return Err(StoreError::UnsupportedVersion {
            observed: from,
            expected: VERSION,
        });
    }
    validate(connection, from)?;
    // Rebuilding referenced tables requires disabling FK enforcement before BEGIN.
    // The complete result is checked inside the transaction before it can commit.
    connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
    let result = migrate_transaction(connection, from);
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    result
}

fn migrate_transaction(connection: &mut Connection, from: i64) -> Result<(), StoreError> {
    let transaction = connection.transaction()?;
    // The v2 step reads observations through the current loader, which needs
    // the v3 count column, so the column is added first.
    add_upstream_response_counts(&transaction)?;
    if from < 2 {
        migrate_to_v2(&transaction)?;
    }
    transaction.execute(
        "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (3, ?1, ?2, ?3)",
        params![
            migration_name(3),
            checksum(3),
            format!("{:.9}", jiff::Timestamp::now())
        ],
    )?;
    let invalid_foreign_keys: i64 =
        transaction.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if invalid_foreign_keys != 0 {
        return Err(StoreError::InvalidData(
            "legacy state contains broken foreign keys".to_owned(),
        ));
    }
    transaction.execute_batch(&format!("PRAGMA user_version = {VERSION};"))?;
    transaction.commit()?;
    Ok(())
}

/// Adds the nullable upstream response count; the table is otherwise
/// identical in v1 and v2. Existing rows keep NULL: their counts were never
/// retained and must not read as zero responses.
fn add_upstream_response_counts(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    rebuild_table(transaction, &current_sql(), "upstream_observations")
}

fn migrate_to_v2(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let modes = {
        let mut statement = transaction.prepare("SELECT DISTINCT mode FROM runs ORDER BY mode")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    if modes.len() > 1 {
        return Err(StoreError::InvalidData(
            "legacy state contains both live and dry-run histories".to_owned(),
        ));
    }
    if modes.is_empty() {
        let count: i64 = transaction.query_row(
            "SELECT (SELECT COUNT(*) FROM condition_state) + (SELECT COUNT(*) FROM target_runtime_state)",
            [], |row| row.get(0),
        )?;
        if count != 0 {
            return Err(StoreError::InvalidData(
                "legacy state has latches but no history establishing its run mode".to_owned(),
            ));
        }
    }
    let current = v2_sql();
    for table in [
        "runs",
        "target_observations",
        "filter_observations",
        "aggregate_observations",
        "condition_evaluations",
        "condition_state",
        "notification_outbox",
        "notification_conditions",
        "notification_attempts",
    ] {
        rebuild_table(transaction, &current, table)?;
    }
    transaction.execute_batch(table_sql(&current, "state_identity")?)?;
    if let Some(mode) = modes.first() {
        transaction.execute(
            "INSERT INTO state_identity(singleton, run_mode) VALUES (1, ?1)",
            [mode],
        )?;
    }
    transaction.execute_batch("CREATE INDEX outbox_status_idx ON notification_outbox(status, created_at); CREATE INDEX runs_completed_at_idx ON runs(completed_at);")?;
    normalize_timestamps(transaction)?;
    // v1 saturated u64 counters to i64::MAX. Keep the reported historical
    // value, but never use an ambiguous count as a rate-window endpoint.
    transaction.execute(
        "UPDATE target_observations SET counters_exact = 0 WHERE queries = '9223372036854775807' OR blocked = '9223372036854775807'", [],
    )?;
    migrate_notification_history(transaction)?;
    migrate_health(transaction)?;
    transaction.execute(
        "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (2, ?1, ?2, ?3)",
        params![
            migration_name(2),
            checksum(2),
            format!("{:.9}", jiff::Timestamp::now())
        ],
    )?;
    Ok(())
}

fn table_sql<'a>(schema: &'a str, table: &str) -> Result<&'a str, StoreError> {
    let start = schema
        .find(&format!("CREATE TABLE {table} ("))
        .ok_or_else(|| StoreError::InvalidData(format!("schema has no table {table}")))?;
    let end = schema[start..]
        .find(") STRICT;")
        .ok_or_else(|| StoreError::InvalidData(format!("schema table {table} is incomplete")))?;
    Ok(&schema[start..start + end + ") STRICT;".len()])
}

fn rebuild_table(
    transaction: &Transaction<'_>,
    schema: &str,
    table: &str,
) -> Result<(), StoreError> {
    let new_table = format!("{table}_rebuild");
    transaction.execute_batch(&table_sql(schema, table)?.replacen(
        &format!("CREATE TABLE {table} ("),
        &format!("CREATE TABLE {new_table} ("),
        1,
    ))?;
    let columns = {
        let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut names = columns.join(", ");
    let mut values = names.clone();
    if table == "notification_conditions" {
        names.push_str(", episode_id, summary");
        values.push_str(", '', ''");
    }
    if table == "notification_attempts" {
        names.push_str(", executing_run_id");
        values.push_str(", (SELECT run_id FROM notification_outbox WHERE id = notification_attempts.notification_id)");
    }
    // All table/column names above are source-owned. Preserve rowid for exact
    // timestamp ties; STRICT TEXT columns convert legacy integers losslessly.
    transaction.execute_batch(&format!(
        "INSERT INTO {new_table}(rowid, {names}) SELECT rowid, {values} FROM {table} ORDER BY rowid; \
         DROP TABLE {table}; ALTER TABLE {new_table} RENAME TO {table};"
    ))?;
    Ok(())
}

fn normalize_timestamps(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    for (table, columns) in [
        ("runs", &["started_at", "completed_at"][..]),
        (
            "notification_outbox",
            &["created_at", "next_retry_at", "delivered_at"][..],
        ),
        ("notification_attempts", &["started_at", "completed_at"][..]),
        (
            "condition_state",
            &["first_observed_at", "last_observed_at"][..],
        ),
        ("schema_migrations", &["applied_at"][..]),
    ] {
        for column in columns {
            let values = {
                let mut statement =
                    transaction.prepare(&format!("SELECT rowid, {column} FROM {table}"))?;
                statement
                    .query_map([], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for (id, value) in values {
                if let Some(value) = value {
                    transaction.execute(
                        &format!("UPDATE {table} SET {column} = ?1 WHERE rowid = ?2"),
                        params![canonical_timestamp(&value)?, id],
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn migrate_notification_history(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    transaction.execute(
        "UPDATE condition_state SET episode_id = 'legacy:' || COALESCE(last_transition_run, 'state') || ':' || condition_id",
        [],
    )?;
    let notifications = {
        let mut statement = transaction.prepare(
            "SELECT id, run_id, message, status, transition FROM notification_outbox ORDER BY created_at, rowid",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut confirmed = std::collections::BTreeSet::new();
    for (id, run_id, message, status, kind) in notifications {
        let members = super::load_notification_conditions(transaction, &id)?;
        let mut summaries = Vec::new();
        for condition_id in &members {
            let evidence: Option<String> = transaction.query_row(
                "SELECT evidence_json FROM condition_evaluations WHERE run_id = ?1 AND condition_id = ?2",
                params![run_id, condition_id], |row| row.get(0),
            ).optional()?;
            let summary = evidence
                .map(|text| serde_json::from_str::<sentinel_core::ConditionEvaluation>(&text))
                .transpose()
                .map_err(|error| StoreError::InvalidData(error.to_string()))?
                .map(|evaluation| evaluation.summary);
            let episode = format!("legacy:{run_id}:{condition_id}");
            transaction.execute(
                "UPDATE notification_conditions SET episode_id = ?3, summary = ?4 WHERE notification_id = ?1 AND condition_id = ?2",
                params![id, condition_id, episode, summary.as_deref().unwrap_or("Legacy transition; original summary unavailable")],
            )?;
            transaction.execute("UPDATE condition_evaluations SET episode_id = ?3 WHERE run_id = ?1 AND condition_id = ?2",
                params![run_id, condition_id, episode])?;
            summaries.push(summary);
        }
        // Matching individual lines is insufficient: a truncated first member
        // can be a complete prefix of a later member. Confirm the entire exact
        // sequence, or quarantine the batch's membership claim.
        let expected = summaries
            .iter()
            .map(|summary| summary.as_ref().map(|summary| format!("- {summary}")))
            .collect::<Option<Vec<_>>>()
            .map(|lines| lines.join("\n"));
        let visible = !members.is_empty()
            && expected.as_deref() == Some(message.as_str())
            && message.chars().count() <= 1_024;
        let acknowledged: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM notification_outbox n JOIN notification_attempts a ON a.notification_id = n.id
             WHERE n.id = ?1 AND length(trim(n.remote_request_id)) > 0 AND a.remote_request_id = n.remote_request_id
               AND a.outcome = 'delivered' AND a.http_status = 200 AND a.completed_at IS NOT NULL)",
            [&id], |row| row.get(0),
        )?;
        let unconfirmed = status == "pending"
            || status == "retryable"
            || (status == "delivered" && (!visible || !acknowledged));
        if unconfirmed {
            transaction.execute(
                "UPDATE notification_outbox SET status = 'unknown', next_retry_at = NULL, error_class = 'legacy_delivery_unconfirmed' WHERE id = ?1",
                [&id],
            )?;
        }
        for condition_id in members {
            let episode = format!("legacy:{run_id}:{condition_id}");
            if status == "delivered" && kind == "alert" && !unconfirmed {
                confirmed.insert((condition_id.clone(), episode.clone()));
            }
            if unconfirmed {
                transaction.execute(
                    "UPDATE condition_state SET alert_delivery_state = 'unknown' WHERE condition_id = ?1 AND episode_id = ?2",
                    params![condition_id, episode],
                )?;
                super::refresh_evaluation(
                    transaction,
                    &run_id,
                    &condition_id,
                    &episode,
                    sentinel_core::AlertDeliveryState::Unknown,
                )?;
            }
        }
    }
    let states = {
        let mut statement = transaction.prepare(
            "SELECT condition_id, episode_id, alert_delivery_state FROM condition_state WHERE alert_delivery_state IN ('pending', 'delivered')",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (condition, episode, delivery) in states {
        if delivery == "pending" || !confirmed.contains(&(condition.clone(), episode)) {
            transaction.execute("UPDATE condition_state SET alert_delivery_state = 'unknown' WHERE condition_id = ?1", [condition])?;
        }
    }
    let latest = {
        let mut statement = transaction.prepare(
            "SELECT e.run_id, e.condition_id, s.episode_id, s.alert_delivery_state
             FROM condition_state s JOIN condition_evaluations e ON e.condition_id = s.condition_id
             WHERE e.run_id = (SELECT e2.run_id FROM condition_evaluations e2 JOIN runs r ON r.id = e2.run_id
                 WHERE e2.condition_id = s.condition_id ORDER BY r.completed_at DESC, r.rowid DESC LIMIT 1)",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (run, condition, episode, delivery) in latest {
        transaction.execute("UPDATE condition_evaluations SET episode_id = ?3 WHERE run_id = ?1 AND condition_id = ?2", params![run, condition, episode])?;
        super::refresh_evaluation(
            transaction,
            &run,
            &condition,
            &episode,
            super::decode(&delivery)?,
        )?;
    }
    Ok(())
}

fn migrate_health(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let runs = {
        let mut statement =
            transaction.prepare("SELECT id, complete_targets, minimum_targets FROM runs")?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (run, complete, minimum) in runs {
        let mut issues = super::load_targets(transaction, &run)?
            .into_iter()
            .filter(|target| !target.complete)
            .map(|target| {
                format!(
                    "target {} incomplete: {}",
                    target.id,
                    target.error_kind.as_deref().unwrap_or("unknown")
                )
            })
            .collect::<Vec<_>>();
        if complete < minimum {
            issues.push("minimum complete target count was not met".to_owned());
        }
        transaction.execute(
            "UPDATE runs SET health_issues_json = ?2 WHERE id = ?1",
            params![
                run,
                serde_json::to_string(&issues)
                    .map_err(|error| StoreError::InvalidData(error.to_string()))?
            ],
        )?;
    }
    Ok(())
}
