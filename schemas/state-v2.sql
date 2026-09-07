PRAGMA foreign_keys = ON;
PRAGMA synchronous = FULL;

CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  checksum TEXT NOT NULL,
  applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE runs (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('live', 'dry_run')),
  config_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('complete', 'partial', 'unhealthy')),
  expected_targets INTEGER NOT NULL CHECK (expected_targets >= 0),
  complete_targets INTEGER NOT NULL CHECK (complete_targets >= 0),
  minimum_targets INTEGER NOT NULL CHECK (minimum_targets >= 0),
  exit_code INTEGER NOT NULL CHECK (exit_code BETWEEN 0 AND 5),
  health_issues_json TEXT NOT NULL DEFAULT '[]',
  delivery_activity_json TEXT NOT NULL DEFAULT '[]'
) STRICT;

CREATE TABLE target_observations (
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL,
  target_name TEXT NOT NULL,
  status TEXT NOT NULL,
  complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
  server_version TEXT,
  protection_enabled INTEGER CHECK (protection_enabled IN (0, 1)),
  queries TEXT CHECK (queries IS NULL OR (queries = '0' OR (substr(queries, 1, 1) BETWEEN '1' AND '9' AND queries NOT GLOB '*[^0-9]*' AND (length(queries) < 20 OR (length(queries) = 20 AND queries <= '18446744073709551615'))))),
  blocked TEXT CHECK (blocked IS NULL OR (blocked = '0' OR (substr(blocked, 1, 1) BETWEEN '1' AND '9' AND blocked NOT GLOB '*[^0-9]*' AND (length(blocked) < 20 OR (length(blocked) = 20 AND blocked <= '18446744073709551615'))))),
  counters_exact INTEGER NOT NULL DEFAULT 1 CHECK (counters_exact IN (0, 1)),
  blocked_ratio REAL,
  average_processing_seconds REAL,
  maximum_upstream_seconds REAL,
  top_client_share REAL,
  dns_upstream_mode TEXT,
  dns_upstream_json TEXT,
  filtering_enabled INTEGER CHECK (filtering_enabled IN (0, 1)),
  rewrites_enabled INTEGER CHECK (rewrites_enabled IN (0, 1)),
  error_kind TEXT,
  error_detail TEXT,
  PRIMARY KEY (run_id, target_id)
) STRICT;

CREATE TABLE upstream_observations (
  run_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  upstream_identity TEXT NOT NULL,
  average_seconds REAL NOT NULL CHECK (average_seconds >= 0),
  PRIMARY KEY (run_id, target_id, upstream_identity),
  FOREIGN KEY (run_id, target_id) REFERENCES target_observations(run_id, target_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE filter_observations (
  run_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  filter_url TEXT NOT NULL,
  server_id INTEGER NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  rules_count TEXT NOT NULL CHECK ((rules_count = '0' OR (substr(rules_count, 1, 1) BETWEEN '1' AND '9' AND rules_count NOT GLOB '*[^0-9]*' AND (length(rules_count) < 20 OR (length(rules_count) = 20 AND rules_count <= '18446744073709551615'))))),
  last_updated TEXT,
  last_updated_unix_seconds INTEGER,
  PRIMARY KEY (run_id, target_id, filter_url),
  FOREIGN KEY (run_id, target_id) REFERENCES target_observations(run_id, target_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE rewrite_observations (
  run_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  answer TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  PRIMARY KEY (run_id, target_id, domain, answer),
  FOREIGN KEY (run_id, target_id) REFERENCES target_observations(run_id, target_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE aggregate_observations (
  run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
  local_hour INTEGER NOT NULL CHECK (local_hour BETWEEN 0 AND 23),
  utc_offset_minutes INTEGER NOT NULL,
  combined_queries TEXT NOT NULL CHECK ((combined_queries = '0' OR (substr(combined_queries, 1, 1) BETWEEN '1' AND '9' AND combined_queries NOT GLOB '*[^0-9]*' AND (length(combined_queries) < 20 OR (length(combined_queries) = 20 AND combined_queries <= '18446744073709551615'))))),
  combined_blocked_ratio REAL NOT NULL CHECK (combined_blocked_ratio >= 0 AND combined_blocked_ratio <= 1),
  baseline_age_seconds INTEGER NOT NULL CHECK (baseline_age_seconds >= 0),
  same_hour_samples INTEGER NOT NULL CHECK (same_hour_samples >= 0),
  baseline_ready INTEGER NOT NULL CHECK (baseline_ready IN (0, 1)),
  volume_limit REAL,
  ratio_limit REAL,
  resolver_query_share_json TEXT NOT NULL,
  top_client_share_json TEXT NOT NULL
) STRICT;

CREATE TABLE condition_evaluations (
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  condition_id TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('active', 'clear', 'not_evaluated')),
  expected_json TEXT NOT NULL,
  observed_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  episode_id TEXT,
  complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
  PRIMARY KEY (run_id, condition_id)
) STRICT;

CREATE TABLE condition_state (
  condition_id TEXT PRIMARY KEY,
  target_id TEXT,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('warning', 'error', 'critical')),
  lifecycle TEXT NOT NULL CHECK (lifecycle IN ('clear', 'pending', 'firing')),
  first_observed_at TEXT,
  last_observed_at TEXT,
  active_count INTEGER NOT NULL CHECK (active_count >= 0),
  clear_count INTEGER NOT NULL CHECK (clear_count >= 0),
  alert_delivery_state TEXT NOT NULL CHECK (alert_delivery_state IN (
    'never', 'pending', 'delivered', 'suppressed', 'failed', 'unknown', 'resolved'
  )),
  last_transition_run TEXT,
  episode_id TEXT
) STRICT;

CREATE TABLE target_runtime_state (
  target_id TEXT PRIMARY KEY,
  auth_failed_at INTEGER,
  auth_retry_after INTEGER
) STRICT;

CREATE TABLE notification_outbox (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  transition TEXT NOT NULL CHECK (transition IN ('alert', 'resolution')),
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  priority INTEGER NOT NULL CHECK (priority BETWEEN -2 AND 2),
  status TEXT NOT NULL CHECK (status IN (
    'pending', 'in_flight', 'suppressed', 'delivered', 'retryable', 'failed', 'unknown', 'cancelled'
  )),
  created_at TEXT NOT NULL,
  next_retry_at TEXT,
  delivered_at TEXT,
  remote_request_id TEXT,
  error_class TEXT,
  attempt_id TEXT
) STRICT;

CREATE TABLE notification_conditions (
  notification_id TEXT NOT NULL REFERENCES notification_outbox(id) ON DELETE CASCADE,
  condition_id TEXT NOT NULL,
  episode_id TEXT NOT NULL,
  summary TEXT NOT NULL,
  PRIMARY KEY (notification_id, condition_id)
) STRICT;

CREATE TABLE notification_attempts (
  id TEXT PRIMARY KEY,
  notification_id TEXT NOT NULL REFERENCES notification_outbox(id) ON DELETE CASCADE,
  executing_run_id TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('in_flight', 'delivered', 'retryable', 'failed', 'unknown')),
  http_status INTEGER,
  remote_request_id TEXT,
  error_class TEXT
) STRICT;

CREATE INDEX runs_completed_at_idx ON runs(completed_at);
CREATE INDEX outbox_status_idx ON notification_outbox(status, created_at);

CREATE TABLE state_identity (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  run_mode TEXT NOT NULL CHECK (run_mode IN ('live', 'dry_run'))
) STRICT;

PRAGMA user_version = 2;
