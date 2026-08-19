use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use semver::VersionReq;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Host, Url};

const CONFIG_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: u64 = 1_048_576;
const MAX_TARGETS: usize = 64;
const MAX_RESPONSE_BYTES: u64 = 16 * 1_048_576;
const SUPPORTED_ADGUARD_REQUIREMENT: &str = ">=0.107.78,<0.108.0";
const DEFAULT_CONDITION_PROFILE_ID: &str = "current";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot inspect configuration {path}")]
    Inspect {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("configuration {path} is {size} bytes; maximum is {maximum}")]
    TooLarge {
        path: PathBuf,
        size: u64,
        maximum: u64,
    },
    #[error("cannot read configuration {path}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("configuration is not valid TOML")]
    Decode(#[from] toml::de::Error),
    #[error("configuration validation failed:\n- {0}")]
    Validation(String),
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    #[serde(default)]
    pub state: StateConfig,
    #[serde(default)]
    pub observation: ObservationConfig,
    pub behavioral_baseline: Option<BehavioralBaselineConfig>,
    #[serde(default = "default_condition_profiles")]
    pub condition_profiles: BTreeMap<String, ConditionProfile>,
    #[serde(default)]
    pub notifications: NotificationConfig,
    #[serde(default)]
    pub policies: BTreeMap<String, PolicyConfig>,
    pub targets: Vec<TargetConfig>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    pub path: PathBuf,
    pub retention_days: u32,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/adguard-sentinel/state.sqlite"),
            retention_days: 21,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationConfig {
    pub request_timeout_ms: u64,
    pub notification_timeout_ms: u64,
    pub max_response_bytes: u64,
    pub stats_lookback_ms: u64,
    pub target_concurrency: usize,
    pub minimum_complete_targets: usize,
    pub adguard_version_requirement: String,
    /// Accept an `adguard_version_requirement` outside the range this release
    /// has recorded evidence for. Defaults to false, so the tested range is
    /// what you get unless you say otherwise. An accepted untested range is
    /// still enforced at the request boundary; only the choice of range is
    /// widened, never the strictness of the check.
    #[serde(default)]
    pub allow_untested_adguard_version: bool,
}

impl Default for ObservationConfig {
    fn default() -> Self {
        Self {
            request_timeout_ms: 5_000,
            notification_timeout_ms: 15_000,
            max_response_bytes: 4_194_304,
            stats_lookback_ms: 3_600_000,
            target_concurrency: 2,
            minimum_complete_targets: 1,
            adguard_version_requirement: SUPPORTED_ADGUARD_REQUIREMENT.to_owned(),
            allow_untested_adguard_version: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehavioralBaselineConfig {
    pub target_ids: Vec<String>,
    pub time_zone: String,
    pub learning_days: u32,
    pub minimum_same_hour_samples: usize,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionProfile {
    pub authentication_rejected_sustain_runs: u32,
    pub api_unavailable_sustain_runs: u32,
    pub invalid_response_sustain_runs: u32,
    pub unsupported_version_sustain_runs: u32,
    pub protection_disabled_sustain_runs: u32,
    pub processing_latency_sustain_runs: u32,
    pub upstream_latency_sustain_runs: u32,
    pub policy_drift_sustain_runs: u32,
    pub behavioral_anomaly_sustain_runs: u32,
    pub recovery_runs: u32,
    pub authentication_retry_seconds: u64,
    pub processing_latency_ms: u64,
    pub upstream_latency_ms: u64,
}

impl Default for ConditionProfile {
    fn default() -> Self {
        Self {
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

fn default_condition_profiles() -> BTreeMap<String, ConditionProfile> {
    BTreeMap::from([(
        DEFAULT_CONDITION_PROFILE_ID.to_owned(),
        ConditionProfile::default(),
    )])
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationProvider {
    Disabled,
    Pushover,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetAuth {
    None,
    #[default]
    Basic,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationConfig {
    pub provider: NotificationProvider,
    pub pushover: Option<PushoverConfig>,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            provider: NotificationProvider::Disabled,
            pushover: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushoverConfig {
    pub application_token_file: PathBuf,
    pub user_key_file: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub protection_enabled: Option<bool>,
    pub upstream_mode: Option<String>,
    pub upstream_dns: Option<Vec<String>>,
    #[serde(default)]
    pub filters: Vec<RequiredFilter>,
    #[serde(default)]
    pub rewrites: RequiredRewrites,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredFilter {
    pub url: String,
    pub enabled: bool,
    pub maximum_age_hours: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredRewrites {
    pub enabled: Option<bool>,
    #[serde(default)]
    pub required: Vec<RequiredRewrite>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredRewrite {
    pub domain: String,
    pub answer: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub id: String,
    pub name: String,
    pub base_url: String,
    #[serde(default)]
    pub auth: TargetAuth,
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
    pub policy: Option<String>,
    #[serde(default = "default_condition_profile_id")]
    pub condition_profile: String,
    #[serde(default)]
    pub allow_insecure_local_http: bool,
}

fn default_condition_profile_id() -> String {
    DEFAULT_CONDITION_PROFILE_ID.to_owned()
}

impl Config {
    pub fn load(path: &Path, check_secret_files: bool) -> Result<Self, ConfigError> {
        let metadata = fs::metadata(path).map_err(|source| ConfigError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                path: path.to_path_buf(),
                size: metadata.len(),
                maximum: MAX_CONFIG_BYTES,
            });
        }
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = toml::from_str(&text)?;
        config.validate(check_secret_files)?;
        Ok(config)
    }

    pub fn validate(&self, check_secret_files: bool) -> Result<(), ConfigError> {
        let mut errors = Vec::new();
        if self.schema_version != CONFIG_VERSION {
            errors.push(format!(
                "schema_version must be {CONFIG_VERSION}, got {}",
                self.schema_version
            ));
        }
        validate_absolute_path("state.path", &self.state.path, &mut errors);
        if self.state.retention_days == 0 {
            errors.push("state.retention_days must be positive".to_owned());
        }
        if let Some(baseline) = &self.behavioral_baseline
            && self.state.retention_days < baseline.learning_days
        {
            errors.push(
                "state.retention_days must be at least behavioral_baseline.learning_days"
                    .to_owned(),
            );
        }
        validate_range(
            "observation.request_timeout_ms",
            self.observation.request_timeout_ms,
            1,
            60_000,
            &mut errors,
        );
        validate_range(
            "observation.notification_timeout_ms",
            self.observation.notification_timeout_ms,
            1,
            60_000,
            &mut errors,
        );
        validate_range(
            "observation.max_response_bytes",
            self.observation.max_response_bytes,
            1_024,
            MAX_RESPONSE_BYTES,
            &mut errors,
        );
        if self.observation.stats_lookback_ms == 0
            || !self.observation.stats_lookback_ms.is_multiple_of(3_600_000)
        {
            errors.push(
                "observation.stats_lookback_ms must be a positive whole-hour multiple".to_owned(),
            );
        }
        if self.targets.is_empty() || self.targets.len() > MAX_TARGETS {
            errors.push(format!(
                "targets must contain between 1 and {MAX_TARGETS} entries"
            ));
        }
        if self.observation.target_concurrency == 0
            || self.observation.target_concurrency > MAX_TARGETS
        {
            errors.push(format!(
                "observation.target_concurrency must be between 1 and {MAX_TARGETS}"
            ));
        }
        if self.observation.minimum_complete_targets == 0
            || self.observation.minimum_complete_targets > self.targets.len()
        {
            errors.push(
                "observation.minimum_complete_targets must be between 1 and target count"
                    .to_owned(),
            );
        }
        if VersionReq::parse(&self.observation.adguard_version_requirement).is_err() {
            errors.push(
                "observation.adguard_version_requirement is not a semver requirement".to_owned(),
            );
        } else if self.uses_untested_adguard_version()
            && !self.observation.allow_untested_adguard_version
        {
            errors.push(format!(
                "observation.adguard_version_requirement is {:?}, but only {SUPPORTED_ADGUARD_REQUIREMENT:?} has recorded evidence; set observation.allow_untested_adguard_version = true to accept an untested range",
                self.observation.adguard_version_requirement
            ));
        }
        if let Some(baseline) = &self.behavioral_baseline {
            if baseline.time_zone.trim().is_empty() {
                errors.push("behavioral_baseline.time_zone must not be empty".to_owned());
            }
            if baseline.learning_days == 0 || baseline.minimum_same_hour_samples == 0 {
                errors.push(
                    "behavioral baseline learning and sample counts must be positive".to_owned(),
                );
            }
        }

        validate_profiles(&self.condition_profiles, &mut errors);
        validate_policies(&self.policies, &mut errors);
        validate_targets(self, check_secret_files, &mut errors);
        validate_notifications(&self.notifications, check_secret_files, &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Validation(errors.join("\n- ")))
        }
    }

    /// True when the configured `AdGuard` version requirement is not the range
    /// this release has recorded evidence for. Says nothing about whether the
    /// requirement was accepted; `validate` decides that.
    pub fn uses_untested_adguard_version(&self) -> bool {
        self.observation.adguard_version_requirement != SUPPORTED_ADGUARD_REQUIREMENT
    }

    /// The version requirement this release has recorded evidence for.
    pub fn supported_adguard_version_requirement() -> &'static str {
        SUPPORTED_ADGUARD_REQUIREMENT
    }

    pub fn fingerprint(&self) -> String {
        let serialized = serde_json::to_vec(self).expect("serializing Config cannot fail");
        let digest = Sha256::digest(serialized);
        format!("sha256:{}", crate::hex::encode(&digest))
    }
}

fn validate_profiles(profiles: &BTreeMap<String, ConditionProfile>, errors: &mut Vec<String>) {
    if profiles.is_empty() {
        errors.push("condition_profiles must not be empty".to_owned());
    }
    for (id, profile) in profiles {
        if !valid_id(id) {
            errors.push(format!("condition profile id {id:?} is not a stable slug"));
        }
        let counts = [
            (
                "authentication_rejected_sustain_runs",
                profile.authentication_rejected_sustain_runs,
            ),
            (
                "api_unavailable_sustain_runs",
                profile.api_unavailable_sustain_runs,
            ),
            (
                "invalid_response_sustain_runs",
                profile.invalid_response_sustain_runs,
            ),
            (
                "unsupported_version_sustain_runs",
                profile.unsupported_version_sustain_runs,
            ),
            (
                "protection_disabled_sustain_runs",
                profile.protection_disabled_sustain_runs,
            ),
            (
                "processing_latency_sustain_runs",
                profile.processing_latency_sustain_runs,
            ),
            (
                "upstream_latency_sustain_runs",
                profile.upstream_latency_sustain_runs,
            ),
            (
                "policy_drift_sustain_runs",
                profile.policy_drift_sustain_runs,
            ),
            (
                "behavioral_anomaly_sustain_runs",
                profile.behavioral_anomaly_sustain_runs,
            ),
            ("recovery_runs", profile.recovery_runs),
        ];
        for (label, count) in counts {
            if !(1_u32..=1_000).contains(&count) {
                errors.push(format!(
                    "condition profile {id:?} {label} must be between 1 and 1000, got {count}"
                ));
            }
        }
        let durations = [
            (
                "authentication_retry_seconds",
                profile.authentication_retry_seconds,
            ),
            ("processing_latency_ms", profile.processing_latency_ms),
            ("upstream_latency_ms", profile.upstream_latency_ms),
        ];
        for (label, duration) in durations {
            if duration == 0 {
                errors.push(format!("condition profile {id:?} {label} must be positive"));
            }
        }
    }
}

fn validate_policies(policies: &BTreeMap<String, PolicyConfig>, errors: &mut Vec<String>) {
    for (id, policy) in policies {
        if !valid_id(id) {
            errors.push(format!("policy id {id:?} is not a stable slug"));
        }
        if policy
            .upstream_mode
            .as_deref()
            .is_some_and(|mode| mode.trim().is_empty())
        {
            errors.push(format!("policy {id:?} upstream_mode must not be empty"));
        }
        if let Some(upstream_dns) = &policy.upstream_dns {
            let upstreams: BTreeSet<_> = upstream_dns.iter().collect();
            if upstream_dns.is_empty()
                || upstreams.len() != upstream_dns.len()
                || upstream_dns.iter().any(|value| value.trim().is_empty())
            {
                errors.push(format!(
                    "policy {id:?} upstream_dns must be unique and nonempty"
                ));
            }
        }
        let mut filter_urls = BTreeSet::new();
        for filter in &policy.filters {
            if Url::parse(&filter.url).is_err() || !filter_urls.insert(filter.url.as_str()) {
                errors.push(format!(
                    "policy {id:?} has an invalid or duplicate filter URL {:?}",
                    filter.url
                ));
            }
            if filter.enabled && filter.maximum_age_hours.is_none_or(|hours| hours == 0) {
                errors.push(format!(
                    "policy {id:?} enabled filter {} requires positive maximum_age_hours",
                    filter.url
                ));
            }
            if !filter.enabled && filter.maximum_age_hours.is_some() {
                errors.push(format!(
                    "policy {id:?} disabled filter {} must omit maximum_age_hours",
                    filter.url
                ));
            }
        }
        let mut rewrites = BTreeSet::new();
        for rewrite in &policy.rewrites.required {
            let key = (
                normalize_dns_name(&rewrite.domain),
                normalize_rewrite_answer(&rewrite.answer),
            );
            if key.0.is_empty() || key.1.is_empty() || !rewrites.insert(key.clone()) {
                errors.push(format!(
                    "policy {id:?} has an invalid or duplicate rewrite {:?} -> {:?}",
                    rewrite.domain, rewrite.answer
                ));
            }
        }
    }
}

fn validate_targets(config: &Config, check_secret_files: bool, errors: &mut Vec<String>) {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for target in &config.targets {
        if !valid_id(&target.id) || !ids.insert(target.id.as_str()) {
            errors.push(format!(
                "target id {:?} is invalid or duplicated",
                target.id
            ));
        }
        if target.name.trim().is_empty() || !names.insert(target.name.as_str()) {
            errors.push(format!(
                "target name {:?} is empty or duplicated",
                target.name
            ));
        }
        match target.auth {
            TargetAuth::None => {
                if target.username.is_some() || target.password_file.is_some() {
                    errors.push(format!(
                        "target {:?} must omit username and password_file when auth is none",
                        target.id
                    ));
                }
            }
            TargetAuth::Basic => {
                match target.username.as_deref() {
                    Some(username) if !username.trim().is_empty() => {}
                    _ => errors.push(format!(
                        "target {:?} username must not be empty when auth is basic",
                        target.id
                    )),
                }
                match target.password_file.as_deref() {
                    Some(password_file) => {
                        validate_absolute_path("target.password_file", password_file, errors);
                        if check_secret_files {
                            validate_secret_file(
                                password_file,
                                &format!("target {:?} password", target.id),
                                errors,
                            );
                        }
                    }
                    None => errors.push(format!(
                        "target {:?} password_file is required when auth is basic",
                        target.id
                    )),
                }
            }
        }
        if let Some(policy) = &target.policy
            && !config.policies.contains_key(policy)
        {
            errors.push(format!(
                "target {:?} references unknown policy {policy:?}",
                target.id
            ));
        }
        if !config
            .condition_profiles
            .contains_key(&target.condition_profile)
        {
            errors.push(format!(
                "target {:?} references unknown condition profile {:?}",
                target.id, target.condition_profile
            ));
        }
        validate_target_url(target, errors);
    }
    if let Some(baseline) = &config.behavioral_baseline {
        let configured_ids: BTreeSet<_> = config.targets.iter().map(|target| &target.id).collect();
        let baseline_ids: BTreeSet<_> = baseline.target_ids.iter().collect();
        if baseline_ids.is_empty() {
            errors.push("behavioral_baseline.target_ids must not be empty".to_owned());
        }
        let mut seen_baseline_ids = BTreeSet::new();
        for id in &baseline.target_ids {
            if !seen_baseline_ids.insert(id) {
                errors.push(format!(
                    "behavioral_baseline.target_ids repeats target {id:?}"
                ));
            }
        }
        for id in baseline_ids.difference(&configured_ids) {
            errors.push(format!(
                "behavioral_baseline.target_ids references unknown target {id:?}"
            ));
        }
        let baseline_profiles: BTreeSet<_> = config
            .targets
            .iter()
            .filter(|target| baseline_ids.contains(&target.id))
            .map(|target| target.condition_profile.as_str())
            .collect();
        if baseline_profiles.len() > 1 {
            errors.push("behavioral_baseline targets must share one condition profile".to_owned());
        }
    }
}

fn validate_target_url(target: &TargetConfig, errors: &mut Vec<String>) {
    let Ok(url) = Url::parse(&target.base_url) else {
        errors.push(format!("target {:?} base_url is invalid", target.id));
        return;
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        errors.push(format!(
            "target {:?} base_url may not contain credentials, query, or fragment",
            target.id
        ));
    }
    if url.path() != "/" && !url.path().is_empty() {
        errors.push(format!("target {:?} base_url path must be /", target.id));
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) || target.allow_insecure_local_http => {}
        "http" => errors.push(format!(
            "target {:?} uses non-loopback HTTP without allow_insecure_local_http",
            target.id
        )),
        _ => errors.push(format!(
            "target {:?} base_url must use HTTP or HTTPS",
            target.id
        )),
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn validate_notifications(
    notifications: &NotificationConfig,
    check_secret_files: bool,
    errors: &mut Vec<String>,
) {
    match (&notifications.provider, &notifications.pushover) {
        (NotificationProvider::Disabled, None) => {}
        (NotificationProvider::Disabled, Some(_)) => {
            errors
                .push("notifications.pushover must be absent when provider is disabled".to_owned());
        }
        (NotificationProvider::Pushover, Some(pushover)) => {
            validate_absolute_path(
                "notifications.pushover.application_token_file",
                &pushover.application_token_file,
                errors,
            );
            validate_absolute_path(
                "notifications.pushover.user_key_file",
                &pushover.user_key_file,
                errors,
            );
            if check_secret_files {
                validate_secret_file(
                    &pushover.application_token_file,
                    "Pushover application token",
                    errors,
                );
                validate_secret_file(&pushover.user_key_file, "Pushover user key", errors);
            }
        }
        (NotificationProvider::Pushover, None) => {
            errors.push("notifications.pushover is required when provider is pushover".to_owned());
        }
    }
}

fn validate_absolute_path(label: &str, path: &Path, errors: &mut Vec<String>) {
    if !path.is_absolute() {
        errors.push(format!("{label} must be an absolute path"));
    }
}

fn validate_secret_file(path: &Path, label: &str, errors: &mut Vec<String>) {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() > 0 => {}
        Ok(_) => errors.push(format!("{label} must reference a nonempty regular file")),
        Err(error) => errors.push(format!("cannot inspect {label}: {error}")),
    }
}

fn validate_range(label: &str, value: u64, minimum: u64, maximum: u64, errors: &mut Vec<String>) {
    if !(minimum..=maximum).contains(&value) {
        errors.push(format!("{label} must be between {minimum} and {maximum}"));
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub fn normalize_dns_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn normalize_rewrite_answer(value: &str) -> String {
    let trimmed = value.trim();
    if let Ok(address) = trimmed.parse::<IpAddr>() {
        address.to_string()
    } else {
        normalize_dns_name(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConditionProfile, Config, NotificationConfig, NotificationProvider, ObservationConfig,
        StateConfig, TargetAuth, default_condition_profiles, normalize_dns_name,
        normalize_rewrite_answer,
    };

    #[test]
    fn normalizes_dns_values() {
        assert_eq!(normalize_dns_name("Example.COM."), "example.com");
        assert_eq!(normalize_rewrite_answer("2001:0db8::1"), "2001:db8::1");
    }

    #[test]
    fn synthetic_example_is_semantically_valid_without_secret_access() {
        let config: Config =
            toml::from_str(include_str!("../../../config.example.toml")).expect("example TOML");
        config.validate(false).expect("example semantics");
    }

    #[test]
    fn unknown_configuration_fields_are_rejected() {
        let text = format!(
            "{}\nunknown_root_field = true\n",
            include_str!("../../../config.example.toml")
        );
        assert!(toml::from_str::<Config>(&text).is_err());
    }

    #[test]
    fn omitted_auth_preserves_basic_authentication() {
        let text = include_str!("../../../config.example.toml").replace("auth = \"basic\"\n", "");
        let config: Config = toml::from_str(&text).expect("v0.1.3 example TOML");

        assert!(
            config
                .targets
                .iter()
                .all(|target| target.auth == TargetAuth::Basic)
        );
        config.validate(false).expect("v0.1.3 authentication");
    }

    #[test]
    fn no_authentication_needs_no_credentials() {
        let mut config: Config =
            toml::from_str(include_str!("../../../config.example.toml")).expect("example TOML");
        for target in &mut config.targets {
            target.auth = TargetAuth::None;
            target.username = None;
            target.password_file = None;
        }

        config.validate(false).expect("no-auth targets");
    }

    #[test]
    fn basic_authentication_still_requires_file_credentials() {
        let mut config: Config =
            toml::from_str(include_str!("../../../config.example.toml")).expect("example TOML");
        config.targets[0].password_file = None;

        let error = config
            .validate(false)
            .expect_err("basic auth without a password file must fail");

        assert!(
            error
                .to_string()
                .contains("target \"resolver-a\" password_file is required when auth is basic")
        );
    }

    #[test]
    fn reference_sections_equal_their_omission_defaults() {
        let config: Config =
            toml::from_str(include_str!("../../../config.example.toml")).expect("example TOML");

        assert_eq!(
            serde_json::to_value(&config.state).expect("state JSON"),
            serde_json::to_value(StateConfig::default()).expect("default state JSON")
        );
        assert_eq!(
            serde_json::to_value(&config.observation).expect("observation JSON"),
            serde_json::to_value(ObservationConfig::default()).expect("default observation JSON")
        );
        assert_eq!(
            serde_json::to_value(&config.condition_profiles).expect("profiles JSON"),
            serde_json::to_value(default_condition_profiles()).expect("default profiles JSON")
        );
        assert_eq!(
            serde_json::to_value(&config.notifications).expect("notifications JSON"),
            serde_json::to_value(NotificationConfig::default())
                .expect("default notifications JSON")
        );
    }

    #[test]
    fn operational_sections_and_behavioral_baseline_can_be_omitted() {
        let text = r#"
schema_version = 1

[policies.home]
protection_enabled = true
upstream_mode = "load_balance"
upstream_dns = ["tls://resolver.invalid"]
filters = []

[policies.home.rewrites]
enabled = true
required = []

[[targets]]
id = "resolver"
name = "Resolver"
base_url = "https://resolver.invalid"
auth = "none"
policy = "home"
"#;
        let config: Config = toml::from_str(text).expect("configuration with defaults");

        config.validate(false).expect("defaulted configuration");
        assert!(config.behavioral_baseline.is_none());
        assert_eq!(config.targets[0].condition_profile, "current");
        assert!(!config.targets[0].allow_insecure_local_http);
        assert!(matches!(
            config.notifications.provider,
            NotificationProvider::Disabled
        ));
        assert_eq!(
            config
                .condition_profiles
                .get("current")
                .map(|profile| profile.processing_latency_ms),
            Some(ConditionProfile::default().processing_latency_ms)
        );
    }

    #[test]
    fn one_no_auth_target_is_a_complete_minimal_configuration() {
        let text = include_str!("../../../config.minimal.toml");
        let config: Config = toml::from_str(text).expect("minimal configuration");

        config.validate(false).expect("minimal semantics");
        assert!(config.policies.is_empty());
        assert!(config.targets[0].policy.is_none());
        assert!(config.behavioral_baseline.is_none());
        assert!(matches!(
            config.notifications.provider,
            NotificationProvider::Disabled
        ));
    }

    #[test]
    fn a_policy_can_declare_only_one_independent_field() {
        let text = r#"
schema_version = 1

[policies.protection-only]
protection_enabled = true

[[targets]]
id = "resolver"
name = "Resolver"
base_url = "https://resolver.invalid"
auth = "none"
policy = "protection-only"
"#;
        let config: Config = toml::from_str(text).expect("partial policy");

        config.validate(false).expect("partial policy semantics");
        let policy = config
            .policies
            .get("protection-only")
            .expect("declared policy");
        assert_eq!(policy.protection_enabled, Some(true));
        assert!(policy.upstream_mode.is_none());
        assert!(policy.upstream_dns.is_none());
        assert!(policy.filters.is_empty());
        assert!(policy.rewrites.enabled.is_none());
        assert!(policy.rewrites.required.is_empty());
    }
}
