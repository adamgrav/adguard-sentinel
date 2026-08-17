#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use reqwest::header::{ACCEPT, ACCEPT_ENCODING, USER_AGENT};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use semver::{Version, VersionReq};
use sentinel_core::config::{PolicyConfig, normalize_dns_name, normalize_rewrite_answer};
use sentinel_core::{
    DnsObservation, FilterObservation, OperationalObservation, RewriteObservation, TargetConfig,
    TargetReport, TargetStatus, UpstreamObservation,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use url::Url;

const USER_AGENT_VALUE: &str = concat!("adguard-sentinel/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Error)]
pub enum AdGuardError {
    #[error("AdGuard API authentication was rejected")]
    AuthenticationRejected,
    #[error("AdGuard API request failed at {endpoint}: {detail}")]
    Unavailable {
        endpoint: &'static str,
        detail: String,
    },
    #[error("AdGuard API response was invalid at {endpoint}: {detail}")]
    InvalidResponse {
        endpoint: &'static str,
        detail: String,
    },
    #[error("AdGuard Home version {observed} is outside {required}")]
    UnsupportedVersion { observed: String, required: String },
    #[error("AdGuard API response exceeded {limit} bytes at {endpoint}")]
    ResponseTooLarge { endpoint: &'static str, limit: u64 },
}

impl AdGuardError {
    pub fn target_status(&self) -> TargetStatus {
        match self {
            Self::AuthenticationRejected => TargetStatus::AuthenticationRejected,
            Self::Unavailable { .. } => TargetStatus::Unavailable,
            Self::InvalidResponse { .. } => TargetStatus::InvalidResponse,
            Self::UnsupportedVersion { .. } => TargetStatus::UnsupportedVersion,
            Self::ResponseTooLarge { .. } => TargetStatus::ResponseTooLarge,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::AuthenticationRejected => "authentication_rejected",
            Self::Unavailable { .. } => "api_unavailable",
            Self::InvalidResponse { .. } => "invalid_response",
            Self::UnsupportedVersion { .. } => "unsupported_version",
            Self::ResponseTooLarge { .. } => "response_too_large",
        }
    }
}

#[async_trait]
pub trait AdGuardReadClient: Send + Sync {
    async fn observe(
        &self,
        target: &TargetConfig,
        policy: &PolicyConfig,
        password: &SecretString,
        stats_lookback_ms: u64,
        now_unix_seconds: i64,
    ) -> Result<TargetReport, AdGuardError>;
}

#[derive(Clone, Debug)]
pub struct ReqwestAdGuardClient {
    client: Client,
    max_response_bytes: u64,
    version_requirement: VersionReq,
}

impl ReqwestAdGuardClient {
    pub fn new(
        request_timeout_ms: u64,
        max_response_bytes: u64,
        version_requirement: &str,
    ) -> Result<Self, AdGuardError> {
        let version_requirement = VersionReq::parse(version_requirement).map_err(|error| {
            AdGuardError::InvalidResponse {
                endpoint: "configuration",
                detail: format!("invalid version requirement: {error}"),
            }
        })?;
        let client = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| AdGuardError::Unavailable {
                endpoint: "client",
                detail: "could not construct the bounded HTTP client".to_owned(),
            })?;
        Ok(Self {
            client,
            max_response_bytes,
            version_requirement,
        })
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        base_url: &str,
        endpoint: Endpoint,
        username: &str,
        password: &SecretString,
    ) -> Result<T, AdGuardError> {
        let url = endpoint.url(base_url)?;
        let label = endpoint.label();
        let mut response = self
            .client
            .get(url)
            .header(ACCEPT, "application/json")
            .header(ACCEPT_ENCODING, "identity")
            .header(USER_AGENT, USER_AGENT_VALUE)
            .basic_auth(username, Some(password.expose_secret()))
            .send()
            .await
            .map_err(|error| AdGuardError::Unavailable {
                endpoint: label,
                detail: request_error_detail(&error),
            })?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(AdGuardError::AuthenticationRejected);
        }
        if !response.status().is_success() {
            return Err(AdGuardError::Unavailable {
                endpoint: label,
                detail: format!("HTTP {}", response.status().as_u16()),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes)
        {
            return Err(AdGuardError::ResponseTooLarge {
                endpoint: label,
                limit: self.max_response_bytes,
            });
        }
        let mut body = Vec::new();
        while let Some(chunk) =
            response
                .chunk()
                .await
                .map_err(|error| AdGuardError::Unavailable {
                    endpoint: label,
                    detail: request_error_detail(&error),
                })?
        {
            let prospective = body.len().saturating_add(chunk.len());
            if u64::try_from(prospective).unwrap_or(u64::MAX) > self.max_response_bytes {
                return Err(AdGuardError::ResponseTooLarge {
                    endpoint: label,
                    limit: self.max_response_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|error| AdGuardError::InvalidResponse {
            endpoint: label,
            detail: format!("JSON decoding failed: {error}"),
        })
    }
}

#[async_trait]
impl AdGuardReadClient for ReqwestAdGuardClient {
    async fn observe(
        &self,
        target: &TargetConfig,
        policy: &PolicyConfig,
        password: &SecretString,
        stats_lookback_ms: u64,
        now_unix_seconds: i64,
    ) -> Result<TargetReport, AdGuardError> {
        let status: StatusResponse = self
            .get_json(
                &target.base_url,
                Endpoint::Status,
                &target.username,
                password,
            )
            .await?;
        let version = Version::parse(status.version.trim_start_matches('v')).map_err(|_| {
            AdGuardError::InvalidResponse {
                endpoint: Endpoint::Status.label(),
                detail: "version is not semantic-version data".to_owned(),
            }
        })?;
        if !self.version_requirement.matches(&version) {
            return Err(AdGuardError::UnsupportedVersion {
                observed: status.version,
                required: self.version_requirement.to_string(),
            });
        }
        if !status.running {
            return Err(AdGuardError::InvalidResponse {
                endpoint: Endpoint::Status.label(),
                detail: "running must be true for a complete observation".to_owned(),
            });
        }
        let statistics: StatsResponse = self
            .get_json(
                &target.base_url,
                Endpoint::Stats(stats_lookback_ms),
                &target.username,
                password,
            )
            .await?;
        let dns: DnsResponse = self
            .get_json(
                &target.base_url,
                Endpoint::DnsInfo,
                &target.username,
                password,
            )
            .await?;
        let filtering: FilteringResponse = self
            .get_json(
                &target.base_url,
                Endpoint::FilteringStatus,
                &target.username,
                password,
            )
            .await?;
        let rewrites: Vec<RewriteResponse> = self
            .get_json(
                &target.base_url,
                Endpoint::RewriteList,
                &target.username,
                password,
            )
            .await?;
        let rewrite_settings: RewriteSettingsResponse = self
            .get_json(
                &target.base_url,
                Endpoint::RewriteSettings,
                &target.username,
                password,
            )
            .await?;

        let operational = normalize_stats(status.protection_enabled, &statistics)?;
        let upstreams = normalize_upstreams(&statistics.top_upstreams_avg_time)?;
        let dns = normalize_dns(dns)?;
        let filters = normalize_filters(filtering.filters, policy, now_unix_seconds)?;
        let rewrites = normalize_rewrites(rewrites)?;
        Ok(TargetReport {
            id: target.id.clone(),
            name: target.name.clone(),
            status: TargetStatus::Complete,
            complete: true,
            server_version: Some(version.to_string()),
            operational: Some(operational),
            dns: Some(dns),
            filtering_enabled: Some(filtering.enabled),
            rewrites_enabled: Some(rewrite_settings.enabled),
            upstreams,
            filters,
            rewrites,
            error_kind: None,
            error_detail: None,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum Endpoint {
    Status,
    Stats(u64),
    DnsInfo,
    FilteringStatus,
    RewriteList,
    RewriteSettings,
}

impl Endpoint {
    fn label(self) -> &'static str {
        match self {
            Self::Status => "GET /control/status",
            Self::Stats(_) => "GET /control/stats",
            Self::DnsInfo => "GET /control/dns_info",
            Self::FilteringStatus => "GET /control/filtering/status",
            Self::RewriteList => "GET /control/rewrite/list",
            Self::RewriteSettings => "GET /control/rewrite/settings",
        }
    }

    fn url(self, base_url: &str) -> Result<Url, AdGuardError> {
        let mut url = Url::parse(base_url).map_err(|_| AdGuardError::InvalidResponse {
            endpoint: "configuration",
            detail: "base URL is invalid".to_owned(),
        })?;
        let (path, query) = match self {
            Self::Status => ("/control/status", None),
            Self::Stats(recent) => ("/control/stats", Some(format!("recent={recent}"))),
            Self::DnsInfo => ("/control/dns_info", None),
            Self::FilteringStatus => ("/control/filtering/status", None),
            Self::RewriteList => ("/control/rewrite/list", None),
            Self::RewriteSettings => ("/control/rewrite/settings", None),
        };
        url.set_path(path);
        url.set_query(query.as_deref());
        Ok(url)
    }
}

#[derive(Debug, Deserialize)]
struct StatusResponse {
    protection_enabled: bool,
    running: bool,
    version: String,
}

#[derive(Debug, Deserialize)]
struct StatsResponse {
    num_dns_queries: u64,
    num_blocked_filtering: u64,
    avg_processing_time: f64,
    top_upstreams_avg_time: Vec<BTreeMap<String, f64>>,
    top_clients: Vec<BTreeMap<String, u64>>,
}

#[derive(Debug, Deserialize)]
struct DnsResponse {
    upstream_dns: Vec<String>,
    upstream_mode: String,
}

#[derive(Debug, Deserialize)]
struct FilteringResponse {
    enabled: bool,
    filters: Vec<FilterResponse>,
}

#[derive(Debug, Deserialize)]
struct FilterResponse {
    id: i64,
    enabled: bool,
    url: String,
    rules_count: u64,
    last_updated: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RewriteResponse {
    domain: String,
    answer: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct RewriteSettingsResponse {
    enabled: bool,
}

fn normalize_stats(
    protection_enabled: bool,
    stats: &StatsResponse,
) -> Result<OperationalObservation, AdGuardError> {
    if stats.num_blocked_filtering > stats.num_dns_queries {
        return invalid_stats("num_blocked_filtering exceeds num_dns_queries");
    }
    if !stats.avg_processing_time.is_finite() || stats.avg_processing_time < 0.0 {
        return invalid_stats("avg_processing_time must be finite and nonnegative");
    }
    let upstreams = normalize_upstreams(&stats.top_upstreams_avg_time)?;
    let maximum_upstream_seconds = upstreams
        .iter()
        .map(|upstream| upstream.average_seconds)
        .max_by(f64::total_cmp)
        .unwrap_or(0.0);
    let mut seen_clients = BTreeSet::new();
    let mut top_client_count = 0_u64;
    for entry in &stats.top_clients {
        if entry.len() != 1 {
            return invalid_stats("each top_clients entry must contain exactly one client");
        }
        let (identity, count) = entry.iter().next().expect("entry length checked");
        if identity.is_empty() || !seen_clients.insert(identity) || *count > stats.num_dns_queries {
            return invalid_stats("top_clients contains invalid or duplicate data");
        }
        top_client_count = top_client_count.max(*count);
    }
    let blocked_ratio = ratio(stats.num_blocked_filtering, stats.num_dns_queries);
    let top_client_share = ratio(top_client_count, stats.num_dns_queries);
    Ok(OperationalObservation {
        protection_enabled,
        queries: stats.num_dns_queries,
        blocked: stats.num_blocked_filtering,
        blocked_ratio,
        average_processing_seconds: stats.avg_processing_time,
        maximum_upstream_seconds,
        top_client_share,
    })
}

fn normalize_upstreams(
    entries: &[BTreeMap<String, f64>],
) -> Result<Vec<UpstreamObservation>, AdGuardError> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.len() != 1 {
            return invalid_stats("each upstream latency entry must contain exactly one upstream");
        }
        let (identity, average) = entry.iter().next().expect("entry length checked");
        if identity.is_empty()
            || !seen.insert(identity.clone())
            || !average.is_finite()
            || *average < 0.0
        {
            return invalid_stats("upstream latency contains invalid or duplicate data");
        }
        normalized.push(UpstreamObservation {
            identity: identity.clone(),
            average_seconds: *average,
        });
    }
    normalized.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(normalized)
}

fn normalize_dns(dns: DnsResponse) -> Result<DnsObservation, AdGuardError> {
    if dns.upstream_mode.trim().is_empty() || dns.upstream_dns.is_empty() {
        return Err(AdGuardError::InvalidResponse {
            endpoint: Endpoint::DnsInfo.label(),
            detail: "upstream mode and set must be nonempty".to_owned(),
        });
    }
    let unique: BTreeSet<_> = dns.upstream_dns.iter().collect();
    if unique.len() != dns.upstream_dns.len()
        || dns.upstream_dns.iter().any(|value| value.trim().is_empty())
    {
        return Err(AdGuardError::InvalidResponse {
            endpoint: Endpoint::DnsInfo.label(),
            detail: "upstream set contains empty or duplicate values".to_owned(),
        });
    }
    Ok(DnsObservation {
        upstream_mode: dns.upstream_mode,
        upstream_dns: dns.upstream_dns,
    })
}

fn normalize_filters(
    filters: Vec<FilterResponse>,
    policy: &PolicyConfig,
    now_unix_seconds: i64,
) -> Result<Vec<FilterObservation>, AdGuardError> {
    let required: BTreeSet<_> = policy
        .filters
        .iter()
        .map(|filter| filter.url.as_str())
        .collect();
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for filter in filters {
        if filter.url.trim().is_empty() || !seen.insert(filter.url.clone()) {
            return Err(AdGuardError::InvalidResponse {
                endpoint: Endpoint::FilteringStatus.label(),
                detail: "filter list contains an empty or duplicate URL".to_owned(),
            });
        }
        if !required.contains(filter.url.as_str()) {
            continue;
        }
        let last_updated_unix_seconds = match filter.last_updated.as_deref() {
            Some(value) => {
                let timestamp: Timestamp =
                    value.parse().map_err(|_| AdGuardError::InvalidResponse {
                        endpoint: Endpoint::FilteringStatus.label(),
                        detail: "required filter last_updated is not RFC3339".to_owned(),
                    })?;
                let seconds = timestamp.as_second();
                if seconds > now_unix_seconds.saturating_add(300) {
                    return Err(AdGuardError::InvalidResponse {
                        endpoint: Endpoint::FilteringStatus.label(),
                        detail: "required filter last_updated is in the future".to_owned(),
                    });
                }
                Some(seconds)
            }
            None => None,
        };
        if filter.enabled && last_updated_unix_seconds.is_none() {
            return Err(AdGuardError::InvalidResponse {
                endpoint: Endpoint::FilteringStatus.label(),
                detail: "enabled required filter has no last_updated value".to_owned(),
            });
        }
        normalized.push(FilterObservation {
            url: filter.url,
            server_id: filter.id,
            enabled: filter.enabled,
            rules_count: filter.rules_count,
            last_updated: filter.last_updated,
            last_updated_unix_seconds,
        });
    }
    normalized.sort_by(|left, right| left.url.cmp(&right.url));
    Ok(normalized)
}

fn normalize_rewrites(
    rewrites: Vec<RewriteResponse>,
) -> Result<Vec<RewriteObservation>, AdGuardError> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(rewrites.len());
    for rewrite in rewrites {
        let domain = normalize_dns_name(&rewrite.domain);
        let answer = normalize_rewrite_answer(&rewrite.answer);
        if domain.is_empty() || answer.is_empty() || !seen.insert((domain.clone(), answer.clone()))
        {
            return Err(AdGuardError::InvalidResponse {
                endpoint: Endpoint::RewriteList.label(),
                detail: "rewrite list contains empty or duplicate normalized entries".to_owned(),
            });
        }
        normalized.push(RewriteObservation {
            domain,
            answer,
            enabled: rewrite.enabled,
        });
    }
    normalized
        .sort_by(|left, right| (&left.domain, &left.answer).cmp(&(&right.domain, &right.answer)));
    Ok(normalized)
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn invalid_stats<T>(detail: &str) -> Result<T, AdGuardError> {
    Err(AdGuardError::InvalidResponse {
        endpoint: Endpoint::Stats(0).label(),
        detail: detail.to_owned(),
    })
}

fn request_error_detail(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "request timed out".to_owned()
    } else if error.is_connect() {
        "connection failed".to_owned()
    } else if error.is_decode() {
        "response decoding failed".to_owned()
    } else {
        "request failed".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use httpmock::Method::GET;
    use httpmock::MockServer;
    use secrecy::SecretString;
    use sentinel_core::config::{PolicyConfig, RequiredFilter, RequiredRewrites, TargetConfig};

    use super::{
        AdGuardError, AdGuardReadClient, ReqwestAdGuardClient, StatsResponse, normalize_stats,
    };

    #[tokio::test]
    async fn observes_only_the_six_allowlisted_gets() {
        let server = MockServer::start_async().await;
        let fixtures = [
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
        let mut mocks = Vec::new();
        for (path, body) in fixtures {
            let builder = server
                .mock_async(|when, then| {
                    when.method(GET).path(path);
                    then.status(200)
                        .header("content-type", "application/json")
                        .body(body);
                })
                .await;
            mocks.push(builder);
        }
        let target = TargetConfig {
            id: "resolver-a".to_owned(),
            name: "Resolver A".to_owned(),
            base_url: server.base_url(),
            username: "admin".to_owned(),
            password_file: PathBuf::from("/tmp/synthetic-password"),
            policy: "test".to_owned(),
            condition_profile: "test".to_owned(),
            allow_insecure_local_http: false,
        };
        let policy = PolicyConfig {
            protection_enabled: true,
            upstream_mode: "load_balance".to_owned(),
            upstream_dns: vec!["tls://resolver.invalid".to_owned()],
            filters: Vec::<RequiredFilter>::new(),
            rewrites: RequiredRewrites {
                enabled: true,
                required: Vec::new(),
            },
        };
        let client =
            ReqwestAdGuardClient::new(5_000, 4_194_304, ">=0.107.78,<0.108.0").expect("client");
        let report = client
            .observe(
                &target,
                &policy,
                &SecretString::from("synthetic".to_owned()),
                3_600_000,
                1_800_000_000,
            )
            .await
            .expect("observation");
        assert!(report.complete);
        for mock in mocks {
            mock.assert_async().await;
        }
    }

    #[test]
    fn rejects_negative_latency_instead_of_defaulting_to_healthy() {
        let statistics: StatsResponse = serde_json::from_str(include_str!(
            "../../../testdata/api/malformed-negative-stats.json"
        ))
        .expect("syntactically valid fixture");
        let error = normalize_stats(true, &statistics).expect_err("negative latency must fail");
        assert!(matches!(error, AdGuardError::InvalidResponse { .. }));
    }

    #[tokio::test]
    async fn timeout_is_an_incomplete_unavailable_observation() {
        let server = MockServer::start_async().await;
        let _status = server
            .mock_async(|when, then| {
                when.method(GET).path("/control/status");
                then.status(200)
                    .delay(Duration::from_millis(100))
                    .header("content-type", "application/json")
                    .body(include_str!("../../../testdata/api/status.json"));
            })
            .await;
        let target = TargetConfig {
            id: "resolver-a".to_owned(),
            name: "Resolver A".to_owned(),
            base_url: server.base_url(),
            username: "admin".to_owned(),
            password_file: PathBuf::from("/tmp/synthetic-password"),
            policy: "test".to_owned(),
            condition_profile: "test".to_owned(),
            allow_insecure_local_http: false,
        };
        let policy = PolicyConfig {
            protection_enabled: true,
            upstream_mode: "load_balance".to_owned(),
            upstream_dns: vec!["tls://resolver.invalid".to_owned()],
            filters: Vec::new(),
            rewrites: RequiredRewrites {
                enabled: true,
                required: Vec::new(),
            },
        };
        let client =
            ReqwestAdGuardClient::new(10, 4_194_304, ">=0.107.78,<0.108.0").expect("client");
        let error = client
            .observe(
                &target,
                &policy,
                &SecretString::from("synthetic".to_owned()),
                3_600_000,
                1_800_000_000,
            )
            .await
            .expect_err("must time out");
        assert!(matches!(error, AdGuardError::Unavailable { .. }));
    }

    #[tokio::test]
    async fn rejects_a_response_over_the_configured_limit() {
        let server = MockServer::start_async().await;
        let status = server
            .mock_async(|when, then| {
                when.method(GET).path("/control/status");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(include_str!("../../../testdata/api/status.json"));
            })
            .await;
        let target = TargetConfig {
            id: "resolver-a".to_owned(),
            name: "Resolver A".to_owned(),
            base_url: server.base_url(),
            username: "admin".to_owned(),
            password_file: PathBuf::from("/tmp/synthetic-password"),
            policy: "test".to_owned(),
            condition_profile: "test".to_owned(),
            allow_insecure_local_http: false,
        };
        let policy = PolicyConfig {
            protection_enabled: true,
            upstream_mode: "load_balance".to_owned(),
            upstream_dns: vec!["tls://resolver.invalid".to_owned()],
            filters: Vec::new(),
            rewrites: RequiredRewrites {
                enabled: true,
                required: Vec::new(),
            },
        };
        let client = ReqwestAdGuardClient::new(5_000, 16, ">=0.107.78,<0.108.0").expect("client");
        let error = client
            .observe(
                &target,
                &policy,
                &SecretString::from("synthetic".to_owned()),
                3_600_000,
                1_800_000_000,
            )
            .await
            .expect_err("must reject oversized body");
        assert!(matches!(error, AdGuardError::ResponseTooLarge { .. }));
        status.assert_async().await;
    }

    #[tokio::test]
    async fn classifies_unauthorized_without_requesting_other_endpoints() {
        let server = MockServer::start_async().await;
        let status = server
            .mock_async(|when, then| {
                when.method(GET).path("/control/status");
                then.status(401);
            })
            .await;
        let target = TargetConfig {
            id: "resolver-a".to_owned(),
            name: "Resolver A".to_owned(),
            base_url: server.base_url(),
            username: "admin".to_owned(),
            password_file: PathBuf::from("/tmp/synthetic-password"),
            policy: "test".to_owned(),
            condition_profile: "test".to_owned(),
            allow_insecure_local_http: false,
        };
        let policy = PolicyConfig {
            protection_enabled: true,
            upstream_mode: "load_balance".to_owned(),
            upstream_dns: vec!["tls://resolver.invalid".to_owned()],
            filters: Vec::new(),
            rewrites: RequiredRewrites {
                enabled: true,
                required: Vec::new(),
            },
        };
        let client =
            ReqwestAdGuardClient::new(5_000, 4_194_304, ">=0.107.78,<0.108.0").expect("client");
        let error = client
            .observe(
                &target,
                &policy,
                &SecretString::from("synthetic".to_owned()),
                3_600_000,
                1_800_000_000,
            )
            .await
            .expect_err("must reject authentication");
        assert!(matches!(error, AdGuardError::AuthenticationRejected));
        status.assert_async().await;
    }

    #[tokio::test]
    async fn rejects_an_unsupported_server_version_before_other_requests() {
        let server = MockServer::start_async().await;
        let status = server
            .mock_async(|when, then| {
                when.method(GET).path("/control/status");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(r#"{"protection_enabled":true,"running":true,"version":"v0.108.0"}"#);
            })
            .await;
        let target = TargetConfig {
            id: "resolver-a".to_owned(),
            name: "Resolver A".to_owned(),
            base_url: server.base_url(),
            username: "admin".to_owned(),
            password_file: PathBuf::from("/tmp/synthetic-password"),
            policy: "test".to_owned(),
            condition_profile: "test".to_owned(),
            allow_insecure_local_http: false,
        };
        let policy = PolicyConfig {
            protection_enabled: true,
            upstream_mode: "load_balance".to_owned(),
            upstream_dns: vec!["tls://resolver.invalid".to_owned()],
            filters: Vec::new(),
            rewrites: RequiredRewrites {
                enabled: true,
                required: Vec::new(),
            },
        };
        let client =
            ReqwestAdGuardClient::new(5_000, 4_194_304, ">=0.107.78,<0.108.0").expect("client");
        let error = client
            .observe(
                &target,
                &policy,
                &SecretString::from("synthetic".to_owned()),
                3_600_000,
                1_800_000_000,
            )
            .await
            .expect_err("unsupported version must fail");
        assert!(matches!(error, AdGuardError::UnsupportedVersion { .. }));
        status.assert_async().await;
    }

    #[test]
    fn required_stats_fields_and_json_syntax_are_strict() {
        assert!(serde_json::from_str::<StatsResponse>("{}").is_err());
        assert!(serde_json::from_str::<StatsResponse>("{not-json}").is_err());
        assert!(
            serde_json::from_str::<StatsResponse>(
                r#"{"num_dns_queries":"100","num_blocked_filtering":20,"avg_processing_time":0.01,"top_upstreams_avg_time":[],"top_clients":[]}"#,
            )
            .is_err()
        );
    }
}
