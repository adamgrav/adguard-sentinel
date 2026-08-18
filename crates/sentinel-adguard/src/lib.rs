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
    let upstream_mode = if dns.upstream_mode.is_empty() {
        // AdGuard Home 0.107.78 serializes its load-balancing mode as the
        // legacy empty-string API value.  Normalize that documented alias at
        // the request boundary so policy evaluation sees the canonical mode.
        "load_balance".to_owned()
    } else if dns.upstream_mode.trim().is_empty() {
        return Err(AdGuardError::InvalidResponse {
            endpoint: Endpoint::DnsInfo.label(),
            detail: "upstream mode must not contain only whitespace".to_owned(),
        });
    } else {
        dns.upstream_mode
    };
    if dns.upstream_dns.is_empty() {
        return Err(AdGuardError::InvalidResponse {
            endpoint: Endpoint::DnsInfo.label(),
            detail: "upstream set must be nonempty".to_owned(),
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
        upstream_mode,
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
    use httpmock::{Mock, MockServer};
    use secrecy::SecretString;
    use sentinel_core::config::{PolicyConfig, TargetConfig};
    use sentinel_core::{Config, TargetReport};

    use super::{
        AdGuardError, AdGuardReadClient, DnsResponse, FilteringResponse, ReqwestAdGuardClient,
        RewriteResponse, StatsResponse, normalize_dns, normalize_filters, normalize_rewrites,
        normalize_stats,
    };

    const NOW: i64 = 1_800_000_000;
    const ONE_HOUR_BEFORE_NOW: i64 = 1_799_996_400;
    const REQUIREMENT: &str = ">=0.107.78,<0.108.0";
    const MAX_BYTES: u64 = 4_194_304;
    const TIMEOUT_MS: u64 = 5_000;
    const LOOKBACK_MS: u64 = 3_600_000;

    const STATUS_PATH: &str = "/control/status";
    const STATS_PATH: &str = "/control/stats";
    const DNS_INFO_PATH: &str = "/control/dns_info";
    const FILTERING_PATH: &str = "/control/filtering/status";
    const REWRITE_LIST_PATH: &str = "/control/rewrite/list";
    const REWRITE_SETTINGS_PATH: &str = "/control/rewrite/settings";

    const STATUS: &str = include_str!("../../../testdata/api/status.json");
    const STATS: &str = include_str!("../../../testdata/api/stats.json");
    const DNS_INFO: &str = include_str!("../../../testdata/api/dns-info.json");
    const FILTERING_STATUS: &str = include_str!("../../../testdata/api/filtering-status.json");
    const REWRITE_LIST: &str = include_str!("../../../testdata/api/rewrite-list.json");
    const REWRITE_SETTINGS: &str = include_str!("../../../testdata/api/rewrite-settings.json");

    const DNS_INFO_EXPLICIT_MODE: &str =
        include_str!("../../../testdata/api/dns-info-explicit-mode.json");
    const MALFORMED_NEGATIVE_STATS: &str =
        include_str!("../../../testdata/api/malformed-negative-stats.json");
    const MALFORMED_BLOCKED_EXCEEDS_QUERIES: &str =
        include_str!("../../../testdata/api/malformed-blocked-exceeds-queries.json");
    const MALFORMED_DUPLICATE_TOP_CLIENT: &str =
        include_str!("../../../testdata/api/malformed-duplicate-top-client.json");
    const MALFORMED_DNS_INFO_MISSING_MODE: &str =
        include_str!("../../../testdata/api/malformed-dns-info-missing-mode.json");
    const MALFORMED_WHITESPACE_UPSTREAM_MODE: &str =
        include_str!("../../../testdata/api/malformed-whitespace-upstream-mode.json");
    const MALFORMED_DUPLICATE_REWRITES: &str =
        include_str!("../../../testdata/api/malformed-duplicate-rewrites.json");
    const MALFORMED_EMPTY_REWRITE_DOMAIN: &str =
        include_str!("../../../testdata/api/malformed-empty-rewrite-domain.json");
    const MALFORMED_FUTURE_FILTER_UPDATE: &str =
        include_str!("../../../testdata/api/malformed-future-filter-update.json");
    const MALFORMED_ENABLED_FILTER_WITHOUT_UPDATE: &str =
        include_str!("../../../testdata/api/malformed-enabled-filter-without-update.json");

    fn golden_bodies() -> Vec<(&'static str, &'static str)> {
        vec![
            (STATUS_PATH, STATUS),
            (STATS_PATH, STATS),
            (DNS_INFO_PATH, DNS_INFO),
            (FILTERING_PATH, FILTERING_STATUS),
            (REWRITE_LIST_PATH, REWRITE_LIST),
            (REWRITE_SETTINGS_PATH, REWRITE_SETTINGS),
        ]
    }

    fn replacing(path: &str, body: &'static str) -> Vec<(&'static str, &'static str)> {
        let mut bodies = golden_bodies();
        for entry in &mut bodies {
            if entry.0 == path {
                entry.1 = body;
            }
        }
        bodies
    }

    async fn serve<'server>(
        server: &'server MockServer,
        bodies: &[(&'static str, &'static str)],
    ) -> Vec<Mock<'server>> {
        let mut mocks = Vec::with_capacity(bodies.len());
        for (path, body) in bodies.iter().copied() {
            mocks.push(
                server
                    .mock_async(move |when, then| {
                        when.method(GET).path(path);
                        then.status(200)
                            .header("content-type", "application/json")
                            .body(body);
                    })
                    .await,
            );
        }
        mocks
    }

    fn target(base_url: String) -> TargetConfig {
        TargetConfig {
            id: "resolver-a".to_owned(),
            name: "Resolver A".to_owned(),
            base_url,
            username: "admin".to_owned(),
            password_file: PathBuf::from("/run/credentials/synthetic-password"),
            policy: "home".to_owned(),
            condition_profile: "current".to_owned(),
            allow_insecure_local_http: false,
        }
    }

    fn example_policy() -> PolicyConfig {
        let config: Config =
            toml::from_str(include_str!("../../../config.example.toml")).expect("example config");
        config
            .policies
            .get("home")
            .cloned()
            .expect("the example configuration declares a home policy")
    }

    fn bounded_client(timeout_ms: u64, max_response_bytes: u64) -> ReqwestAdGuardClient {
        ReqwestAdGuardClient::new(timeout_ms, max_response_bytes, REQUIREMENT).expect("client")
    }

    async fn observe_with(
        client: &ReqwestAdGuardClient,
        server: &MockServer,
    ) -> Result<TargetReport, AdGuardError> {
        client
            .observe(
                &target(server.base_url()),
                &example_policy(),
                &SecretString::from("synthetic".to_owned()),
                LOOKBACK_MS,
                NOW,
            )
            .await
    }

    async fn observe(server: &MockServer) -> Result<TargetReport, AdGuardError> {
        observe_with(&bounded_client(TIMEOUT_MS, MAX_BYTES), server).await
    }

    fn near(left: f64, right: f64) -> bool {
        (left - right).abs() < 1e-9
    }

    fn filtering_of(body: &str) -> FilteringResponse {
        serde_json::from_str(body).expect("filtering fixture parses")
    }

    fn rewrites_of(body: &str) -> Vec<RewriteResponse> {
        serde_json::from_str(body).expect("rewrite fixture parses")
    }

    fn stats_of(body: &str) -> StatsResponse {
        serde_json::from_str(body).expect("stats fixture parses")
    }

    fn dns_of(body: &str) -> DnsResponse {
        serde_json::from_str(body).expect("dns fixture parses")
    }

    #[tokio::test]
    async fn golden_observation_normalizes_every_declared_field() {
        let server = MockServer::start_async().await;
        let mocks = serve(&server, &golden_bodies()).await;

        let report = observe(&server).await.expect("observation");

        assert!(report.complete);
        assert_eq!(report.server_version.as_deref(), Some("0.107.78"));
        assert_eq!(report.filtering_enabled, Some(true));
        assert_eq!(report.rewrites_enabled, Some(true));

        let operational = report.operational.expect("operational observation");
        assert!(operational.protection_enabled);
        assert_eq!(operational.queries, 5_000);
        assert_eq!(operational.blocked, 1_250);
        assert!(near(operational.blocked_ratio, 0.25));
        assert!(near(operational.average_processing_seconds, 0.0182));
        assert!(near(operational.maximum_upstream_seconds, 0.0241));
        assert!(near(operational.top_client_share, 0.62));

        let dns = report.dns.expect("dns observation");
        assert_eq!(dns.upstream_mode, "load_balance");
        assert_eq!(dns.upstream_dns, example_policy().upstream_dns);

        let upstreams: Vec<_> = report
            .upstreams
            .iter()
            .map(|upstream| upstream.identity.as_str())
            .collect();
        assert_eq!(
            upstreams,
            [
                "https://cloudflare-dns.com/dns-query",
                "quic://dns10.quad9.net",
                "tls://unfiltered.adguard-dns.com",
            ]
        );

        let rewrites: Vec<_> = report
            .rewrites
            .iter()
            .map(|rewrite| rewrite.domain.as_str())
            .collect();
        assert_eq!(
            rewrites,
            [
                "service-a.example.invalid",
                "service-b.example.invalid",
                "service-c.example.invalid",
            ]
        );

        for mock in mocks {
            mock.assert_calls_async(1).await;
        }
    }

    #[tokio::test]
    async fn observes_only_the_six_allowlisted_gets() {
        let server = MockServer::start_async().await;
        let mocks = serve(&server, &golden_bodies()).await;
        let outside_allowlist = server
            .mock_async(|when, then| {
                when.path_excludes(STATUS_PATH)
                    .path_excludes(STATS_PATH)
                    .path_excludes(DNS_INFO_PATH)
                    .path_excludes(FILTERING_PATH)
                    .path_excludes(REWRITE_LIST_PATH)
                    .path_excludes(REWRITE_SETTINGS_PATH);
                then.status(500);
            })
            .await;

        let report = observe(&server).await.expect("observation");

        assert!(report.complete);
        for mock in mocks {
            mock.assert_calls_async(1).await;
        }
        outside_allowlist.assert_calls_async(0).await;
    }

    #[tokio::test]
    async fn unknown_response_fields_are_ignored_for_forward_compatibility() {
        let server = MockServer::start_async().await;
        let _mocks = serve(
            &server,
            &replacing(
                STATUS_PATH,
                r#"{"protection_enabled":true,"running":true,"version":"v0.107.78","added_by_a_later_patch_release":42}"#,
            ),
        )
        .await;

        let report = observe(&server).await.expect("observation");

        assert!(report.complete);
    }

    #[tokio::test]
    async fn redirect_responses_are_not_followed() {
        let server = MockServer::start_async().await;
        let redirect = server
            .mock_async(|when, then| {
                when.method(GET).path(STATUS_PATH);
                then.status(302).header("location", "/control/elsewhere");
            })
            .await;
        let elsewhere = server
            .mock_async(|when, then| {
                when.method(GET).path("/control/elsewhere");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(STATUS);
            })
            .await;

        let error = observe(&server)
            .await
            .expect_err("a redirect must not be followed");

        assert_eq!(
            error.to_string(),
            "AdGuard API request failed at GET /control/status: HTTP 302"
        );
        redirect.assert_calls_async(1).await;
        elsewhere.assert_calls_async(0).await;
    }

    #[tokio::test]
    async fn a_malformed_body_is_an_invalid_response() {
        let server = MockServer::start_async().await;
        let _mocks = serve(
            &server,
            &replacing(STATUS_PATH, r#"{"protection_enabled":true,"running":"#),
        )
        .await;

        let error = observe(&server)
            .await
            .expect_err("a malformed body must fail closed");

        assert!(matches!(
            error,
            AdGuardError::InvalidResponse {
                endpoint: "GET /control/status",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_stopped_server_is_an_invalid_response() {
        let server = MockServer::start_async().await;
        let _mocks = serve(
            &server,
            &replacing(
                STATUS_PATH,
                r#"{"protection_enabled":true,"running":false,"version":"v0.107.78"}"#,
            ),
        )
        .await;

        let error = observe(&server)
            .await
            .expect_err("a stopped server must fail closed");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/status: running must be true for a complete observation"
        );
    }

    #[tokio::test]
    async fn partial_required_data_fails_closed_at_its_own_endpoint() {
        let server = MockServer::start_async().await;
        let _mocks = serve(
            &server,
            &replacing(DNS_INFO_PATH, MALFORMED_DNS_INFO_MISSING_MODE),
        )
        .await;

        let error = observe(&server)
            .await
            .expect_err("a missing required field must fail closed");

        assert!(matches!(
            error,
            AdGuardError::InvalidResponse {
                endpoint: "GET /control/dns_info",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_failed_endpoint_stops_the_remaining_requests() {
        let server = MockServer::start_async().await;
        let status = serve(&server, &[(STATUS_PATH, STATUS)]).await;
        let broken_stats = server
            .mock_async(|when, then| {
                when.method(GET).path(STATS_PATH);
                then.status(503);
            })
            .await;
        let later = serve(
            &server,
            &[
                (DNS_INFO_PATH, DNS_INFO),
                (FILTERING_PATH, FILTERING_STATUS),
                (REWRITE_LIST_PATH, REWRITE_LIST),
                (REWRITE_SETTINGS_PATH, REWRITE_SETTINGS),
            ],
        )
        .await;

        let error = observe(&server)
            .await
            .expect_err("a failed endpoint must abort the observation");

        assert_eq!(
            error.to_string(),
            "AdGuard API request failed at GET /control/stats: HTTP 503"
        );
        for mock in status {
            mock.assert_calls_async(1).await;
        }
        broken_stats.assert_calls_async(1).await;
        for mock in later {
            mock.assert_calls_async(0).await;
        }
    }

    #[tokio::test]
    async fn timeout_is_an_incomplete_unavailable_observation() {
        let server = MockServer::start_async().await;
        let _status = server
            .mock_async(|when, then| {
                when.method(GET).path(STATUS_PATH);
                then.status(200)
                    .delay(Duration::from_millis(100))
                    .header("content-type", "application/json")
                    .body(STATUS);
            })
            .await;

        let error = observe_with(&bounded_client(10, MAX_BYTES), &server)
            .await
            .expect_err("must time out");

        assert_eq!(
            error.to_string(),
            "AdGuard API request failed at GET /control/status: request timed out"
        );
    }

    #[tokio::test]
    async fn rejects_a_response_over_the_configured_limit() {
        let server = MockServer::start_async().await;
        let status = serve(&server, &[(STATUS_PATH, STATUS)]).await;

        let error = observe_with(&bounded_client(TIMEOUT_MS, 16), &server)
            .await
            .expect_err("must reject oversized body");

        assert!(matches!(error, AdGuardError::ResponseTooLarge { .. }));
        for mock in status {
            mock.assert_calls_async(1).await;
        }
    }

    #[tokio::test]
    async fn classifies_rejected_authentication_without_requesting_other_endpoints() {
        for code in [401_u16, 403] {
            let server = MockServer::start_async().await;
            let rejected = server
                .mock_async(move |when, then| {
                    when.method(GET).path(STATUS_PATH);
                    then.status(code);
                })
                .await;
            let statistics = serve(&server, &[(STATS_PATH, STATS)]).await;

            let error = observe(&server)
                .await
                .expect_err("must reject authentication");

            assert!(matches!(error, AdGuardError::AuthenticationRejected));
            rejected.assert_calls_async(1).await;
            for mock in statistics {
                mock.assert_calls_async(0).await;
            }
        }
    }

    #[tokio::test]
    async fn rejects_an_unsupported_server_version_before_other_requests() {
        let server = MockServer::start_async().await;
        let _mocks = serve(
            &server,
            &replacing(
                STATUS_PATH,
                r#"{"protection_enabled":true,"running":true,"version":"v0.108.0"}"#,
            ),
        )
        .await;
        let stats = serve(&server, &[(STATS_PATH, STATS)]).await;

        let error = observe(&server)
            .await
            .expect_err("unsupported version must fail");

        assert!(matches!(error, AdGuardError::UnsupportedVersion { .. }));
        for mock in stats {
            mock.assert_calls_async(0).await;
        }
    }

    #[test]
    fn normalizes_legacy_empty_upstream_mode_to_load_balance() {
        let observation =
            normalize_dns(dns_of(DNS_INFO)).expect("the legacy empty mode is load_balance");

        assert_eq!(observation.upstream_mode, "load_balance");
    }

    #[test]
    fn preserves_explicit_load_balance_upstream_mode() {
        let observation = normalize_dns(dns_of(DNS_INFO_EXPLICIT_MODE))
            .expect("an explicit load_balance mode is valid");

        assert_eq!(observation.upstream_mode, "load_balance");
    }

    #[test]
    fn rejects_a_whitespace_only_upstream_mode() {
        let error = normalize_dns(dns_of(MALFORMED_WHITESPACE_UPSTREAM_MODE))
            .expect_err("whitespace is not the legacy empty-string alias");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/dns_info: upstream mode must not contain only whitespace"
        );
    }

    #[test]
    fn rejects_empty_upstream_set_with_legacy_mode() {
        let error = normalize_dns(DnsResponse {
            upstream_dns: Vec::new(),
            upstream_mode: String::new(),
        })
        .expect_err("an empty upstream set must remain invalid");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/dns_info: upstream set must be nonempty"
        );
    }

    #[test]
    fn rejects_a_duplicated_upstream_set() {
        let error = normalize_dns(DnsResponse {
            upstream_dns: vec![
                "tls://resolver.invalid".to_owned(),
                "tls://resolver.invalid".to_owned(),
            ],
            upstream_mode: "load_balance".to_owned(),
        })
        .expect_err("a duplicated upstream set must be invalid");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/dns_info: upstream set contains empty or duplicate values"
        );
    }

    #[test]
    fn rejects_negative_latency_instead_of_defaulting_to_healthy() {
        let error = normalize_stats(true, &stats_of(MALFORMED_NEGATIVE_STATS))
            .expect_err("negative latency must fail");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/stats: avg_processing_time must be finite and nonnegative"
        );
    }

    #[test]
    fn rejects_a_blocked_count_above_the_query_count() {
        let error = normalize_stats(true, &stats_of(MALFORMED_BLOCKED_EXCEEDS_QUERIES))
            .expect_err("an impossible blocked count must fail");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/stats: num_blocked_filtering exceeds num_dns_queries"
        );
    }

    #[test]
    fn rejects_a_duplicated_top_client_identity() {
        let error = normalize_stats(true, &stats_of(MALFORMED_DUPLICATE_TOP_CLIENT))
            .expect_err("a duplicated client identity must fail");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/stats: top_clients contains invalid or duplicate data"
        );
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
        assert!(serde_json::from_str::<DnsResponse>(MALFORMED_DNS_INFO_MISSING_MODE).is_err());
    }

    #[test]
    fn normalizes_and_sorts_rewrite_entries() {
        let observed = normalize_rewrites(rewrites_of(REWRITE_LIST)).expect("golden rewrites");

        let rendered: Vec<_> = observed
            .iter()
            .map(|rewrite| {
                (
                    rewrite.domain.as_str(),
                    rewrite.answer.as_str(),
                    rewrite.enabled,
                )
            })
            .collect();
        assert_eq!(
            rendered,
            [
                ("service-a.example.invalid", "192.0.2.10", true),
                ("service-b.example.invalid", "2001:db8::1", true),
                ("service-c.example.invalid", "192.0.2.30", false),
            ]
        );
    }

    #[test]
    fn rejects_rewrites_that_collide_after_normalization() {
        let error = normalize_rewrites(rewrites_of(MALFORMED_DUPLICATE_REWRITES))
            .expect_err("normalized duplicates must fail");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/rewrite/list: rewrite list contains empty or duplicate normalized entries"
        );
    }

    #[test]
    fn rejects_an_empty_rewrite_domain() {
        let error = normalize_rewrites(rewrites_of(MALFORMED_EMPTY_REWRITE_DOMAIN))
            .expect_err("an empty rewrite domain must fail");

        assert!(matches!(
            error,
            AdGuardError::InvalidResponse {
                endpoint: "GET /control/rewrite/list",
                ..
            }
        ));
    }

    #[test]
    fn accepts_an_empty_rewrite_list() {
        assert!(
            normalize_rewrites(rewrites_of("[]"))
                .expect("an empty list is valid")
                .is_empty()
        );
    }

    #[test]
    fn retains_only_filters_named_by_declared_policy() {
        let observed = normalize_filters(
            filtering_of(FILTERING_STATUS).filters,
            &example_policy(),
            NOW,
        )
        .expect("golden filters");

        let rendered: Vec<_> = observed
            .iter()
            .map(|filter| {
                (
                    filter.url.as_str(),
                    filter.enabled,
                    filter.last_updated_unix_seconds,
                )
            })
            .collect();
        assert_eq!(
            rendered,
            [
                (
                    "https://filters.example.invalid/disabled.txt",
                    false,
                    None::<i64>,
                ),
                (
                    "https://filters.example.invalid/enabled.txt",
                    true,
                    Some(ONE_HOUR_BEFORE_NOW),
                ),
            ]
        );
    }

    #[test]
    fn rejects_a_required_filter_updated_in_the_future() {
        let error = normalize_filters(
            filtering_of(MALFORMED_FUTURE_FILTER_UPDATE).filters,
            &example_policy(),
            NOW,
        )
        .expect_err("a future update time must fail");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/filtering/status: required filter last_updated is in the future"
        );
    }

    #[test]
    fn rejects_an_enabled_required_filter_without_an_update_time() {
        let error = normalize_filters(
            filtering_of(MALFORMED_ENABLED_FILTER_WITHOUT_UPDATE).filters,
            &example_policy(),
            NOW,
        )
        .expect_err("an enabled required filter needs an update time");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/filtering/status: enabled required filter has no last_updated value"
        );
    }

    #[test]
    fn rejects_a_duplicated_filter_url() {
        let response = filtering_of(
            r#"{"enabled":true,"filters":[
                {"url":"https://filters.example.invalid/enabled.txt","last_updated":"2027-01-15T07:00:00Z","id":1,"rules_count":1,"enabled":true},
                {"url":"https://filters.example.invalid/enabled.txt","last_updated":"2027-01-15T07:00:00Z","id":2,"rules_count":1,"enabled":true}
            ]}"#,
        );

        let error = normalize_filters(response.filters, &example_policy(), NOW)
            .expect_err("a duplicated filter URL must fail");

        assert_eq!(
            error.to_string(),
            "AdGuard API response was invalid at GET /control/filtering/status: filter list contains an empty or duplicate URL"
        );
    }
}
