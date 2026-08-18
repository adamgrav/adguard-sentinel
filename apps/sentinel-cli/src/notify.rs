use std::fs;
use std::time::Duration;

use anyhow::{Context, anyhow};
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use sentinel_core::{Config, OutboxMessage};
use sentinel_store::NotificationAttemptOutcome;
use serde::Deserialize;

const ENDPOINT: &str = "https://api.pushover.net/1/messages.json";
const MAX_RESPONSE_BYTES: u64 = 65_536;

#[derive(Debug)]
pub struct PushoverClient {
    client: reqwest::Client,
    endpoint: String,
    application_token: SecretString,
    user_key: SecretString,
}

impl PushoverClient {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        Self::build(config, ENDPOINT)
    }

    #[cfg(test)]
    pub fn with_endpoint(config: &Config, endpoint: &str) -> anyhow::Result<Self> {
        Self::build(config, endpoint)
    }

    fn build(config: &Config, endpoint: &str) -> anyhow::Result<Self> {
        let pushover = config
            .notifications
            .pushover
            .as_ref()
            .ok_or_else(|| anyhow!("Pushover configuration is absent"))?;
        let application_token = read_secret(&pushover.application_token_file)
            .context("cannot load Pushover application token")?;
        let user_key =
            read_secret(&pushover.user_key_file).context("cannot load Pushover user key")?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(
                config.observation.notification_timeout_ms,
            ))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .context("cannot construct Pushover client")?;
        Ok(Self {
            client,
            endpoint: endpoint.to_owned(),
            application_token,
            user_key,
        })
    }

    pub async fn send(&self, message: &OutboxMessage) -> NotificationAttemptOutcome {
        let form = [
            ("token", self.application_token.expose_secret()),
            ("user", self.user_key.expose_secret()),
            ("title", message.title.as_str()),
            ("message", message.message.as_str()),
            ("priority", if message.priority == -1 { "-1" } else { "0" }),
        ];
        let response = self
            .client
            .post(&self.endpoint)
            .header(
                reqwest::header::USER_AGENT,
                concat!("adguard-sentinel/", env!("CARGO_PKG_VERSION")),
            )
            .form(&form)
            .send()
            .await;
        let mut response = match response {
            Ok(response) => response,
            Err(error) if error.is_connect() => {
                return NotificationAttemptOutcome::Retryable {
                    http_status: None,
                    error_class: "connection_failed_before_response".to_owned(),
                };
            }
            Err(error) if error.is_timeout() => {
                return NotificationAttemptOutcome::Unknown {
                    error_class: "timeout_after_possible_transmission".to_owned(),
                };
            }
            Err(_) => {
                return NotificationAttemptOutcome::Unknown {
                    error_class: "transport_outcome_unknown".to_owned(),
                };
            }
        };
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES)
        {
            return NotificationAttemptOutcome::Unknown {
                error_class: "oversized_pushover_response".to_owned(),
            };
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    body.extend_from_slice(&chunk);
                    if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_RESPONSE_BYTES {
                        return NotificationAttemptOutcome::Unknown {
                            error_class: "oversized_pushover_response".to_owned(),
                        };
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    return NotificationAttemptOutcome::Unknown {
                        error_class: "response_interrupted_after_possible_delivery".to_owned(),
                    };
                }
            }
        }
        classify_response(status, &body)
    }
}

fn classify_response(status: StatusCode, body: &[u8]) -> NotificationAttemptOutcome {
    let parsed: Option<PushoverResponse> = serde_json::from_slice(body).ok();
    if status == StatusCode::OK {
        if let Some(parsed) = parsed {
            if parsed.status == 1 {
                if parsed.request.is_empty() {
                    return NotificationAttemptOutcome::Unknown {
                        error_class: "success_response_missing_request_id".to_owned(),
                    };
                }
                return NotificationAttemptOutcome::Delivered {
                    http_status: status.as_u16(),
                    remote_request_id: parsed.request,
                };
            }
            return NotificationAttemptOutcome::Failed {
                http_status: Some(status.as_u16()),
                remote_request_id: Some(parsed.request),
                error_class: "pushover_status_rejected".to_owned(),
            };
        }
        return NotificationAttemptOutcome::Unknown {
            error_class: "invalid_success_response".to_owned(),
        };
    }
    if status.is_server_error() {
        NotificationAttemptOutcome::Retryable {
            http_status: Some(status.as_u16()),
            error_class: "pushover_server_error".to_owned(),
        }
    } else {
        NotificationAttemptOutcome::Failed {
            http_status: Some(status.as_u16()),
            remote_request_id: parsed.map(|value| value.request),
            error_class: "pushover_permanent_rejection".to_owned(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct PushoverResponse {
    status: u8,
    request: String,
}

fn read_secret(path: &std::path::Path) -> anyhow::Result<SecretString> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(anyhow!("secret path is not a nonempty regular file"));
    }
    let value = fs::read_to_string(path)?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.is_empty() {
        return Err(anyhow!("secret file is empty"));
    }
    Ok(SecretString::from(value))
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;
    use sentinel_store::NotificationAttemptOutcome;

    use super::classify_response;

    #[test]
    fn requires_status_one_and_request_id_for_delivery() {
        let delivered = classify_response(
            StatusCode::OK,
            br#"{"status":1,"request":"synthetic-request"}"#,
        );
        assert!(matches!(
            delivered,
            NotificationAttemptOutcome::Delivered { .. }
        ));
        let ambiguous = classify_response(StatusCode::OK, br#"{"status":1,"request":""}"#);
        assert!(matches!(
            ambiguous,
            NotificationAttemptOutcome::Unknown { .. }
        ));
    }

    #[test]
    fn classifies_retryable_and_permanent_http_failures() {
        let retryable = classify_response(StatusCode::SERVICE_UNAVAILABLE, b"{}");
        assert!(matches!(
            retryable,
            NotificationAttemptOutcome::Retryable { .. }
        ));
        let permanent = classify_response(
            StatusCode::BAD_REQUEST,
            br#"{"status":0,"request":"synthetic-request"}"#,
        );
        assert!(matches!(
            permanent,
            NotificationAttemptOutcome::Failed { .. }
        ));
    }
}
