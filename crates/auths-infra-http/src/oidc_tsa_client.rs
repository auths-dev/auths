use async_trait::async_trait;

use crate::default_http_client;
use auths_oidc_port::{OidcError, TimestampClient, TimestampConfig};

/// HTTP-based implementation of TimestampClient for RFC 3161 timestamp authority operations.
///
/// Submits data to a configured TSA endpoint and returns the RFC 3161 timestamp token.
/// Supports graceful degradation if TSA is unavailable and fallback_on_error is enabled.
pub struct HttpTimestampClient;

impl HttpTimestampClient {
    /// Create a new HttpTimestampClient.
    pub fn new() -> Self {
        Self
    }
}

impl Default for HttpTimestampClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TimestampClient for HttpTimestampClient {
    async fn timestamp(
        &self,
        data: &[u8],
        config: &TimestampConfig,
    ) -> Result<Option<Vec<u8>>, OidcError> {
        let tsa_uri = match &config.tsa_uri {
            Some(uri) => uri,
            None => {
                return if config.fallback_on_error {
                    Ok(None)
                } else {
                    Err(OidcError::JwksResolutionFailed(
                        "timestamp authority URI not configured".to_string(),
                    ))
                };
            }
        };

        let client = default_http_client();

        let response = client
            .post(tsa_uri)
            .header("Content-Type", "application/octet-stream")
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .body(data.to_vec())
            .send()
            .await;

        match response {
            Ok(resp) => {
                let timestamp_token = resp.bytes().await.map_err(|e| {
                    OidcError::JwksResolutionFailed(format!(
                        "failed to read timestamp response: {}",
                        e
                    ))
                })?;

                Ok(Some(timestamp_token.to_vec()))
            }
            Err(e) => {
                if config.fallback_on_error {
                    Ok(None)
                } else {
                    Err(OidcError::JwksResolutionFailed(format!(
                        "failed to acquire timestamp from {}: {}",
                        tsa_uri, e
                    )))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_timestamp_client_creation() {
        let _client = HttpTimestampClient::new();
        let _default_client = HttpTimestampClient::new();
        // Both should construct without error
    }
}
