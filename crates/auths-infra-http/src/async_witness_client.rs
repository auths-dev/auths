use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::default_client_builder;
use auths_core::witness::{
    AsyncWitnessProvider, DuplicityEvidence, EventHash, Receipt, WitnessError,
};
use auths_keri::{Prefix, Said};

/// HTTP-based witness client implementing [`AsyncWitnessProvider`].
///
/// Communicates with a KERI witness server over HTTP to submit events,
/// retrieve receipts, and check identity heads.
///
/// Usage:
/// ```ignore
/// use auths_infra_http::HttpAsyncWitnessClient;
///
/// let client = HttpAsyncWitnessClient::new("http://localhost:3000", 2)
///     .with_timeout(std::time::Duration::from_secs(10));
/// ```
#[derive(Debug, Clone)]
pub struct HttpAsyncWitnessClient {
    base_url: String,
    client: reqwest::Client,
    quorum_size: usize,
    timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct HeadResponse {
    #[allow(dead_code)] // serde deserialize target — field must exist for JSON mapping
    prefix: String,
    latest_seq: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    duplicity: Option<DuplicityEvidence>,
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
}

impl HttpAsyncWitnessClient {
    /// Creates a new HTTP async witness client.
    ///
    /// Args:
    /// * `base_url`: The witness server base URL (e.g., `"http://localhost:3000"`).
    /// * `quorum_size`: Minimum receipts required for this witness.
    ///
    /// Usage:
    /// ```ignore
    /// let client = HttpAsyncWitnessClient::new("http://witness:3000", 1);
    /// ```
    // INVARIANT: reqwest builder with these settings cannot fail
    #[allow(clippy::expect_used)]
    pub fn new(base_url: impl Into<String>, quorum_size: usize) -> Self {
        let timeout = Duration::from_secs(5);
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: default_client_builder()
                .timeout(timeout)
                .build()
                .expect("failed to build reqwest client"),
            quorum_size,
            timeout,
        }
    }

    /// Sets a custom timeout for HTTP requests.
    ///
    /// Args:
    /// * `timeout`: The request timeout duration.
    ///
    /// Usage:
    /// ```ignore
    /// let client = HttpAsyncWitnessClient::new("http://witness:3000", 1)
    ///     .with_timeout(Duration::from_secs(30));
    /// ```
    // INVARIANT: reqwest builder with these settings cannot fail
    #[allow(clippy::expect_used)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.client = default_client_builder()
            .timeout(timeout)
            .build()
            .expect("failed to build reqwest client");
        self
    }
}

#[async_trait]
impl AsyncWitnessProvider for HttpAsyncWitnessClient {
    async fn submit_event(
        &self,
        prefix: &Prefix,
        event_json: &[u8],
    ) -> Result<Receipt, WitnessError> {
        let url = format!("{}/witness/{}/event", self.base_url, prefix);

        let event_value: serde_json::Value = serde_json::from_slice(event_json)
            .map_err(|e| WitnessError::Serialization(e.to_string()))?;

        let response = self
            .client
            .post(&url)
            .json(&event_value)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    WitnessError::Timeout(self.timeout.as_millis() as u64)
                } else {
                    WitnessError::Network(e.to_string())
                }
            })?;

        let status = response.status();

        if status.is_success() {
            response
                .json::<Receipt>()
                .await
                .map_err(|e| WitnessError::Serialization(e.to_string()))
        } else if status.as_u16() == 409 {
            let error_resp: ErrorResponse = response
                .json()
                .await
                .map_err(|e| WitnessError::Serialization(e.to_string()))?;

            if let Some(evidence) = error_resp.duplicity {
                Err(WitnessError::Duplicity(evidence))
            } else {
                Err(WitnessError::Rejected {
                    reason: error_resp.error,
                })
            }
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(WitnessError::Rejected {
                reason: format!("HTTP {}: {}", status, body),
            })
        }
    }

    async fn observe_identity_head(
        &self,
        prefix: &Prefix,
    ) -> Result<Option<EventHash>, WitnessError> {
        let url = format!("{}/witness/{}/head", self.base_url, prefix);

        let response = self.client.get(&url).send().await.map_err(|e| {
            if e.is_timeout() {
                WitnessError::Timeout(self.timeout.as_millis() as u64)
            } else {
                WitnessError::Network(e.to_string())
            }
        })?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(WitnessError::Network(format!(
                "head query failed: {}",
                body
            )));
        }

        let head: HeadResponse = response
            .json()
            .await
            .map_err(|e| WitnessError::Serialization(e.to_string()))?;

        Ok(head.latest_seq.map(|seq| {
            let mut bytes = [0u8; 20];
            bytes[12..20].copy_from_slice(&seq.to_be_bytes());
            EventHash::from_bytes(bytes)
        }))
    }

    async fn get_receipt(
        &self,
        prefix: &Prefix,
        event_said: &Said,
    ) -> Result<Option<Receipt>, WitnessError> {
        let url = format!(
            "{}/witness/{}/receipt/{}",
            self.base_url, prefix, event_said
        );

        let response = self.client.get(&url).send().await.map_err(|e| {
            if e.is_timeout() {
                WitnessError::Timeout(self.timeout.as_millis() as u64)
            } else {
                WitnessError::Network(e.to_string())
            }
        })?;

        if response.status().as_u16() == 404 {
            return Ok(None);
        }

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(WitnessError::Network(format!(
                "receipt query failed: {}",
                body
            )));
        }

        let receipt: Receipt = response
            .json()
            .await
            .map_err(|e| WitnessError::Serialization(e.to_string()))?;

        Ok(Some(receipt))
    }

    fn quorum(&self) -> usize {
        self.quorum_size
    }

    fn timeout_ms(&self) -> u64 {
        self.timeout.as_millis() as u64
    }

    async fn is_available(&self) -> Result<bool, WitnessError> {
        let url = format!("{}/health", self.base_url);

        let response = self.client.get(&url).send().await.map_err(|e| {
            if e.is_timeout() {
                WitnessError::Timeout(self.timeout.as_millis() as u64)
            } else {
                WitnessError::Network(e.to_string())
            }
        })?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let health: HealthResponse = response
            .json()
            .await
            .map_err(|e| WitnessError::Serialization(e.to_string()))?;

        Ok(health.status == "ok")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn builder_strips_trailing_slash() {
        let client = HttpAsyncWitnessClient::new("http://localhost:3000/", 1);
        assert_eq!(client.base_url, "http://localhost:3000");
    }

    #[tokio::test]
    async fn builder_preserves_clean_url() {
        let client = HttpAsyncWitnessClient::new("http://localhost:3000", 2);
        assert_eq!(client.base_url, "http://localhost:3000");
        assert_eq!(client.quorum_size, 2);
    }

    #[tokio::test]
    async fn custom_timeout() {
        let client = HttpAsyncWitnessClient::new("http://localhost:3000", 1)
            .with_timeout(Duration::from_secs(30));
        assert_eq!(client.timeout_ms(), 30_000);
    }

    #[tokio::test]
    async fn default_timeout_is_5s() {
        let client = HttpAsyncWitnessClient::new("http://localhost:3000", 1);
        assert_eq!(client.timeout_ms(), 5_000);
    }
}
