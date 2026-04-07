use auths_core::ports::network::{NetworkError, WitnessClient};
use auths_keri::Prefix;
use std::future::Future;
use std::time::Duration;

use crate::default_client_builder;
use crate::request::{
    build_get_request, build_post_request, execute_request, parse_response_bytes,
};

/// HTTP-backed implementation of `WitnessClient`.
///
/// Communicates with KERI witness servers to submit events and
/// query receipts.
///
/// Usage:
/// ```ignore
/// use auths_infra_http::HttpWitnessClient;
///
/// let client = HttpWitnessClient::new(std::time::Duration::from_secs(5));
/// let receipt = client.submit_event("http://witness:3000", &event_bytes).await?;
/// ```
pub struct HttpWitnessClient {
    client: reqwest::Client,
}

impl HttpWitnessClient {
    // INVARIANT: reqwest builder with these settings cannot fail
    #[allow(clippy::expect_used)]
    pub fn new(timeout: Duration) -> Self {
        Self {
            client: default_client_builder()
                .timeout(timeout)
                .build()
                .expect("failed to build reqwest client"),
        }
    }
}

impl WitnessClient for HttpWitnessClient {
    fn submit_event(
        &self,
        endpoint: &str,
        event: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, NetworkError>> + Send {
        let url = format!("{}/witness/events", endpoint.trim_end_matches('/'));
        let request = build_post_request(&self.client, &url, event.to_vec());

        async move {
            let response = execute_request(request, endpoint).await?;
            parse_response_bytes(response, &url).await
        }
    }

    fn query_receipts(
        &self,
        endpoint: &str,
        prefix: &Prefix,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>, NetworkError>> + Send {
        let url = format!(
            "{}/witness/{}/receipts",
            endpoint.trim_end_matches('/'),
            prefix
        );
        let request = build_get_request(&self.client, &url);

        async move {
            let response = execute_request(request, endpoint).await?;
            let bytes = parse_response_bytes(response, &url).await?;
            let receipts: Vec<Vec<u8>> =
                serde_json::from_slice(&bytes).map_err(|e| NetworkError::InvalidResponse {
                    detail: e.to_string(),
                })?;
            Ok(receipts)
        }
    }
}
