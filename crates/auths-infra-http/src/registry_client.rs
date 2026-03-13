use auths_core::ports::network::{NetworkError, RateLimitInfo, RegistryClient, RegistryResponse};
use std::future::Future;
use std::time::Duration;

use crate::error::map_reqwest_error;
use crate::request::{
    build_get_request, build_post_request, execute_request, parse_response_bytes,
};
use crate::{default_client_builder, default_http_client};

/// HTTP-backed implementation of `RegistryClient`.
///
/// Fetches and pushes data to a remote registry service for identity
/// and attestation synchronization.
///
/// Usage:
/// ```ignore
/// use auths_infra_http::HttpRegistryClient;
///
/// let client = HttpRegistryClient::new();
/// let data = client.fetch_registry_data("https://registry.example.com", "identities/abc").await?;
/// ```
pub struct HttpRegistryClient {
    client: reqwest::Client,
}

impl HttpRegistryClient {
    pub fn new() -> Self {
        Self {
            client: default_http_client(),
        }
    }

    /// Create an `HttpRegistryClient` with explicit connect and request timeouts.
    ///
    /// Args:
    /// * `connect_timeout`: Maximum time to establish a TCP connection.
    /// * `request_timeout`: Maximum total time for the request to complete.
    ///
    /// Usage:
    /// ```ignore
    /// let client = HttpRegistryClient::new_with_timeouts(
    ///     Duration::from_secs(30),
    ///     Duration::from_secs(60),
    /// );
    /// ```
    // INVARIANT: reqwest builder with these settings cannot fail
    #[allow(clippy::expect_used)]
    pub fn new_with_timeouts(connect_timeout: Duration, request_timeout: Duration) -> Self {
        let client = default_client_builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }
}

impl Default for HttpRegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryClient for HttpRegistryClient {
    fn fetch_registry_data(
        &self,
        registry_url: &str,
        path: &str,
    ) -> impl Future<Output = Result<Vec<u8>, NetworkError>> + Send {
        let url = format!("{}/{}", registry_url.trim_end_matches('/'), path);
        let request = build_get_request(&self.client, &url);

        async move {
            let response = execute_request(request, registry_url).await?;
            parse_response_bytes(response, path).await
        }
    }

    fn push_registry_data(
        &self,
        registry_url: &str,
        path: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), NetworkError>> + Send {
        let url = format!("{}/{}", registry_url.trim_end_matches('/'), path);
        let request = build_post_request(&self.client, &url, data.to_vec());

        async move {
            let response = execute_request(request, registry_url).await?;
            let _ = parse_response_bytes(response, path).await?;
            Ok(())
        }
    }

    fn post_json(
        &self,
        registry_url: &str,
        path: &str,
        json_body: &[u8],
    ) -> impl Future<Output = Result<RegistryResponse, NetworkError>> + Send {
        let url = format!("{}/{}", registry_url.trim_end_matches('/'), path);
        let request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(json_body.to_vec());
        let endpoint = registry_url.to_string();

        async move {
            let response = request
                .send()
                .await
                .map_err(|e| map_reqwest_error(e, &endpoint))?;
            let status = response.status().as_u16();
            let rate_limit = extract_rate_limit_headers(&response);
            let body = response.bytes().await.map(|b| b.to_vec()).map_err(|e| {
                NetworkError::InvalidResponse {
                    detail: e.to_string(),
                }
            })?;
            Ok(RegistryResponse {
                status,
                body,
                rate_limit,
            })
        }
    }
}

fn extract_rate_limit_headers(response: &reqwest::Response) -> Option<RateLimitInfo> {
    let headers = response.headers();
    let limit = headers
        .get("x-ratelimit-limit")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i32>().ok());
    let remaining = headers
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i32>().ok());
    let reset = headers
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok());
    let tier = headers
        .get("x-ratelimit-tier")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if limit.is_some() || remaining.is_some() || reset.is_some() || tier.is_some() {
        Some(RateLimitInfo {
            limit,
            remaining,
            reset,
            tier,
        })
    } else {
        None
    }
}
