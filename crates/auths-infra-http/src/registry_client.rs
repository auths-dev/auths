use auths_core::ports::network::{NetworkError, RegistryClient};
use std::future::Future;

use crate::request::{
    build_get_request, build_post_request, execute_request, parse_response_bytes,
};

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
            client: reqwest::Client::new(),
        }
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
}
