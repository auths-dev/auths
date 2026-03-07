//! HTTP client adapter layer for Auths.
//!
//! Implements the network port traits defined in `auths-core` using `reqwest`.
//! Each client wraps HTTP endpoints for the Auths infrastructure services.
//!
//! ## Modules
//!
//! - [`HttpRegistryClient`] — registry service client for identity and attestation operations
//! - [`HttpWitnessClient`] — synchronous witness client for KERI event submission
//! - [`HttpAsyncWitnessClient`] — async witness client with quorum support
//! - [`HttpIdentityResolver`] — DID resolution over HTTP

use std::time::Duration;

mod async_witness_client;
mod claim_client;
mod error;
mod github_gist;
mod github_oauth;
mod identity_resolver;
mod pairing_client;
mod registry_client;
mod request;
mod witness_client;

pub use async_witness_client::HttpAsyncWitnessClient;
pub use claim_client::HttpRegistryClaimClient;
pub use github_gist::HttpGistPublisher;
pub use github_oauth::HttpGitHubOAuthProvider;
pub use identity_resolver::HttpIdentityResolver;
pub use pairing_client::HttpPairingRelayClient;
pub use registry_client::HttpRegistryClient;
pub use witness_client::HttpWitnessClient;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Returns a [`reqwest::ClientBuilder`] pre-configured with hardened defaults:
/// 10s connect timeout, 30s request timeout, User-Agent, and TLS 1.2 minimum.
pub(crate) fn default_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .user_agent(concat!("auths/", env!("CARGO_PKG_VERSION")))
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
}

/// Builds an HTTP client with hardened defaults.
///
/// Usage:
/// ```ignore
/// let client = auths_infra_http::default_http_client();
/// ```
// INVARIANT: reqwest builder with these settings cannot fail
#[allow(clippy::expect_used)]
pub fn default_http_client() -> reqwest::Client {
    default_client_builder()
        .build()
        .expect("failed to build default HTTP client")
}
