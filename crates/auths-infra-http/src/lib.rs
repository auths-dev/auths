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

mod async_witness_client;
mod error;
mod identity_resolver;
mod pairing_client;
mod registry_client;
mod request;
mod witness_client;

pub use async_witness_client::HttpAsyncWitnessClient;
pub use identity_resolver::HttpIdentityResolver;
pub use pairing_client::HttpPairingRelayClient;
pub use registry_client::HttpRegistryClient;
pub use witness_client::HttpWitnessClient;
