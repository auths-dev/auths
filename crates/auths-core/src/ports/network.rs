//! Network port and DID resolution.

use std::future::Future;

use auths_verifier::keri::Prefix;

use crate::signing::DidMethod;

/// Domain error for outbound network operations.
///
/// Adapters map transport-specific failures (e.g., HTTP timeouts, connection
/// refused) into these variants. Domain logic never sees transport details.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::network::NetworkError;
///
/// fn handle(err: NetworkError) {
///     match err {
///         NetworkError::Unreachable { endpoint } => eprintln!("cannot reach {endpoint}"),
///         NetworkError::Timeout { endpoint } => eprintln!("timed out: {endpoint}"),
///         NetworkError::NotFound { resource } => eprintln!("missing: {resource}"),
///         NetworkError::Unauthorized => eprintln!("not authorized"),
///         NetworkError::InvalidResponse { detail } => eprintln!("bad response: {detail}"),
///         NetworkError::Internal(inner) => eprintln!("bug: {inner}"),
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// The endpoint could not be reached.
    #[error("endpoint unreachable: {endpoint}")]
    Unreachable {
        /// The unreachable endpoint URL.
        endpoint: String,
    },

    /// The request timed out.
    #[error("request timed out: {endpoint}")]
    Timeout {
        /// The endpoint that timed out.
        endpoint: String,
    },

    /// The requested resource was not found.
    #[error("resource not found: {resource}")]
    NotFound {
        /// The missing resource identifier.
        resource: String,
    },

    /// Authentication or authorisation failed.
    #[error("unauthorized")]
    Unauthorized,

    /// The server returned an unexpected response.
    #[error("invalid response: {detail}")]
    InvalidResponse {
        /// Details about the invalid response.
        detail: String,
    },

    /// An unexpected internal error.
    #[error("internal network error: {0}")]
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

/// Domain error for identity resolution operations.
///
/// Distinguishes resolution-specific failures (unknown DID, revoked key)
/// from general transport failures via the `Network` variant.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::network::ResolutionError;
///
/// fn handle(err: ResolutionError) {
///     match err {
///         ResolutionError::DidNotFound { did } => eprintln!("unknown: {did}"),
///         ResolutionError::InvalidDid { did, reason } => eprintln!("{did}: {reason}"),
///         ResolutionError::KeyRevoked { did } => eprintln!("revoked: {did}"),
///         ResolutionError::Network(inner) => eprintln!("transport: {inner}"),
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum ResolutionError {
    /// The DID was not found.
    #[error("DID not found: {did}")]
    DidNotFound {
        /// The DID that was not found.
        did: String,
    },

    /// The DID is malformed.
    #[error("invalid DID {did}: {reason}")]
    InvalidDid {
        /// The malformed DID.
        did: String,
        /// Reason the DID is invalid.
        reason: String,
    },

    /// The key for this DID has been revoked.
    #[error("key revoked for DID: {did}")]
    KeyRevoked {
        /// The DID whose key was revoked.
        did: String,
    },

    /// A network error occurred during resolution.
    #[error("network error: {0}")]
    Network(#[from] NetworkError),
}

/// Cryptographic material resolved from a decentralized identifier.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::network::ResolvedIdentity;
///
/// let identity: ResolvedIdentity = resolver.resolve_identity("did:key:z...").await?;
/// let pk = identity.public_key;
/// ```
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    /// The resolved DID string.
    pub did: String,
    /// The raw Ed25519 public key.
    pub public_key: Vec<u8>,
    /// The DID method.
    pub method: DidMethod,
}

/// Resolves a decentralized identifier to its current cryptographic material.
///
/// Implementations may fetch data from local stores, remote registries, or
/// peer-to-peer networks. The domain only provides a DID string and receives
/// the resolved key material.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::network::IdentityResolver;
///
/// async fn verify_signer(resolver: &dyn IdentityResolver, did: &str) -> Vec<u8> {
///     let resolved = resolver.resolve_identity(did).await.unwrap();
///     resolved.public_key
/// }
/// ```
pub trait IdentityResolver: Send + Sync {
    /// Resolves a DID string to its current public key and method metadata.
    ///
    /// Args:
    /// * `did`: The decentralized identifier to resolve (e.g., `"did:keri:EAbcdef..."`).
    ///
    /// Usage:
    /// ```ignore
    /// let identity = resolver.resolve_identity("did:key:z6Mk...").await?;
    /// ```
    fn resolve_identity(
        &self,
        did: &str,
    ) -> impl Future<Output = Result<ResolvedIdentity, ResolutionError>> + Send;
}

/// Submits key events and queries receipts from the witness infrastructure.
///
/// Witnesses observe and receipt key events to provide accountability.
/// Implementations handle the transport details; the domain provides
/// serialized events and receives receipts as opaque byte arrays.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::network::WitnessClient;
///
/// async fn witness_inception(client: &dyn WitnessClient, endpoint: &str, event: &[u8]) {
///     let receipt = client.submit_event(endpoint, event).await.unwrap();
/// }
/// ```
pub trait WitnessClient: Send + Sync {
    /// Submits a serialized key event to a witness and returns the receipt bytes.
    ///
    /// Args:
    /// * `endpoint`: The witness endpoint identifier.
    /// * `event`: The serialized key event bytes.
    ///
    /// Usage:
    /// ```ignore
    /// let receipt = client.submit_event("witness-1.example.com", &event_bytes).await?;
    /// ```
    fn submit_event(
        &self,
        endpoint: &str,
        event: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, NetworkError>> + Send;

    /// Queries all receipts a witness holds for the given KERI prefix.
    ///
    /// Args:
    /// * `endpoint`: The witness endpoint identifier.
    /// * `prefix`: The KERI prefix to query receipts for.
    ///
    /// Usage:
    /// ```ignore
    /// let prefix = Prefix::new_unchecked("EAbcdef...".into());
    /// let receipts = client.query_receipts("witness-1.example.com", &prefix).await?;
    /// ```
    fn query_receipts(
        &self,
        endpoint: &str,
        prefix: &Prefix,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>, NetworkError>> + Send;
}

/// Fetches and pushes data to a remote registry service.
///
/// Implementations handle the transport protocol (e.g., HTTP, gRPC).
/// The domain provides logical paths and receives raw bytes.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::network::RegistryClient;
///
/// async fn sync_identity(client: &dyn RegistryClient, url: &str) {
///     let data = client.fetch_registry_data(url, "identities/abc123").await.unwrap();
/// }
/// ```
pub trait RegistryClient: Send + Sync {
    /// Fetches data from a registry at the given logical path.
    ///
    /// Args:
    /// * `registry_url`: The registry service identifier.
    /// * `path`: The logical path within the registry.
    ///
    /// Usage:
    /// ```ignore
    /// let data = client.fetch_registry_data("registry.example.com", "identities/abc123").await?;
    /// ```
    fn fetch_registry_data(
        &self,
        registry_url: &str,
        path: &str,
    ) -> impl Future<Output = Result<Vec<u8>, NetworkError>> + Send;

    /// Pushes data to a registry at the given logical path.
    ///
    /// Args:
    /// * `registry_url`: The registry service identifier.
    /// * `path`: The logical path within the registry.
    /// * `data`: The raw bytes to push.
    ///
    /// Usage:
    /// ```ignore
    /// client.push_registry_data("registry.example.com", "identities/abc123", &bytes).await?;
    /// ```
    fn push_registry_data(
        &self,
        registry_url: &str,
        path: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), NetworkError>> + Send;
}
