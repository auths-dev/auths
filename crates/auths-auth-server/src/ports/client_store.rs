//! Port for storing and retrieving dynamically registered OIDC clients.

use async_trait::async_trait;

use crate::domain::RegisteredClient;

/// Errors from the client store.
#[derive(Debug)]
pub enum ClientStoreError {
    /// Client not found.
    NotFound(String),
    /// Duplicate client ID.
    DuplicateClientId(String),
    /// Internal storage error.
    Internal(String),
}

impl std::fmt::Display for ClientStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientStoreError::NotFound(msg) => write!(f, "client not found: {msg}"),
            ClientStoreError::DuplicateClientId(msg) => write!(f, "duplicate client id: {msg}"),
            ClientStoreError::Internal(msg) => write!(f, "client store error: {msg}"),
        }
    }
}

impl std::error::Error for ClientStoreError {}

/// Manages the lifecycle of dynamically registered OIDC clients.
///
/// Args:
/// * Follows the same `#[async_trait]` pattern as `SessionStore` for
///   dyn-compatibility via `Box<dyn ClientStore>`.
///
/// Usage:
/// ```ignore
/// let store: Box<dyn ClientStore> = Box::new(InMemoryClientStore::new());
/// store.create(client).await?;
/// ```
#[async_trait]
pub trait ClientStore: Send + Sync {
    /// Store a newly registered client.
    async fn create(&self, client: RegisteredClient) -> Result<(), ClientStoreError>;

    /// Retrieve a client by its `client_id`.
    async fn get_by_id(
        &self,
        client_id: &str,
    ) -> Result<Option<RegisteredClient>, ClientStoreError>;

    /// Retrieve all clients registered by a given KERI AID.
    async fn get_by_keri_aid(
        &self,
        keri_aid: &str,
    ) -> Result<Vec<RegisteredClient>, ClientStoreError>;

    /// Delete a client by its `client_id`.
    async fn delete(&self, client_id: &str) -> Result<(), ClientStoreError>;

    /// Remove expired clients. Returns the number of clients removed.
    async fn cleanup_expired(&self) -> Result<usize, ClientStoreError>;
}
