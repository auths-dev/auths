//! Port for storing and retrieving auth sessions.

use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::{AuthSession, SessionStatus};

/// Errors from the session store.
#[derive(Debug)]
pub enum StoreError {
    /// Session not found.
    NotFound(String),
    /// Internal storage error.
    Internal(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NotFound(msg) => write!(f, "session not found: {msg}"),
            StoreError::Internal(msg) => write!(f, "store error: {msg}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Manages the lifecycle of authentication sessions.
///
/// The `#[async_trait]` macro boxes the futures, making this trait
/// dyn-compatible for use as `Box<dyn SessionStore>`.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Store a new session.
    async fn create(&self, session: AuthSession) -> Result<(), StoreError>;

    /// Retrieve a session by ID.
    async fn get(&self, id: &Uuid) -> Result<Option<AuthSession>, StoreError>;

    /// Atomically transition a session from `from` status to `to` status.
    /// Returns `Ok(true)` if the row was updated, `Ok(false)` if the current
    /// status did not match `from` (no update performed).
    async fn update_status(
        &self,
        id: &Uuid,
        from: SessionStatus,
        to: SessionStatus,
    ) -> Result<bool, StoreError>;

    /// Delete a session by ID.
    async fn delete(&self, id: &Uuid) -> Result<(), StoreError>;

    /// List active (non-expired, pending) sessions with a hard cap.
    ///
    /// Args:
    /// * `limit`: Maximum number of rows to return (capped server-side).
    async fn list_active(&self, limit: u32) -> Result<Vec<AuthSession>, StoreError>;

    /// Remove expired sessions. Returns the number of sessions removed.
    async fn cleanup_expired(&self) -> Result<usize, StoreError>;
}
