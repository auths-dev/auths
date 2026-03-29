use crate::domains::agents::types::AgentSession;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Persistence port for agent session storage
/// Implementations provide Redis, SQLite, or in-memory backends
#[async_trait]
pub trait AgentPersistencePort: Send + Sync {
    /// Store a session (create or update)
    async fn set_session(&self, session: &AgentSession) -> Result<(), String>;

    /// Retrieve a session by agent_did
    async fn get_session(&self, agent_did: &str) -> Result<Option<AgentSession>, String>;

    /// Delete a session
    async fn delete_session(&self, agent_did: &str) -> Result<(), String>;

    /// Set expiry on a session (auto-cleanup)
    async fn expire(&self, agent_did: &str, expires_at: DateTime<Utc>) -> Result<(), String>;

    /// Load all sessions (cache warming)
    async fn load_all(&self) -> Result<Vec<AgentSession>, String>;

    /// Find sessions by delegator
    async fn find_by_delegator(&self, delegator_did: &str) -> Result<Vec<AgentSession>, String>;

    /// Mark agent as revoked
    async fn revoke_agent(&self, agent_did: &str) -> Result<(), String>;
}
