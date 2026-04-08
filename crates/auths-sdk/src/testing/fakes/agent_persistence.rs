use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::domains::agents::persistence::AgentPersistencePort;
use crate::domains::agents::types::{AgentSession, AgentStatus};

/// In-memory fake for [`AgentPersistencePort`], suitable for unit tests.
pub struct FakeAgentPersistence {
    sessions: Mutex<HashMap<String, AgentSession>>,
}

impl Default for FakeAgentPersistence {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeAgentPersistence {
    /// Create an empty in-memory agent persistence store.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl AgentPersistencePort for FakeAgentPersistence {
    async fn set_session(&self, session: &AgentSession) -> Result<(), String> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session.agent_did.clone(), session.clone());
        Ok(())
    }

    async fn get_session(&self, agent_did: &str) -> Result<Option<AgentSession>, String> {
        Ok(self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(agent_did)
            .cloned())
    }

    async fn delete_session(&self, agent_did: &str) -> Result<(), String> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(agent_did);
        Ok(())
    }

    async fn expire(&self, _agent_did: &str, _expires_at: DateTime<Utc>) -> Result<(), String> {
        Ok(())
    }

    async fn load_all(&self) -> Result<Vec<AgentSession>, String> {
        Ok(self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }

    async fn find_by_delegator(&self, delegator_did: &str) -> Result<Vec<AgentSession>, String> {
        Ok(self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|s| s.delegator_did.as_deref() == Some(delegator_did))
            .cloned()
            .collect())
    }

    async fn revoke_agent(&self, agent_did: &str) -> Result<(), String> {
        if let Some(session) = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(agent_did)
        {
            session.status = AgentStatus::Revoked;
        }
        Ok(())
    }
}
