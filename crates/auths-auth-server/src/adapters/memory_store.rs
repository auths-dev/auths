//! In-memory session store using DashMap.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use auths_verifier::clock::{ClockProvider, SystemClock};
use uuid::Uuid;

use crate::domain::{AuthSession, SessionStatus};
use crate::ports::{SessionStore, StoreError};

/// In-memory session store backed by a `RwLock<HashMap>`.
pub struct InMemorySessionStore {
    sessions: RwLock<HashMap<Uuid, AuthSession>>,
    clock: Arc<dyn ClockProvider + Send + Sync>,
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            clock: Arc::new(SystemClock),
        }
    }
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with an injected clock — use in tests with `MockClock`.
    pub fn with_clock(clock: Arc<dyn ClockProvider + Send + Sync>) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            clock,
        }
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create(&self, session: AuthSession) -> Result<(), StoreError> {
        let id = session.challenge.id;
        let mut map = self
            .sessions
            .write()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        map.insert(id, session);
        Ok(())
    }

    async fn get(&self, id: &Uuid) -> Result<Option<AuthSession>, StoreError> {
        let map = self
            .sessions
            .read()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        Ok(map.get(id).cloned())
    }

    async fn update_status(
        &self,
        id: &Uuid,
        from: SessionStatus,
        to: SessionStatus,
    ) -> Result<bool, StoreError> {
        let mut map = self
            .sessions
            .write()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        match map.get_mut(id) {
            None => Ok(false),
            Some(session) => {
                if std::mem::discriminant(&session.status) == std::mem::discriminant(&from) {
                    session.status = to;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    async fn delete(&self, id: &Uuid) -> Result<(), StoreError> {
        let mut map = self
            .sessions
            .write()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        map.remove(id);
        Ok(())
    }

    async fn list_active(&self, limit: u32) -> Result<Vec<AuthSession>, StoreError> {
        let map = self
            .sessions
            .read()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        let now = self.clock.now();
        Ok(map
            .values()
            .filter(|s| s.challenge.expires_at > now && matches!(s.status, SessionStatus::Pending))
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn cleanup_expired(&self) -> Result<usize, StoreError> {
        let mut map = self
            .sessions
            .write()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        let now = self.clock.now();
        let before = map.len();
        map.retain(|_, s| s.challenge.expires_at > now);
        Ok(before - map.len())
    }
}
