//! In-memory client store for tests and development.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use auths_verifier::clock::{ClockProvider, SystemClock};

use crate::domain::RegisteredClient;
use crate::ports::{ClientStore, ClientStoreError};

/// In-memory client store backed by a `RwLock<HashMap>`.
pub struct InMemoryClientStore {
    clients: RwLock<HashMap<String, RegisteredClient>>,
    clock: Arc<dyn ClockProvider + Send + Sync>,
}

impl Default for InMemoryClientStore {
    fn default() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            clock: Arc::new(SystemClock),
        }
    }
}

impl InMemoryClientStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with an injected clock — use in tests with `MockClock`.
    pub fn with_clock(clock: Arc<dyn ClockProvider + Send + Sync>) -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            clock,
        }
    }
}

#[async_trait]
impl ClientStore for InMemoryClientStore {
    async fn create(&self, client: RegisteredClient) -> Result<(), ClientStoreError> {
        let mut map = self
            .clients
            .write()
            .map_err(|e| ClientStoreError::Internal(e.to_string()))?;
        if map.contains_key(&client.client_id) {
            return Err(ClientStoreError::DuplicateClientId(
                client.client_id.clone(),
            ));
        }
        map.insert(client.client_id.clone(), client);
        Ok(())
    }

    async fn get_by_id(
        &self,
        client_id: &str,
    ) -> Result<Option<RegisteredClient>, ClientStoreError> {
        let map = self
            .clients
            .read()
            .map_err(|e| ClientStoreError::Internal(e.to_string()))?;
        Ok(map.get(client_id).cloned())
    }

    async fn get_by_keri_aid(
        &self,
        keri_aid: &str,
    ) -> Result<Vec<RegisteredClient>, ClientStoreError> {
        let map = self
            .clients
            .read()
            .map_err(|e| ClientStoreError::Internal(e.to_string()))?;
        Ok(map
            .values()
            .filter(|c| c.keri_aid == keri_aid)
            .cloned()
            .collect())
    }

    async fn delete(&self, client_id: &str) -> Result<(), ClientStoreError> {
        let mut map = self
            .clients
            .write()
            .map_err(|e| ClientStoreError::Internal(e.to_string()))?;
        map.remove(client_id);
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize, ClientStoreError> {
        let mut map = self
            .clients
            .write()
            .map_err(|e| ClientStoreError::Internal(e.to_string()))?;
        let now = self.clock.now();
        let before = map.len();
        map.retain(|_, c| {
            // Remove if expired or revoked
            let expired = c.expires_at.is_some_and(|exp| exp <= now);
            let revoked = c.revoked_at.is_some();
            !expired && !revoked
        });
        Ok(before - map.len())
    }
}
