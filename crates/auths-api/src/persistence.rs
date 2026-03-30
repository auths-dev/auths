use async_trait::async_trait;
use auths_sdk::domains::agents::AgentPersistencePort;
use auths_sdk::domains::agents::types::{AgentSession, AgentStatus};
use chrono::{DateTime, Utc};
use redis::AsyncCommands;

/// Redis-backed persistence layer for agent sessions
pub struct AgentPersistence {
    client: Option<redis::Client>,
}

impl AgentPersistence {
    /// Create a new persistence layer (connects to Redis at default localhost:6379)
    pub fn new() -> Result<Self, redis::RedisError> {
        let client = redis::Client::open("redis://127.0.0.1:6379/")?;
        Ok(Self {
            client: Some(client),
        })
    }

    /// Create a new persistence layer with custom URL
    pub fn with_url(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        Ok(Self {
            client: Some(client),
        })
    }

    /// Create a test-mode persistence layer (no Redis, operations are no-ops)
    #[allow(dead_code)] // Used in tests
    pub fn new_test() -> Self {
        Self { client: None }
    }

    /// Store session in Redis with key: "agent:{agent_did}"
    pub async fn set_session(
        &self,
        session: &AgentSession,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(client) = &self.client else {
            return Ok(()); // Test mode: no-op
        };

        let mut conn = client.get_multiplexed_async_connection().await?;
        let key = format!("agent:{}", session.agent_did);
        let value = serde_json::to_string(session)?;

        let _: () = conn.set(&key, &value).await?;

        Ok(())
    }

    /// Retrieve session from Redis by agent_did
    pub async fn get_session(
        &self,
        agent_did: &str,
    ) -> Result<Option<AgentSession>, Box<dyn std::error::Error>> {
        let Some(client) = &self.client else {
            return Ok(None); // Test mode: no-op
        };

        let mut conn = client.get_multiplexed_async_connection().await?;
        let key = format!("agent:{}", agent_did);

        let value: Option<String> = conn.get(&key).await?;

        match value {
            Some(json) => {
                let session = serde_json::from_str(&json)?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Delete session from Redis
    pub async fn delete_session(&self, agent_did: &str) -> Result<(), Box<dyn std::error::Error>> {
        let Some(client) = &self.client else {
            return Ok(()); // Test mode: no-op
        };

        let mut conn = client.get_multiplexed_async_connection().await?;
        let key = format!("agent:{}", agent_did);

        let _: () = conn.del(&key).await?;

        Ok(())
    }

    /// Set expiry on a session key (auto-cleanup)
    pub async fn expire(
        &self,
        agent_did: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(client) = &self.client else {
            return Ok(()); // Test mode: no-op
        };

        let mut conn = client.get_multiplexed_async_connection().await?;
        let key = format!("agent:{}", agent_did);

        #[allow(clippy::disallowed_methods)]
        // INVARIANT: persistence layer gets current time to calculate TTL
        let ttl_seconds = (expires_at - Utc::now()).num_seconds();
        if ttl_seconds > 0 {
            let _: () = conn.expire(&key, ttl_seconds).await?;
        }

        Ok(())
    }

    /// Load all active sessions from Redis (for cache warming on startup)
    pub async fn load_all(&self) -> Result<Vec<AgentSession>, Box<dyn std::error::Error>> {
        let Some(client) = &self.client else {
            return Ok(Vec::new()); // Test mode: no-op
        };

        let mut conn = client.get_multiplexed_async_connection().await?;

        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("agent:*")
            .query_async(&mut conn)
            .await?;

        let mut sessions = Vec::new();
        for key in keys {
            let value: Option<String> = conn.get(&key).await?;

            if let Some(json) = value {
                #[allow(clippy::collapsible_if)]
                if let Ok(session) = serde_json::from_str::<AgentSession>(&json) {
                    sessions.push(session);
                }
            }
        }

        Ok(sessions)
    }

    /// Find all sessions delegated by a specific delegator
    pub async fn find_by_delegator(
        &self,
        delegator_did: &str,
    ) -> Result<Vec<AgentSession>, Box<dyn std::error::Error>> {
        let sessions = self.load_all().await?;
        let filtered = sessions
            .into_iter()
            .filter(|s| s.delegator_did.as_deref() == Some(delegator_did))
            .collect();
        Ok(filtered)
    }

    /// Revoke an agent by setting status to Revoked
    pub async fn revoke_agent(&self, agent_did: &str) -> Result<(), Box<dyn std::error::Error>> {
        let Some(client) = &self.client else {
            return Ok(()); // Test mode: no-op
        };

        let mut conn = client.get_multiplexed_async_connection().await?;
        let key = format!("agent:{}", agent_did);

        if let Some(json) = conn.get::<_, Option<String>>(&key).await? {
            let mut session: AgentSession = serde_json::from_str(&json)?;
            session.status = AgentStatus::Revoked;
            let updated_json = serde_json::to_string(&session)?;

            let _: () = conn.set(&key, &updated_json).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl AgentPersistencePort for AgentPersistence {
    async fn set_session(&self, session: &AgentSession) -> Result<(), String> {
        AgentPersistence::set_session(self, session)
            .await
            .map_err(|e| e.to_string())
    }

    async fn get_session(&self, agent_did: &str) -> Result<Option<AgentSession>, String> {
        AgentPersistence::get_session(self, agent_did)
            .await
            .map_err(|e| e.to_string())
    }

    async fn delete_session(&self, agent_did: &str) -> Result<(), String> {
        AgentPersistence::delete_session(self, agent_did)
            .await
            .map_err(|e| e.to_string())
    }

    async fn expire(&self, agent_did: &str, expires_at: DateTime<Utc>) -> Result<(), String> {
        AgentPersistence::expire(self, agent_did, expires_at)
            .await
            .map_err(|e| e.to_string())
    }

    async fn load_all(&self) -> Result<Vec<AgentSession>, String> {
        AgentPersistence::load_all(self)
            .await
            .map_err(|e| e.to_string())
    }

    async fn find_by_delegator(&self, delegator_did: &str) -> Result<Vec<AgentSession>, String> {
        AgentPersistence::find_by_delegator(self, delegator_did)
            .await
            .map_err(|e| e.to_string())
    }

    async fn revoke_agent(&self, agent_did: &str) -> Result<(), String> {
        AgentPersistence::revoke_agent(self, agent_did)
            .await
            .map_err(|e| e.to_string())
    }
}
