use super::types::{AgentSession, AgentStatus};
use auths_verifier::IdentityDID;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use uuid::Uuid;

/// Concurrent in-memory session registry for fast agent lookups (cache)
/// Source of truth is Redis; DashMap is the cache layer
#[derive(Debug, Clone)]
pub struct AgentRegistry {
    // Primary index: agent_did → AgentSession
    sessions: DashMap<IdentityDID, AgentSession>,
    // Secondary index: session_id → agent_did (for reverse lookups)
    by_session_id: DashMap<Uuid, IdentityDID>,
    // Tertiary index: delegator_did → Vec<agent_did> (for delegation tree queries)
    by_delegator: DashMap<IdentityDID, Vec<IdentityDID>>,
}

impl AgentRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            by_session_id: DashMap::new(),
            by_delegator: DashMap::new(),
        }
    }

    /// Insert a new agent session into the registry
    /// Returns previous value if agent_did already exists (overwrite case)
    pub fn insert(&self, session: AgentSession) -> Option<AgentSession> {
        let agent_did = session.agent_did.clone();
        let session_id = session.session_id;

        // Insert into by_session_id index
        self.by_session_id.insert(session_id, agent_did.clone());

        // Track delegator relationship (for cascading revocation)
        if let Some(delegator_did) = &session.delegator_did {
            self.by_delegator
                .entry(delegator_did.clone())
                .or_default()
                .push(agent_did.clone());
        }

        // Insert into primary sessions map
        self.sessions.insert(agent_did, session)
    }

    /// Get an agent session by DID without filtering
    /// Returns the session regardless of expiry or revocation status
    /// For authorization checks that need to differentiate between revoked/expired/notfound
    pub fn get_raw(&self, agent_did: &IdentityDID) -> Option<AgentSession> {
        self.sessions.get(agent_did).map(|entry| entry.clone())
    }

    /// Get an agent session by DID
    /// Returns None if not found or expired
    pub fn get(&self, agent_did: &IdentityDID, now: DateTime<Utc>) -> Option<AgentSession> {
        let session = self.get_raw(agent_did)?;

        // Check expiry and status
        if session.is_active(now) {
            Some(session)
        } else {
            None
        }
    }

    /// Get an agent session by session_id (reverse lookup)
    pub fn get_by_session_id(&self, session_id: Uuid, now: DateTime<Utc>) -> Option<AgentSession> {
        let agent_did = self.by_session_id.get(&session_id)?;
        self.get(&agent_did, now)
    }

    /// Revoke an agent (marks as Revoked, doesn't delete)
    /// Returns true if revoked, false if not found
    pub fn revoke(&self, agent_did: &IdentityDID) -> bool {
        if let Some(mut entry) = self.sessions.get_mut(agent_did) {
            entry.status = AgentStatus::Revoked;
            true
        } else {
            false
        }
    }

    /// List all non-expired active sessions
    pub fn list(&self, now: DateTime<Utc>) -> Vec<AgentSession> {
        self.sessions
            .iter()
            .filter_map(|entry| {
                let session = entry.value();
                if session.is_active(now) {
                    Some(session.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// List all agents delegated by a specific delegator (for tree traversal)
    pub fn list_by_delegator(
        &self,
        delegator_did: &IdentityDID,
        now: DateTime<Utc>,
    ) -> Vec<AgentSession> {
        let Some(agent_dids) = self.by_delegator.get(delegator_did) else {
            return Vec::new();
        };

        agent_dids
            .iter()
            .filter_map(|agent_did| self.get(agent_did, now))
            .collect()
    }

    /// Reap expired sessions (removes from all indices)
    /// Called periodically by background cleanup task
    /// Returns count of reaped sessions
    pub fn reap_expired(&self, now: DateTime<Utc>) -> usize {
        let mut count = 0;

        // Collect DIDs to remove (avoid holding locks during iteration)
        let expired_dids: Vec<IdentityDID> = self
            .sessions
            .iter()
            .filter(|entry| entry.value().is_expired(now))
            .map(|entry| entry.key().clone())
            .collect();

        // Remove from all indices
        for agent_did in expired_dids {
            // Remove from primary sessions map
            if let Some((_, session)) = self.sessions.remove(&agent_did) {
                count += 1;

                // Remove from by_session_id index
                self.by_session_id.remove(&session.session_id);

                // Remove from by_delegator index
                if let Some(delegator_did) = &session.delegator_did
                    && let Some(mut entry) = self.by_delegator.get_mut(delegator_did)
                {
                    entry.retain(|did| did != &agent_did);
                    if entry.is_empty() {
                        drop(entry);
                        self.by_delegator.remove(delegator_did);
                    }
                }
            }
        }

        count
    }

    /// Get count of active sessions (for metrics)
    pub fn len(&self, now: DateTime<Utc>) -> usize {
        self.sessions
            .iter()
            .filter(|entry| entry.value().is_active(now))
            .count()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // INVARIANT: test fixtures call Utc::now() and Uuid::new_v4()
mod tests {
    use super::*;
    use auths_verifier::Capability;

    #[test]
    fn test_insert_and_get() {
        let registry = AgentRegistry::new();
        let now = Utc::now();

        let session = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: IdentityDID::new_unchecked("did:keri:test1"),
            agent_name: "test-agent".to_string(),
            delegator_did: None,
            capabilities: vec![Capability::sign_commit()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            delegation_depth: 0,
            max_delegation_depth: 0,
        };

        registry.insert(session.clone());

        let agent_did = IdentityDID::new_unchecked("did:keri:test1");
        let retrieved = registry.get(&agent_did, now);
        assert_eq!(retrieved, Some(session));
    }

    #[test]
    fn test_get_by_session_id() {
        let registry = AgentRegistry::new();
        let now = Utc::now();
        let session_id = Uuid::new_v4();

        let session = AgentSession {
            session_id,
            agent_did: IdentityDID::new_unchecked("did:keri:test2"),
            agent_name: "test-agent".to_string(),
            delegator_did: None,
            capabilities: vec![Capability::sign_commit()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            delegation_depth: 0,
            max_delegation_depth: 0,
        };

        registry.insert(session.clone());

        let retrieved = registry.get_by_session_id(session_id, now);
        assert_eq!(retrieved, Some(session));
    }

    #[test]
    fn test_revoke() {
        let registry = AgentRegistry::new();
        let now = Utc::now();

        let session = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: IdentityDID::new_unchecked("did:keri:test3"),
            agent_name: "test-agent".to_string(),
            delegator_did: None,
            capabilities: vec![Capability::sign_commit()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            delegation_depth: 0,
            max_delegation_depth: 0,
        };

        registry.insert(session);
        let agent_did = IdentityDID::new_unchecked("did:keri:test3");
        assert!(registry.revoke(&agent_did));
        assert!(registry.get(&agent_did, now).is_none());
    }

    #[test]
    fn test_reap_expired() {
        let registry = AgentRegistry::new();
        let now = Utc::now();

        let expired_session = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: IdentityDID::new_unchecked("did:keri:expired"),
            agent_name: "expired-agent".to_string(),
            delegator_did: None,
            capabilities: vec![Capability::sign_commit()],
            status: AgentStatus::Active,
            created_at: now - chrono::Duration::hours(2),
            expires_at: now - chrono::Duration::seconds(1),
            delegation_depth: 0,
            max_delegation_depth: 0,
        };

        let active_session = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: IdentityDID::new_unchecked("did:keri:active"),
            agent_name: "active-agent".to_string(),
            delegator_did: None,
            capabilities: vec![Capability::sign_commit()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            delegation_depth: 0,
            max_delegation_depth: 0,
        };

        registry.insert(expired_session);
        registry.insert(active_session);

        let reaped = registry.reap_expired(now);
        assert_eq!(reaped, 1);
        assert_eq!(registry.len(now), 1);
    }

    #[test]
    fn test_list_by_delegator() {
        let registry = AgentRegistry::new();
        let now = Utc::now();
        let delegator_did = IdentityDID::new_unchecked("did:keri:delegator");

        let child1 = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: IdentityDID::new_unchecked("did:keri:child1"),
            agent_name: "child1".to_string(),
            delegator_did: Some(delegator_did.clone()),
            capabilities: vec![Capability::sign_commit()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            delegation_depth: 1,
            max_delegation_depth: 0,
        };

        let child2 = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: IdentityDID::new_unchecked("did:keri:child2"),
            agent_name: "child2".to_string(),
            delegator_did: Some(delegator_did.clone()),
            capabilities: vec![Capability::sign_release()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            delegation_depth: 1,
            max_delegation_depth: 0,
        };

        registry.insert(child1);
        registry.insert(child2);

        let children = registry.list_by_delegator(&delegator_did, now);
        assert_eq!(children.len(), 2);
    }
}
