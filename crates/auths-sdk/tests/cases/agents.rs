use std::sync::Arc;

use auths_sdk::domains::agents::registry::AgentRegistry;
use auths_sdk::domains::agents::service::AgentService;
use auths_sdk::domains::agents::types::{AgentSession, AgentStatus, ProvisionRequest};
use auths_sdk::testing::fakes::FakeAgentPersistence;
use chrono::Utc;
use uuid::Uuid;

fn make_service() -> AgentService {
    let registry = Arc::new(AgentRegistry::new());
    let persistence = Arc::new(FakeAgentPersistence::new());
    AgentService::new(registry, persistence)
}

fn make_service_with_registry(registry: Arc<AgentRegistry>) -> AgentService {
    let persistence = Arc::new(FakeAgentPersistence::new());
    AgentService::new(registry, persistence)
}

// ── provision ───────────────────────────────────────────────────────────────

#[tokio::test]
#[allow(clippy::disallowed_methods)]
async fn provision_root_agent_succeeds() {
    let service = make_service();
    let now = Utc::now();

    let req = ProvisionRequest {
        delegator_did: String::new(),
        agent_name: "test-agent".into(),
        capabilities: vec!["sign_commit".into()],
        ttl_seconds: 3600,
        max_delegation_depth: Some(1),
        signature: String::new(),
        timestamp: now,
    };

    let result = service.provision(req, now).await;
    assert!(result.is_ok(), "provision failed: {:?}", result.err());

    let resp = result.unwrap();
    assert!(resp.agent_did.starts_with("did:keri:"));
    assert!(resp.bearer_token.is_some());
    assert!(resp.expires_at > now);
}

#[tokio::test]
#[allow(clippy::disallowed_methods)]
async fn provision_rejects_large_clock_skew() {
    let service = make_service();
    let now = Utc::now();

    let req = ProvisionRequest {
        delegator_did: String::new(),
        agent_name: "test-agent".into(),
        capabilities: vec!["sign_commit".into()],
        ttl_seconds: 3600,
        max_delegation_depth: None,
        signature: String::new(),
        timestamp: now - chrono::Duration::seconds(600), // 10 min ago
    };

    let result = service.provision(req, now).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Clock skew"));
}

#[tokio::test]
#[allow(clippy::disallowed_methods)]
async fn provision_delegated_agent_fails_when_delegator_not_found() {
    let service = make_service();
    let now = Utc::now();

    let req = ProvisionRequest {
        delegator_did: "did:keri:ENotInRegistry".into(),
        agent_name: "child-agent".into(),
        capabilities: vec!["read".into()],
        ttl_seconds: 1800,
        max_delegation_depth: None,
        signature: String::new(),
        timestamp: now,
    };

    let result = service.provision(req, now).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Delegator not found"));
}

// ── authorize ───────────────────────────────────────────────────────────────

#[test]
#[allow(clippy::disallowed_methods)]
fn authorize_grants_matching_capability() {
    let registry = Arc::new(AgentRegistry::new());
    let now = Utc::now();

    let session = AgentSession {
        session_id: Uuid::new_v4(),
        agent_did: "did:keri:EAgent001".into(),
        agent_name: "test-agent".into(),
        delegator_did: None,
        capabilities: vec!["sign_commit".into(), "sign_release".into()],
        status: AgentStatus::Active,
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        delegation_depth: 0,
        max_delegation_depth: 0,
    };
    registry.insert(session);

    let service = make_service_with_registry(registry);
    let result = service.authorize("did:keri:EAgent001", "sign_commit", now, now);

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert!(resp.authorized);
    assert!(resp.matched_capabilities.contains(&"sign_commit".into()));
}

#[test]
#[allow(clippy::disallowed_methods)]
fn authorize_grants_wildcard_capability() {
    let registry = Arc::new(AgentRegistry::new());
    let now = Utc::now();

    let session = AgentSession {
        session_id: Uuid::new_v4(),
        agent_did: "did:keri:EWildcard".into(),
        agent_name: "super-agent".into(),
        delegator_did: None,
        capabilities: vec!["*".into()],
        status: AgentStatus::Active,
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        delegation_depth: 0,
        max_delegation_depth: 0,
    };
    registry.insert(session);

    let service = make_service_with_registry(registry);
    let result = service.authorize("did:keri:EWildcard", "anything_at_all", now, now);

    assert!(result.is_ok());
    assert!(result.unwrap().authorized);
}

#[test]
#[allow(clippy::disallowed_methods)]
fn authorize_denies_unmatched_capability() {
    let registry = Arc::new(AgentRegistry::new());
    let now = Utc::now();

    let session = AgentSession {
        session_id: Uuid::new_v4(),
        agent_did: "did:keri:ELimited".into(),
        agent_name: "limited-agent".into(),
        delegator_did: None,
        capabilities: vec!["sign_commit".into()],
        status: AgentStatus::Active,
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        delegation_depth: 0,
        max_delegation_depth: 0,
    };
    registry.insert(session);

    let service = make_service_with_registry(registry);
    let result = service.authorize("did:keri:ELimited", "manage_members", now, now);

    assert!(result.is_ok());
    assert!(!result.unwrap().authorized);
}

#[test]
#[allow(clippy::disallowed_methods)]
fn authorize_rejects_unknown_agent() {
    let service = make_service();
    let now = Utc::now();

    let result = service.authorize("did:keri:ENonexistent", "sign_commit", now, now);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

#[test]
#[allow(clippy::disallowed_methods)]
fn authorize_rejects_large_clock_skew() {
    let service = make_service();
    let now = Utc::now();
    let stale = now - chrono::Duration::seconds(600);

    let result = service.authorize("did:keri:EAgent001", "sign_commit", now, stale);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Clock skew"));
}

#[test]
#[allow(clippy::disallowed_methods)]
fn authorize_rejects_revoked_agent() {
    let registry = Arc::new(AgentRegistry::new());
    let now = Utc::now();

    let session = AgentSession {
        session_id: Uuid::new_v4(),
        agent_did: "did:keri:ERevoked".into(),
        agent_name: "revoked-agent".into(),
        delegator_did: None,
        capabilities: vec!["sign_commit".into()],
        status: AgentStatus::Revoked,
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        delegation_depth: 0,
        max_delegation_depth: 0,
    };
    registry.insert(session);

    let service = make_service_with_registry(registry);
    let result = service.authorize("did:keri:ERevoked", "sign_commit", now, now);

    // Revoked agents should not be found by registry.get() (which filters by is_active)
    assert!(result.is_err());
}

// ── revoke ──────────────────────────────────────────────────────────────────

#[tokio::test]
#[allow(clippy::disallowed_methods)]
async fn revoke_marks_agent_as_revoked() {
    let registry = Arc::new(AgentRegistry::new());
    let now = Utc::now();

    let session = AgentSession {
        session_id: Uuid::new_v4(),
        agent_did: "did:keri:EToRevoke".into(),
        agent_name: "doomed-agent".into(),
        delegator_did: None,
        capabilities: vec!["sign_commit".into()],
        status: AgentStatus::Active,
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        delegation_depth: 0,
        max_delegation_depth: 0,
    };
    registry.insert(session);

    let service = make_service_with_registry(registry.clone());
    let result = service.revoke("did:keri:EToRevoke", now).await;
    assert!(result.is_ok());

    // Agent should no longer be findable (revoked)
    assert!(registry.get("did:keri:EToRevoke", now).is_none());
}

#[tokio::test]
#[allow(clippy::disallowed_methods)]
async fn revoke_cascades_to_children() {
    let registry = Arc::new(AgentRegistry::new());
    let now = Utc::now();

    // Insert parent
    registry.insert(AgentSession {
        session_id: Uuid::new_v4(),
        agent_did: "did:keri:EParent".into(),
        agent_name: "parent".into(),
        delegator_did: None,
        capabilities: vec!["*".into()],
        status: AgentStatus::Active,
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        delegation_depth: 0,
        max_delegation_depth: 2,
    });

    // Insert child delegated by parent
    registry.insert(AgentSession {
        session_id: Uuid::new_v4(),
        agent_did: "did:keri:EChild".into(),
        agent_name: "child".into(),
        delegator_did: Some("did:keri:EParent".into()),
        capabilities: vec!["sign_commit".into()],
        status: AgentStatus::Active,
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        delegation_depth: 1,
        max_delegation_depth: 0,
    });

    let service = make_service_with_registry(registry.clone());
    let result = service.revoke("did:keri:EParent", now).await;
    assert!(result.is_ok());

    // Both parent and child should be revoked
    assert!(registry.get("did:keri:EParent", now).is_none());
    assert!(registry.get("did:keri:EChild", now).is_none());
}

#[tokio::test]
#[allow(clippy::disallowed_methods)]
async fn revoke_nonexistent_agent_returns_error() {
    let service = make_service();
    let now = Utc::now();

    let result = service.revoke("did:keri:EGhost", now).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}
