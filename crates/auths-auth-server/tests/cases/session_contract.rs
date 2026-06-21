use auths_auth_server::adapters::InMemorySessionStore;
use auths_auth_server::domain::{AuthChallenge, AuthSession, SessionStatus};
use auths_auth_server::ports::SessionStore;
use chrono::{Duration, Utc};
use uuid::Uuid;

#[allow(clippy::disallowed_methods)]
fn make_pending_session() -> AuthSession {
    let now = Utc::now();
    AuthSession {
        challenge: AuthChallenge {
            id: Uuid::new_v4(),
            nonce: "abc123".to_string(),
            domain: "test.example.com".to_string(),
            created_at: now,
            expires_at: now + Duration::seconds(300),
        },
        status: SessionStatus::Pending,
    }
}

#[allow(clippy::disallowed_methods)]
fn make_expired_session() -> AuthSession {
    let now = Utc::now();
    AuthSession {
        challenge: AuthChallenge {
            id: Uuid::new_v4(),
            nonce: "expired456".to_string(),
            domain: "test.example.com".to_string(),
            created_at: now - Duration::seconds(600),
            expires_at: now - Duration::seconds(300),
        },
        status: SessionStatus::Pending,
    }
}

mod in_memory {
    use super::*;

    #[tokio::test]
    async fn contract_create_and_get() {
        let store = InMemorySessionStore::new();
        let session = make_pending_session();
        let id = session.challenge.id;
        store.create(session).await.unwrap();
        let retrieved = store.get(&id).await.unwrap();
        assert!(retrieved.is_some(), "session should exist after create");
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn contract_get_nonexistent_returns_none() {
        let store = InMemorySessionStore::new();
        let id = Uuid::new_v4();
        let result = store.get(&id).await.unwrap();
        assert!(result.is_none(), "missing session should return None");
    }

    #[tokio::test]
    async fn contract_update_status_cas_semantics() {
        let store = InMemorySessionStore::new();
        let session = make_pending_session();
        let id = session.challenge.id;
        store.create(session).await.unwrap();

        // Correct from-status: should succeed
        let updated = store
            .update_status(
                &id,
                SessionStatus::Pending,
                SessionStatus::Verified {
                    did: "did:keri:test".to_string(),
                    verified_at: Utc::now(),
                },
            )
            .await
            .unwrap();
        assert!(
            updated,
            "update with correct from-status should return true"
        );

        // Wrong from-status (already Verified): should be a no-op
        let not_updated = store
            .update_status(&id, SessionStatus::Pending, SessionStatus::Expired)
            .await
            .unwrap();
        assert!(
            !not_updated,
            "update with wrong from-status should return false"
        );
    }

    #[tokio::test]
    async fn contract_delete_removes_session() {
        let store = InMemorySessionStore::new();
        let session = make_pending_session();
        let id = session.challenge.id;
        store.create(session).await.unwrap();
        store.delete(&id).await.unwrap();
        let result = store.get(&id).await.unwrap();
        assert!(result.is_none(), "session should be gone after delete");
    }

    #[tokio::test]
    async fn contract_list_active_excludes_non_active() {
        let store = InMemorySessionStore::new();
        let pending = make_pending_session();
        let expired = make_expired_session();
        store.create(pending).await.unwrap();
        store.create(expired).await.unwrap();
        let active = store.list_active(100).await.unwrap();
        assert_eq!(
            active.len(),
            1,
            "only non-expired pending session should appear in list_active"
        );
    }

    #[tokio::test]
    async fn contract_cleanup_expired_returns_count() {
        let store = InMemorySessionStore::new();
        let pending = make_pending_session();
        let expired = make_expired_session();
        store.create(pending).await.unwrap();
        store.create(expired).await.unwrap();
        let removed = store.cleanup_expired().await.unwrap();
        assert_eq!(removed, 1, "exactly one expired session should be removed");
        let active = store.list_active(100).await.unwrap();
        assert_eq!(
            active.len(),
            1,
            "pending session should remain after cleanup"
        );
    }
}
