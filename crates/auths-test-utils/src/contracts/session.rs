/// Contract test suite for [`SessionStore`] implementations.
///
/// Generates a module with `#[tokio::test]` cases that verify behavioural
/// correctness for any [`SessionStore`] implementation.
///
/// Args:
/// * `$name` — identifier for the generated module (e.g. `in_memory`).
/// * `$setup` — expression evaluated fresh inside each test; must return
///   an owned `SessionStore` implementation.
/// * `$make_pending_session` — expression returning an `AuthSession` with
///   `status: SessionStatus::Pending` and `challenge.expires_at` in the future.
/// * `$make_expired_session` — expression returning an `AuthSession` with
///   `challenge.expires_at` in the past.
///
/// Usage:
/// ```ignore
/// use auths_test_utils::session_store_contract_tests;
///
/// session_store_contract_tests!(
///     in_memory,
///     InMemorySessionStore::new(),
///     make_pending_session(),
///     make_expired_session(),
/// );
/// ```
#[macro_export]
macro_rules! session_store_contract_tests {
    ($name:ident, $setup:expr, $make_pending_session:expr, $make_expired_session:expr $(,)?) => {
        mod $name {
            use super::*;

            #[tokio::test]
            async fn contract_create_and_get() {
                let store = $setup;
                let session = $make_pending_session;
                let id = session.challenge.id;
                store.create(session).await.unwrap();
                let retrieved = store.get(&id).await.unwrap();
                assert!(retrieved.is_some(), "session should exist after create");
            }

            #[tokio::test]
            #[allow(clippy::disallowed_methods)]
            async fn contract_get_nonexistent_returns_none() {
                let store = $setup;
                let id = uuid::Uuid::new_v4();
                let result = store.get(&id).await.unwrap();
                assert!(result.is_none(), "missing session should return None");
            }

            #[tokio::test]
            async fn contract_update_status_cas_semantics() {
                use auths_auth_server::domain::SessionStatus;

                let store = $setup;
                let session = $make_pending_session;
                let id = session.challenge.id;
                store.create(session).await.unwrap();

                // Correct from-status: should succeed
                let updated = store
                    .update_status(
                        &id,
                        SessionStatus::Pending,
                        SessionStatus::Verified {
                            did: "did:keri:test".to_string(),
                            verified_at: chrono::Utc::now(),
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
                let store = $setup;
                let session = $make_pending_session;
                let id = session.challenge.id;
                store.create(session).await.unwrap();
                store.delete(&id).await.unwrap();
                let result = store.get(&id).await.unwrap();
                assert!(result.is_none(), "session should be gone after delete");
            }

            #[tokio::test]
            async fn contract_list_active_excludes_non_active() {
                let store = $setup;
                let pending = $make_pending_session;
                let expired = $make_expired_session;
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
                let store = $setup;
                let pending = $make_pending_session;
                let expired = $make_expired_session;
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
    };
}
