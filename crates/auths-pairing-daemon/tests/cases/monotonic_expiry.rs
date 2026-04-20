//! Session-expiry enforcement via `tokio::time::Instant`.

use std::sync::Arc;
use std::time::Duration;

use auths_core::pairing::types::{Base64UrlEncoded, CreateSessionRequest};
use auths_pairing_daemon::DaemonState;

fn session() -> CreateSessionRequest {
    CreateSessionRequest {
        session_id: "s".into(),
        controller_did: "did:keri:x".into(),
        ephemeral_pubkey: Base64UrlEncoded::from_raw("A".into()),
        short_code: "ABC123".into(),
        capabilities: vec![],
        expires_at: 9999999999,
    }
}

#[tokio::test(start_paused = true)]
async fn session_becomes_expired_after_ttl() {
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let state = Arc::new(DaemonState::new_with_ttl(
        session(),
        b"tok".to_vec(),
        tx,
        Duration::from_secs(300),
    ));

    assert!(!state.is_expired(tokio::time::Instant::now()));
    tokio::time::advance(Duration::from_secs(299)).await;
    assert!(!state.is_expired(tokio::time::Instant::now()));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(state.is_expired(tokio::time::Instant::now()));
}

#[tokio::test(start_paused = true)]
async fn fresh_session_is_not_expired() {
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let state = Arc::new(DaemonState::new_with_ttl(
        session(),
        b"tok".to_vec(),
        tx,
        Duration::from_secs(60),
    ));
    assert!(!state.is_expired(tokio::time::Instant::now()));
    // Barely-fresh: 1 second in, still OK.
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(!state.is_expired(tokio::time::Instant::now()));
}
