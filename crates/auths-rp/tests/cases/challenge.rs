use std::sync::Arc;

use auths_rp::{
    Audience, ChallengeError, ChallengeStore, DEFAULT_CHALLENGE_TTL_SECS, InMemoryChallengeStore,
    NONCE_LEN, Nonce,
};
use chrono::{DateTime, Duration, Utc};

fn aud() -> Audience {
    Audience::parse("api.example.com").unwrap()
}

fn other_aud() -> Audience {
    Audience::parse("evil.example.com").unwrap()
}

fn t0() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

#[test]
fn issue_then_consume_returns_matching_nonce_and_empties_store() {
    let store = InMemoryChallengeStore::new(16);
    let issued = store.issue(&aud(), t0()).unwrap();
    assert_eq!(store.live_count(), 1);

    let expected = store.consume(&aud(), &issued.nonce, t0()).unwrap();
    assert_eq!(expected.as_bytes(), issued.nonce.as_bytes());
    assert_eq!(expected.nonce(), issued.nonce);
    assert_eq!(store.live_count(), 0);
}

#[test]
fn replayed_nonce_second_consume_is_not_live() {
    let store = InMemoryChallengeStore::new(16);
    let issued = store.issue(&aud(), t0()).unwrap();
    store.consume(&aud(), &issued.nonce, t0()).unwrap();
    assert!(matches!(
        store.consume(&aud(), &issued.nonce, t0()),
        Err(ChallengeError::NotLive)
    ));
}

#[test]
fn never_issued_nonce_is_not_live() {
    let store = InMemoryChallengeStore::new(16);
    let forged = Nonce::from_bytes([0xFF; NONCE_LEN]);
    assert!(matches!(
        store.consume(&aud(), &forged, t0()),
        Err(ChallengeError::NotLive)
    ));
}

#[test]
fn consume_exactly_at_not_after_is_rejected() {
    let store = InMemoryChallengeStore::with_ttl(16, Duration::seconds(60));
    let issued = store.issue(&aud(), t0()).unwrap();
    assert_eq!(issued.not_after, t0() + Duration::seconds(60));
    assert!(matches!(
        store.consume(&aud(), &issued.nonce, issued.not_after),
        Err(ChallengeError::NotLive)
    ));
}

#[test]
fn consume_one_millisecond_before_not_after_succeeds() {
    let store = InMemoryChallengeStore::with_ttl(16, Duration::seconds(60));
    let issued = store.issue(&aud(), t0()).unwrap();
    let just_before = issued.not_after - Duration::milliseconds(1);
    assert!(store.consume(&aud(), &issued.nonce, just_before).is_ok());
}

#[test]
fn expired_consume_removes_the_entry() {
    let store = InMemoryChallengeStore::with_ttl(16, Duration::seconds(60));
    let issued = store.issue(&aud(), t0()).unwrap();
    let late = t0() + Duration::seconds(61);
    assert!(matches!(
        store.consume(&aud(), &issued.nonce, late),
        Err(ChallengeError::NotLive)
    ));
    assert_eq!(store.live_count(), 0);
}

#[test]
fn challenge_issued_for_audience_a_not_consumable_for_audience_b() {
    let store = InMemoryChallengeStore::new(16);
    let issued = store.issue(&aud(), t0()).unwrap();
    assert!(matches!(
        store.consume(&other_aud(), &issued.nonce, t0()),
        Err(ChallengeError::NotLive)
    ));
}

#[test]
fn wrong_audience_consume_does_not_burn_the_real_audience_nonce() {
    let store = InMemoryChallengeStore::new(16);
    let issued = store.issue(&aud(), t0()).unwrap();
    let _ = store.consume(&other_aud(), &issued.nonce, t0());
    assert_eq!(store.live_count(), 1);
    assert!(store.consume(&aud(), &issued.nonce, t0()).is_ok());
}

#[test]
fn same_audience_string_consumes_across_audience_instances() {
    let store = InMemoryChallengeStore::new(16);
    let issued = store.issue(&aud(), t0()).unwrap();
    let same_audience_reparsed = Audience::parse("api.example.com").unwrap();
    assert!(
        store
            .consume(&same_audience_reparsed, &issued.nonce, t0())
            .is_ok()
    );
}

#[test]
fn issue_at_max_live_returns_store_full() {
    let store = InMemoryChallengeStore::with_ttl(2, Duration::seconds(60));
    store.issue(&aud(), t0()).unwrap();
    store.issue(&aud(), t0()).unwrap();
    assert!(matches!(
        store.issue(&aud(), t0()),
        Err(ChallengeError::StoreFull)
    ));
    assert_eq!(store.live_count(), 2);
}

#[test]
fn store_full_applies_across_audiences() {
    let store = InMemoryChallengeStore::with_ttl(1, Duration::seconds(60));
    store.issue(&aud(), t0()).unwrap();
    assert!(matches!(
        store.issue(&other_aud(), t0()),
        Err(ChallengeError::StoreFull)
    ));
}

#[test]
fn issue_after_ttl_prunes_expired_entries_and_frees_capacity() {
    let store = InMemoryChallengeStore::with_ttl(2, Duration::seconds(60));
    store.issue(&aud(), t0()).unwrap();
    store.issue(&aud(), t0()).unwrap();
    assert!(matches!(
        store.issue(&aud(), t0()),
        Err(ChallengeError::StoreFull)
    ));

    let after_ttl = t0() + Duration::seconds(61);
    assert!(store.issue(&aud(), after_ttl).is_ok());
    assert_eq!(store.live_count(), 1);
}

#[test]
fn issue_exactly_at_expiry_instant_prunes_the_expired_entry() {
    let store = InMemoryChallengeStore::with_ttl(1, Duration::seconds(60));
    let issued = store.issue(&aud(), t0()).unwrap();
    assert!(store.issue(&aud(), issued.not_after).is_ok());
    assert_eq!(store.live_count(), 1);
}

#[test]
fn consume_after_capacity_freeing_still_rejects_the_pruned_nonce() {
    let store = InMemoryChallengeStore::with_ttl(1, Duration::seconds(60));
    let stale = store.issue(&aud(), t0()).unwrap();
    let after_ttl = t0() + Duration::seconds(61);
    let fresh = store.issue(&aud(), after_ttl).unwrap();

    assert!(matches!(
        store.consume(&aud(), &stale.nonce, after_ttl),
        Err(ChallengeError::NotLive)
    ));
    assert!(store.consume(&aud(), &fresh.nonce, after_ttl).is_ok());
}

#[test]
fn issued_not_after_uses_configured_ttl() {
    let store = InMemoryChallengeStore::new(16);
    let issued = store.issue(&aud(), t0()).unwrap();
    assert_eq!(
        issued.not_after,
        t0() + Duration::seconds(DEFAULT_CHALLENGE_TTL_SECS)
    );
    assert_eq!(issued.audience, aud());
}

#[test]
fn nonces_are_unique_across_issues() {
    let store = InMemoryChallengeStore::new(64);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..32 {
        let issued = store.issue(&aud(), t0()).unwrap();
        assert!(seen.insert(issued.nonce.as_bytes().to_vec()));
    }
}

#[test]
fn store_is_usable_as_trait_object_behind_arc() {
    let store: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new(16));
    let issued = store.issue(&aud(), t0()).unwrap();
    assert_eq!(store.live_count(), 1);
    assert!(store.consume(&aud(), &issued.nonce, t0()).is_ok());
    assert_eq!(store.live_count(), 0);
}

#[test]
fn zero_capacity_store_rejects_every_issue() {
    let store = InMemoryChallengeStore::new(0);
    assert!(matches!(
        store.issue(&aud(), t0()),
        Err(ChallengeError::StoreFull)
    ));
}
