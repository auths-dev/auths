#![no_main]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use auths_auth_server::adapters::InMemorySessionStore;
use auths_auth_server::domain::{AuthChallenge, AuthSession, SessionStatus};
use auths_auth_server::ports::SessionStore;
use auths_verifier::clock::ClockProvider;
use chrono::{DateTime, Duration, Utc};
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;

/// Fuzz-controlled clock: the fuzzer controls the timestamp so TTL-boundary
/// and integer-overflow conditions can be discovered.
struct ArbitraryClock {
    timestamp_secs: i64,
}

impl ClockProvider for ArbitraryClock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.timestamp_secs, 0).unwrap_or(DateTime::UNIX_EPOCH)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }

    // First byte controls thread count (2–9); next 8 bytes drive the clock.
    let n_threads = (data[0] % 8 + 2) as usize;
    let timestamp_secs = i64::from_le_bytes(data[1..9].try_into().unwrap());

    let clock = Arc::new(ArbitraryClock { timestamp_secs });
    let store = Arc::new(InMemorySessionStore::with_clock(clock.clone()));

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let now = clock.now();
    let session = AuthSession {
        challenge: AuthChallenge {
            id: Uuid::new_v4(),
            nonce: "fuzz-nonce".to_string(),
            domain: "fuzz.example".to_string(),
            created_at: now,
            expires_at: now + Duration::seconds(300),
        },
        status: SessionStatus::Pending,
    };
    let id = session.challenge.id;
    rt.block_on(store.create(session)).unwrap();

    let handles: Vec<_> = (0..n_threads)
        .map(|_| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                rt.block_on(store.update_status(
                    &id,
                    SessionStatus::Pending,
                    SessionStatus::Verified {
                        did: "did:keri:fuzz".to_string(),
                        verified_at: now,
                    },
                ))
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let success_count = results.iter().filter(|r| matches!(r, Ok(true))).count();
    assert_eq!(
        success_count, 1,
        "CAS invariant violated: {success_count} threads succeeded"
    );
});
