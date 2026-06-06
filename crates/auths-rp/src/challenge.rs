//! Single-use challenge store for the interactive presentation path (Epic D1 / fn-151.4).
//!
//! `/v1/auth/challenge` mints a fresh CSPRNG [`Nonce`] bound to an [`Audience`]; the client
//! signs over it and presents. [`ChallengeStore::consume`] is remove-on-read, so a nonce
//! verifies exactly once — genuine single-use replay protection with NO global seen-cache in
//! the verifier (the verify path stays WASM-safe; see `auths_verifier::verify_presentation`).
//!
//! The store is bounded and TTL-pruned, so a `/v1/auth/challenge` flood cannot exhaust
//! memory, and `consume` runs only after the caller's cheap structural checks so a third
//! party cannot burn a legitimate client's nonce.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use ring::rand::SecureRandom;

use crate::{Audience, NONCE_LEN, Nonce};

/// The default TTL ceiling for a minted challenge (decision 7 / fn-151.1).
pub const DEFAULT_CHALLENGE_TTL_SECS: i64 = 120;

/// Proof that a live challenge for an audience was consumed exactly now.
///
/// Produced only by [`ChallengeStore::consume`]; pass [`ExpectedNonce::as_bytes`] as
/// `auths_verifier::verify_presentation`'s `expected_challenge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedNonce(Nonce);

impl ExpectedNonce {
    /// The expected nonce bytes for the pure verifier.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The expected nonce.
    pub fn nonce(&self) -> Nonce {
        self.0
    }
}

/// A freshly minted challenge handed to the client (`/v1/auth/challenge` response).
#[derive(Debug, Clone)]
pub struct IssuedChallenge {
    /// The audience the presentation must bind to.
    pub audience: Audience,
    /// The single-use nonce the client signs over.
    pub nonce: Nonce,
    /// When the challenge expires.
    pub not_after: DateTime<Utc>,
}

/// Challenge-store errors (`thiserror`, exhaustive).
#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    /// The system CSPRNG failed to produce a nonce.
    #[error("failed to generate challenge nonce")]
    NonceGeneration,
    /// The store is at capacity (DoS bound) — try again shortly.
    #[error("challenge store at capacity")]
    StoreFull,
    /// No live challenge matched (absent, already consumed, or expired).
    #[error("no live challenge for this audience/nonce")]
    NotLive,
}

/// The map key: the audience string plus the nonce bytes.
type ChallengeKey = (String, [u8; NONCE_LEN]);

/// A bounded, single-process, TTL-pruned single-use challenge store.
#[derive(Debug)]
pub struct ChallengeStore {
    inner: Mutex<HashMap<ChallengeKey, DateTime<Utc>>>,
    max_live: usize,
    ttl: Duration,
}

impl ChallengeStore {
    /// Create a store with a capacity bound and the default TTL.
    pub fn new(max_live: usize) -> Self {
        Self::with_ttl(max_live, Duration::seconds(DEFAULT_CHALLENGE_TTL_SECS))
    }

    /// Create a store with an explicit capacity bound and TTL.
    pub fn with_ttl(max_live: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_live,
            ttl,
        }
    }

    /// Mint a fresh single-use challenge bound to `audience`.
    ///
    /// Prunes expired entries first; fails with [`ChallengeError::StoreFull`] if the live set
    /// is already at capacity, so `/v1/auth/challenge` cannot be a memory-exhaustion vector.
    ///
    /// Args:
    /// * `audience`: The relying party the presentation must bind to.
    /// * `now`: The current time, injected at the boundary.
    pub fn issue(
        &self,
        audience: &Audience,
        now: DateTime<Utc>,
    ) -> Result<IssuedChallenge, ChallengeError> {
        let mut bytes = [0u8; NONCE_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| ChallengeError::NonceGeneration)?;
        let nonce = Nonce::from_bytes(bytes);
        let not_after = now + self.ttl;

        let mut map = self.inner.lock();
        map.retain(|_, expiry| *expiry > now);
        if map.len() >= self.max_live {
            return Err(ChallengeError::StoreFull);
        }
        map.insert((audience.as_str().to_string(), bytes), not_after);
        Ok(IssuedChallenge {
            audience: audience.clone(),
            nonce,
            not_after,
        })
    }

    /// Consume a challenge once (remove-on-read).
    ///
    /// Returns the expected nonce iff a live challenge for `(audience, nonce)` exists; a second
    /// consume of the same nonce, an expired one, or an unknown one all yield
    /// [`ChallengeError::NotLive`] — the single-use replay protection.
    ///
    /// Args:
    /// * `audience`: The audience the client claims to bind to.
    /// * `nonce`: The nonce the client presented.
    /// * `now`: The current time, injected at the boundary.
    pub fn consume(
        &self,
        audience: &Audience,
        nonce: &Nonce,
        now: DateTime<Utc>,
    ) -> Result<ExpectedNonce, ChallengeError> {
        let key: ChallengeKey = (audience.as_str().to_string(), nonce_array(nonce));
        let mut map = self.inner.lock();
        match map.remove(&key) {
            Some(not_after) if not_after > now => Ok(ExpectedNonce(*nonce)),
            _ => Err(ChallengeError::NotLive),
        }
    }

    /// The number of currently-stored challenges.
    pub fn live_count(&self) -> usize {
        self.inner.lock().len()
    }
}

/// Copy a nonce into its fixed array key form.
fn nonce_array(nonce: &Nonce) -> [u8; NONCE_LEN] {
    let mut arr = [0u8; NONCE_LEN];
    arr.copy_from_slice(nonce.as_bytes());
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aud() -> Audience {
        Audience::parse("api.example.com").unwrap()
    }

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn consume_once_then_replay_rejected() {
        let store = ChallengeStore::new(16);
        let issued = store.issue(&aud(), t0()).unwrap();
        let expected = store.consume(&aud(), &issued.nonce, t0()).unwrap();
        assert_eq!(expected.as_bytes(), issued.nonce.as_bytes());
        assert!(matches!(
            store.consume(&aud(), &issued.nonce, t0()),
            Err(ChallengeError::NotLive)
        ));
    }

    #[test]
    fn wrong_audience_does_not_burn_the_nonce() {
        let store = ChallengeStore::new(16);
        let issued = store.issue(&aud(), t0()).unwrap();
        let other = Audience::parse("evil.example.com").unwrap();
        assert!(matches!(
            store.consume(&other, &issued.nonce, t0()),
            Err(ChallengeError::NotLive)
        ));
        // The real audience can still consume — a third party cannot burn it.
        assert!(store.consume(&aud(), &issued.nonce, t0()).is_ok());
    }

    #[test]
    fn expired_challenge_rejected() {
        let store = ChallengeStore::with_ttl(16, Duration::seconds(60));
        let issued = store.issue(&aud(), t0()).unwrap();
        let later = t0() + Duration::seconds(61);
        assert!(matches!(
            store.consume(&aud(), &issued.nonce, later),
            Err(ChallengeError::NotLive)
        ));
    }

    #[test]
    fn bounded_store_full_then_pruned() {
        let store = ChallengeStore::with_ttl(1, Duration::seconds(60));
        let _a = store.issue(&aud(), t0()).unwrap();
        assert!(matches!(
            store.issue(&aud(), t0()),
            Err(ChallengeError::StoreFull)
        ));
        // After the TTL, the next issue prunes the expired entry and succeeds.
        let later = t0() + Duration::seconds(61);
        assert!(store.issue(&aud(), later).is_ok());
    }

    #[test]
    fn nonces_differ_across_issues() {
        let store = ChallengeStore::new(16);
        let a = store.issue(&aud(), t0()).unwrap();
        let b = store.issue(&aud(), t0()).unwrap();
        assert_ne!(a.nonce.as_bytes(), b.nonce.as_bytes());
    }
}
