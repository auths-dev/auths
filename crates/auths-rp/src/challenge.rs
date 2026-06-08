//! Single-use challenge store for the interactive presentation path.
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

/// The single-use challenge seam: mint a nonce, then consume it exactly once.
///
/// [`InMemoryChallengeStore`] is the shipped single-process implementation. A future
/// multi-instance deployment behind a load balancer supplies its own implementation over a
/// shared backend (Redis/SQL) so a nonce minted on one node is consumable on another — see
/// the load-balancer caveat on [`InMemoryChallengeStore`]. The trait is object-safe: a
/// relying party holds an `Arc<dyn ChallengeStore>` and swaps the backend without touching
/// `authenticate_presentation` or the mint route.
///
/// Usage:
/// ```ignore
/// let store: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new(10_000));
/// let issued = store.issue(&audience, now)?;
/// let expected = store.consume(&audience, &issued.nonce, now)?;
/// ```
pub trait ChallengeStore: Send + Sync {
    /// Mint a fresh single-use challenge bound to `audience`.
    ///
    /// Implementations MUST draw the nonce from a CSPRNG and bound the live set so a
    /// `/v1/auth/challenge` flood cannot exhaust memory (returning [`ChallengeError::StoreFull`]
    /// at capacity rather than evicting a live nonce).
    ///
    /// Args:
    /// * `audience`: The relying party the presentation must bind to.
    /// * `now`: The current time, injected at the boundary.
    fn issue(
        &self,
        audience: &Audience,
        now: DateTime<Utc>,
    ) -> Result<IssuedChallenge, ChallengeError>;

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
    fn consume(
        &self,
        audience: &Audience,
        nonce: &Nonce,
        now: DateTime<Utc>,
    ) -> Result<ExpectedNonce, ChallengeError>;

    /// The number of currently-stored challenges (diagnostics / tests).
    fn live_count(&self) -> usize;
}

/// The map key: the audience string plus the nonce bytes.
type ChallengeKey = (String, [u8; NONCE_LEN]);

/// A bounded, TTL-pruned single-use challenge store — the shipped [`ChallengeStore`].
///
/// ## Load-balancer caveat (SINGLE-PROCESS ONLY)
///
/// This store lives in one process's heap. Behind a load balancer fronting N nodes, a nonce
/// minted on node A is unknown to node B: a client that mints on A then presents on B is
/// rejected as [`ChallengeError::NotLive`], and — worse for security — the remove-on-read
/// single-use guarantee holds only *per node*, so a within-TTL replay can still land on a
/// different node than the original. Single-process or sticky-session deployments are safe;
/// multi-node deployments MUST supply a shared [`ChallengeStore`] backend (the trait seam).
/// The shared backend is deferred to the cross-cutting tracking issue (see fn-153.15).
#[derive(Debug)]
pub struct InMemoryChallengeStore {
    inner: Mutex<HashMap<ChallengeKey, DateTime<Utc>>>,
    max_live: usize,
    ttl: Duration,
}

impl InMemoryChallengeStore {
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
}

impl ChallengeStore for InMemoryChallengeStore {
    fn issue(
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

    fn consume(
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

    fn live_count(&self) -> usize {
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
        let store = InMemoryChallengeStore::new(16);
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
        let store = InMemoryChallengeStore::new(16);
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
        let store = InMemoryChallengeStore::with_ttl(16, Duration::seconds(60));
        let issued = store.issue(&aud(), t0()).unwrap();
        let later = t0() + Duration::seconds(61);
        assert!(matches!(
            store.consume(&aud(), &issued.nonce, later),
            Err(ChallengeError::NotLive)
        ));
    }

    #[test]
    fn bounded_store_full_then_pruned() {
        let store = InMemoryChallengeStore::with_ttl(1, Duration::seconds(60));
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
        let store = InMemoryChallengeStore::new(16);
        let a = store.issue(&aud(), t0()).unwrap();
        let b = store.issue(&aud(), t0()).unwrap();
        assert_ne!(a.nonce.as_bytes(), b.nonce.as_bytes());
    }
}
