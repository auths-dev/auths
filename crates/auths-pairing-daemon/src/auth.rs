//! Hybrid authentication — HMAC over short-code for the lookup
//! bootstrap endpoint, Ed25519 / P-256 device signatures for every
//! other session-scoped endpoint.
//!
//! # Why two schemes
//!
//! - On `/lookup`, the phone holds ONLY the 6-character short code —
//!   no `session_id`, no long-term key. The strongest authenticator
//!   available is an HMAC keyed by that short code.
//! - Once the phone has the `session_id` (via the lookup response, or
//!   via a QR scan that skips lookup entirely), every subsequent call
//!   authenticates with a device signature over a canonical request
//!   string. Signatures beat bearer tokens on every dimension that
//!   matters: no URL leakage, no header-log leakage, replay blocked
//!   by nonce, forged-traffic blocked by pubkey binding.
//!
//! # Canonical signing input
//!
//! Both schemes sign the same canonical string. Rewriting methods or
//! paths to collide is much harder than inventing two different
//! formats.
//!
//! ```text
//! <context>\n<method>\n<path>\n<sha256-hex(body)>\n<ts>\n<nonce>
//! ```
//!
//! `<context>` is [`DAEMON_HMAC_INFO`] for HMAC or [`DAEMON_SIG_CONTEXT`]
//! for signatures. Including the context byte string in the signed
//! input is belt-and-suspenders atop HKDF domain separation — it
//! makes it visible in a request log what the signature was over.
//!
//! # Replay window
//!
//! `ts` is wall-clock unix seconds. Rejection if `|ts - now| > 30s`.
//! The 30-second ceiling accommodates legitimate clock skew while
//! keeping a capture-and-replay attacker's window small.
//!
//! The nonce cache is a simple bounded `HashMap` with TTL eviction on
//! insert. Collisions inside the window return [`AuthError::ReplayedNonce`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use ring::hmac;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::domain_separation::{DAEMON_HMAC_INFO, DAEMON_SIG_CONTEXT};

/// Maximum allowed wall-clock skew between client `ts` and server
/// `now()` before a request is rejected as too old or too far future.
const MAX_TS_SKEW_SECS: i64 = 30;

/// Capacity of the nonce cache. Cheap to keep generous since each
/// entry is ~64 bytes; 4096 × 64 B = 256 KiB.
const NONCE_CACHE_CAPACITY: usize = 4096;

/// Entries this old are evicted on the next insert regardless of
/// cache capacity.
const NONCE_TTL: Duration = Duration::from_secs(90);

/// The top-level auth error type. Maps to `DaemonError` variants at
/// the handler boundary.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("missing Authorization header")]
    MissingHeader,
    #[error("malformed Authorization header")]
    MalformedHeader,
    #[error("unknown scheme")]
    UnknownScheme,
    #[error("bad kid")]
    BadKid,
    #[error("timestamp skew out of bounds")]
    TimestampSkew,
    #[error("signature mismatch")]
    BadSignature,
    #[error("nonce replayed")]
    ReplayedNonce,
    #[error("pubkey binding mismatch")]
    KeyBindingMismatch,
}

/// Parsed shape of an Authorization header value matching either
/// `Auths-HMAC …` or `Auths-Sig …`.
#[derive(Debug, Clone)]
pub struct ParsedAuth {
    pub scheme: AuthScheme,
    pub kid: Vec<u8>,
    pub ts: i64,
    pub nonce: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    Hmac,
    Sig,
}

/// Parse `Authorization: Auths-HMAC kid=…,ts=…,nonce=…,sig=…` or
/// `Authorization: Auths-Sig …` (same parameters).
pub fn parse_authorization(header: &str) -> Result<ParsedAuth, AuthError> {
    let (scheme_str, rest) = header
        .split_once(char::is_whitespace)
        .ok_or(AuthError::MalformedHeader)?;
    let scheme = match scheme_str.trim() {
        "Auths-HMAC" => AuthScheme::Hmac,
        "Auths-Sig" => AuthScheme::Sig,
        _ => return Err(AuthError::UnknownScheme),
    };

    let mut kid = None;
    let mut ts = None;
    let mut nonce = None;
    let mut sig = None;
    for part in rest.split(',') {
        let (k, v) = part.split_once('=').ok_or(AuthError::MalformedHeader)?;
        let v = v.trim();
        match k.trim() {
            "kid" => kid = Some(b64_decode(v)?),
            "ts" => ts = Some(v.parse::<i64>().map_err(|_| AuthError::MalformedHeader)?),
            "nonce" => nonce = Some(b64_decode(v)?),
            "sig" => sig = Some(b64_decode(v)?),
            _ => {}
        }
    }

    Ok(ParsedAuth {
        scheme,
        kid: kid.ok_or(AuthError::MalformedHeader)?,
        ts: ts.ok_or(AuthError::MalformedHeader)?,
        nonce: nonce.ok_or(AuthError::MalformedHeader)?,
        sig: sig.ok_or(AuthError::MalformedHeader)?,
    })
}

fn b64_decode(s: &str) -> Result<Vec<u8>, AuthError> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| AuthError::MalformedHeader)
}

/// Build the canonical signing input for a request.
pub fn canonical_string(
    context: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    ts: i64,
    nonce: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash = hasher.finalize();
    let body_hash_hex = hex::encode(body_hash);
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);

    let mut out = Vec::with_capacity(context.len() + method.len() + path.len() + 200);
    out.extend_from_slice(context);
    out.push(b'\n');
    out.extend_from_slice(method.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(body_hash_hex.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(ts.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(nonce_b64.as_bytes());
    out
}

/// Derive the 32-byte HMAC key from the pairing short code.
pub fn derive_hmac_key(short_code: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, short_code.as_bytes());
    let mut key = [0u8; 32];
    let _ = hk.expand(DAEMON_HMAC_INFO, &mut key);
    key
}

/// First 16 bytes of `SHA-256(short_code_bytes)` — the kid used on the
/// `Auths-HMAC` scheme.
pub fn derive_hmac_kid(short_code: &str) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(short_code.as_bytes());
    let full = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Verify an `Auths-HMAC` Authorization header for a request.
///
/// Caller supplies the server-side short code (from `DaemonState`).
/// The kid in the header is compared constant-time against the
/// expected kid derived from that short code; mismatch → `BadKid`
/// (404-shaped — enumeration attacker cannot distinguish "no session"
/// from "wrong short code").
pub fn verify_hmac(
    parsed: &ParsedAuth,
    method: &str,
    path: &str,
    body: &[u8],
    short_code: &str,
    now_unix: i64,
) -> Result<(), AuthError> {
    if parsed.scheme != AuthScheme::Hmac {
        return Err(AuthError::UnknownScheme);
    }
    check_skew(parsed.ts, now_unix)?;
    let expected_kid = derive_hmac_kid(short_code);
    if !bool::from(parsed.kid.as_slice().ct_eq(&expected_kid)) {
        return Err(AuthError::BadKid);
    }
    let key = derive_hmac_key(short_code);
    let canonical = canonical_string(
        DAEMON_HMAC_INFO,
        method,
        path,
        body,
        parsed.ts,
        &parsed.nonce,
    );
    let ring_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
    let expected_sig = hmac::sign(&ring_key, &canonical);
    if !bool::from(parsed.sig.as_slice().ct_eq(expected_sig.as_ref())) {
        return Err(AuthError::BadSignature);
    }
    Ok(())
}

/// Verify an `Auths-Sig` Authorization header for a request against
/// the session's bound pubkey (curve-tagged).
pub fn verify_sig(
    parsed: &ParsedAuth,
    method: &str,
    path: &str,
    body: &[u8],
    bound_pubkey: &auths_keri::KeriPublicKey,
    now_unix: i64,
) -> Result<(), AuthError> {
    if parsed.scheme != AuthScheme::Sig {
        return Err(AuthError::UnknownScheme);
    }
    check_skew(parsed.ts, now_unix)?;
    let expected_kid = pubkey_kid(bound_pubkey);
    if !bool::from(parsed.kid.as_slice().ct_eq(&expected_kid)) {
        return Err(AuthError::BadKid);
    }
    let canonical = canonical_string(
        DAEMON_SIG_CONTEXT,
        method,
        path,
        body,
        parsed.ts,
        &parsed.nonce,
    );
    bound_pubkey
        .verify_signature(&canonical, &parsed.sig)
        .map_err(|_| AuthError::BadSignature)
}

/// kid derivation for a `KeriPublicKey` — first 16 bytes of
/// `SHA-256(compressed_pubkey_bytes)`.
pub fn pubkey_kid(pk: &auths_keri::KeriPublicKey) -> [u8; 16] {
    let mut h = Sha256::new();
    match pk {
        auths_keri::KeriPublicKey::Ed25519(arr) => h.update(arr),
        auths_keri::KeriPublicKey::P256(arr) => h.update(arr),
    }
    let full = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

fn check_skew(ts: i64, now: i64) -> Result<(), AuthError> {
    if (ts - now).abs() > MAX_TS_SKEW_SECS {
        Err(AuthError::TimestampSkew)
    } else {
        Ok(())
    }
}

/// Bounded nonce replay cache, keyed by `(kid, nonce)`.
pub struct NonceCache {
    entries: Mutex<HashMap<(Vec<u8>, Vec<u8>), Instant>>,
    capacity: usize,
    ttl: Duration,
}

impl NonceCache {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity: NONCE_CACHE_CAPACITY,
            ttl: NONCE_TTL,
        }
    }

    /// Try to insert a `(kid, nonce)` tuple. Returns `Ok` on first
    /// sighting, `Err(ReplayedNonce)` if already present and within
    /// the TTL. Evicts expired entries on insert.
    pub fn check_and_insert(&self, kid: &[u8], nonce: &[u8]) -> Result<(), AuthError> {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Evict expired entries; also cap total size at capacity.
        guard.retain(|_, inserted| now.duration_since(*inserted) < self.ttl);
        if guard.len() >= self.capacity {
            // Drop the oldest entry to make room. HashMap doesn't
            // order insertions, so this is approximate — fine given
            // we only reach capacity under active flood.
            if let Some(oldest) = guard.iter().min_by_key(|(_, t)| *t).map(|(k, _)| k.clone()) {
                guard.remove(&oldest);
            }
        }

        let key = (kid.to_vec(), nonce.to_vec());
        if guard.contains_key(&key) {
            return Err(AuthError::ReplayedNonce);
        }
        guard.insert(key, now);
        Ok(())
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Pubkey binding: the session records the first pubkey that
/// successfully authenticated. Subsequent requests MUST match that
/// pubkey exactly.
#[derive(Default)]
pub struct PubkeyBinding {
    bound: Mutex<Option<auths_keri::KeriPublicKey>>,
}

impl PubkeyBinding {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind this pubkey to the session if none is bound, or confirm
    /// it matches the already-bound key. Returns `KeyBindingMismatch`
    /// if it differs.
    pub fn bind_or_match(&self, pk: &auths_keri::KeriPublicKey) -> Result<(), AuthError> {
        let mut guard = self.bound.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            None => {
                *guard = Some(pk.clone());
                Ok(())
            }
            Some(existing) => {
                if keri_pubkeys_equal(existing, pk) {
                    Ok(())
                } else {
                    Err(AuthError::KeyBindingMismatch)
                }
            }
        }
    }

    /// Returns the currently-bound pubkey, if any.
    pub fn current(&self) -> Option<auths_keri::KeriPublicKey> {
        self.bound.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

fn keri_pubkeys_equal(a: &auths_keri::KeriPublicKey, b: &auths_keri::KeriPublicKey) -> bool {
    match (a, b) {
        (auths_keri::KeriPublicKey::Ed25519(x), auths_keri::KeriPublicKey::Ed25519(y)) => {
            bool::from(x[..].ct_eq(&y[..]))
        }
        (auths_keri::KeriPublicKey::P256(x), auths_keri::KeriPublicKey::P256(y)) => {
            bool::from(x[..].ct_eq(&y[..]))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_authorization_happy_path() {
        let auth =
            parse_authorization("Auths-HMAC kid=AAAA,ts=1700000000,nonce=BBBB,sig=CCCC").unwrap();
        assert_eq!(auth.scheme, AuthScheme::Hmac);
        assert_eq!(auth.kid, b64_decode("AAAA").unwrap());
        assert_eq!(auth.ts, 1700000000);
        assert_eq!(auth.nonce, b64_decode("BBBB").unwrap());
        assert_eq!(auth.sig, b64_decode("CCCC").unwrap());
    }

    #[test]
    fn parse_authorization_sig_scheme() {
        let auth = parse_authorization("Auths-Sig kid=AAAA,ts=1,nonce=BBBB,sig=CCCC").unwrap();
        assert_eq!(auth.scheme, AuthScheme::Sig);
    }

    #[test]
    fn parse_authorization_rejects_unknown_scheme() {
        let r = parse_authorization("Bearer abc");
        assert!(matches!(r, Err(AuthError::UnknownScheme)));
    }

    #[test]
    fn hmac_round_trip() {
        let short_code = "ABC123";
        let kid = derive_hmac_kid(short_code);
        let key = derive_hmac_key(short_code);
        let ts = 1_700_000_000;
        let nonce = b"random-nonce-16b";
        let body = b"{}";
        let canonical = canonical_string(
            DAEMON_HMAC_INFO,
            "GET",
            "/v1/pairing/sessions/lookup",
            body,
            ts,
            nonce,
        );
        let ring_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
        let tag = hmac::sign(&ring_key, &canonical);

        let parsed = ParsedAuth {
            scheme: AuthScheme::Hmac,
            kid: kid.to_vec(),
            ts,
            nonce: nonce.to_vec(),
            sig: tag.as_ref().to_vec(),
        };

        verify_hmac(
            &parsed,
            "GET",
            "/v1/pairing/sessions/lookup",
            body,
            short_code,
            ts,
        )
        .expect("round-trip must verify");
    }

    #[test]
    fn hmac_wrong_short_code_rejected() {
        let mut parsed = ParsedAuth {
            scheme: AuthScheme::Hmac,
            kid: derive_hmac_kid("ABC123").to_vec(),
            ts: 1,
            nonce: vec![0; 16],
            sig: vec![0; 32],
        };
        // Matching short code now: kid and sig both belong to "ABC123".
        let r = verify_hmac(&parsed, "GET", "/x", b"", "DIFFERENT", 1);
        assert!(matches!(r, Err(AuthError::BadKid)));

        // Bad kid even with matching short code.
        parsed.kid = vec![0; 16];
        let r = verify_hmac(&parsed, "GET", "/x", b"", "ABC123", 1);
        assert!(matches!(r, Err(AuthError::BadKid)));
    }

    #[test]
    fn hmac_ts_skew_rejected() {
        let short_code = "ABC123";
        let parsed = ParsedAuth {
            scheme: AuthScheme::Hmac,
            kid: derive_hmac_kid(short_code).to_vec(),
            ts: 1_700_000_000,
            nonce: vec![0; 16],
            sig: vec![0; 32],
        };
        // Server clock is 90s ahead — exceeds the 30s window.
        let r = verify_hmac(&parsed, "GET", "/x", b"", short_code, 1_700_000_090);
        assert!(matches!(r, Err(AuthError::TimestampSkew)));
    }

    #[test]
    fn nonce_cache_detects_replay() {
        let cache = NonceCache::new();
        let kid = b"kid1";
        let nonce = b"nonce1";
        cache.check_and_insert(kid, nonce).unwrap();
        let r = cache.check_and_insert(kid, nonce);
        assert!(matches!(r, Err(AuthError::ReplayedNonce)));
    }

    #[test]
    fn nonce_cache_different_nonces_ok() {
        let cache = NonceCache::new();
        cache.check_and_insert(b"kid", b"n1").unwrap();
        cache.check_and_insert(b"kid", b"n2").unwrap();
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn nonce_cache_different_kids_ok() {
        let cache = NonceCache::new();
        cache.check_and_insert(b"kidA", b"nonce").unwrap();
        cache.check_and_insert(b"kidB", b"nonce").unwrap();
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn pubkey_binding_first_sighting_binds() {
        let b = PubkeyBinding::new();
        let pk = auths_keri::KeriPublicKey::Ed25519([0x11; 32]);
        assert!(b.bind_or_match(&pk).is_ok());
        // Same key again → OK.
        assert!(b.bind_or_match(&pk).is_ok());
    }

    #[test]
    fn pubkey_binding_divergent_key_rejected() {
        let b = PubkeyBinding::new();
        let pk1 = auths_keri::KeriPublicKey::Ed25519([0x11; 32]);
        let pk2 = auths_keri::KeriPublicKey::Ed25519([0x22; 32]);
        b.bind_or_match(&pk1).unwrap();
        let r = b.bind_or_match(&pk2);
        assert!(matches!(r, Err(AuthError::KeyBindingMismatch)));
    }

    #[test]
    fn pubkey_binding_different_curve_rejected() {
        let b = PubkeyBinding::new();
        let pk_ed = auths_keri::KeriPublicKey::Ed25519([0x11; 32]);
        let pk_p256 = auths_keri::KeriPublicKey::P256([0x11; 33]);
        b.bind_or_match(&pk_ed).unwrap();
        let r = b.bind_or_match(&pk_p256);
        assert!(matches!(r, Err(AuthError::KeyBindingMismatch)));
    }
}
