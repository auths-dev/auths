//! Executor-free, pure-Rust signature verification for the synchronous verifier core.
//!
//! The presentation/credential verifier is pure over its injected inputs — the only
//! reason it was ever `async` is that [`auths_crypto::CryptoProvider`] is an async
//! trait (it has to be, so a WASM build can route through the genuinely-async
//! `WebCrypto`). But `block_on` is structurally impossible in browser WASM, so every
//! non-Rust binding target needs a path that verifies **without an executor**.
//!
//! This module is that path. It dispatches on the CESR key's curve tag (never on byte
//! length) and verifies with vetted pure-Rust crates — `p256` for P-256 and
//! `ed25519-dalek` for Ed25519 — both of which compile on `wasm32` and run
//! synchronously on every target. Signature verification is deterministic and
//! backend-independent: a valid signature verifies identically whether checked by
//! `ring`, AWS-LC, or these crates, so the synchronous verdict is in exact parity with
//! the async [`CryptoProvider`]-driven path (guarded by the `*_sync` parity tests).
//!
//! It never signs and never touches a secret — it is a verification-only surface, which
//! is exactly why a pure-Rust implementation (no `ring`, no FIPS toolchain) is the right
//! fit for the embeddable verifier.

use auths_crypto::CurveType;
use auths_keri::KeriPublicKey;

/// Verify a signature against a CESR-tagged key, dispatching on the key's curve tag.
///
/// The curve is read from the parsed CESR key (`key.curve()`), never inferred from byte
/// length — preserving the load-bearing wire-format curve-tagging rule. Any malformed
/// key, signature, or curve mismatch returns `false` (fail-closed); this function never
/// panics, so it is safe to call directly from the FFI/WASM boundary.
///
/// Args:
/// * `key`: The CESR-tagged public key recovered from a replayed KEL.
/// * `message`: The exact bytes that were signed.
/// * `signature`: The detached signature to check (64 bytes for both curves).
///
/// Usage:
/// ```ignore
/// if software_verify::verify_with_key_sync(&key, &message, &signature) {
///     // signature is valid under the key's tagged curve
/// }
/// ```
pub(crate) fn verify_with_key_sync(key: &KeriPublicKey, message: &[u8], signature: &[u8]) -> bool {
    match key.curve() {
        CurveType::Ed25519 => verify_ed25519(key.as_bytes(), message, signature),
        CurveType::P256 => verify_p256(key.as_bytes(), message, signature),
    }
}

/// Verify an Ed25519 signature (RFC 8032) over `message` against a raw 32-byte key.
fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pubkey): Result<[u8; 32], _> = pubkey.try_into() else {
        return false;
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pubkey) else {
        return false;
    };
    let Ok(signature): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&signature);
    verifying_key.verify_strict(message, &signature).is_ok()
}

/// Verify an ECDSA P-256 signature (`r||s`, 64 bytes) against a SEC1 public key.
fn verify_p256(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    verifying_key.verify(message, &signature).is_ok()
}
