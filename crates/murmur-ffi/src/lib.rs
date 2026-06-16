//! UniFFI bindings for murmur-core — the Swift↔engine glue the native iOS +
//! macOS Murmur shells embed.
//!
//! This mirrors `auths-mobile-ffi`: every private-key operation lives off-Rust
//! (the mobile side holds the key in the Secure Enclave and produces signatures
//! externally), so this FFI only ever sees public material — an address, an
//! envelope, a trust verdict. The engine roots identity; this layer is the
//! projection the SwiftUI shells call.
//!
//! SKELETON: the seams are exposed and they compile, but the bind/ratchet/relay
//! are not built in murmur-core yet — so an operation that would need them
//! surfaces an honest [`MurmurError::NotBuilt`] across the FFI, never a fake
//! success. That is exactly what lets the apps render a real "feature absent"
//! state and what lets a probe tell "absent" apart from "broke".

#![forbid(unsafe_code)]

uniffi::setup_scaffolding!();

/// The error surfaced across the FFI. `NotBuilt` is the load-bearing variant
/// for the skeleton — it names the seam that is specified but unwired.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MurmurError {
    /// A specified seam that has not been built yet (the string names it).
    #[error("not built yet: {0}")]
    NotBuilt(String),
    /// A message that must fail closed — an unauthorized AID, a substituted
    /// key, tampered ciphertext, a revoked device. The string names which.
    #[error("rejected: {0}")]
    Rejected(String),
    /// Input the core could not parse.
    #[error("malformed: {0}")]
    Malformed(String),
}

impl From<murmur_core::CoreError> for MurmurError {
    fn from(e: murmur_core::CoreError) -> Self {
        match e {
            murmur_core::CoreError::NotBuilt(s) => MurmurError::NotBuilt(s.to_string()),
            murmur_core::CoreError::Rejected(s) => MurmurError::Rejected(s.to_string()),
            murmur_core::CoreError::Malformed(s) => MurmurError::Malformed(s),
        }
    }
}

/// The trust verdict the SwiftUI shell renders beside a contact or a received
/// message. A flattened projection of [`murmur_core::TrustState`] so the Swift
/// side can switch on it and pick the trust-state token (the one thing Liquid
/// Glass must never dilute).
#[derive(uniffi::Enum)]
pub enum TrustBadge {
    /// A contact whose current key-state we verified by replay.
    Verified,
    /// The headline win: a verified, pre-committed continuation of the same
    /// identity (not a scary safety-number warning).
    VerifiedContinuation,
    /// The adversarial case: a key change that is NOT a pre-committed
    /// continuation — must read unmistakably as a warning behind glass.
    NonContinuationWarning,
}

impl From<murmur_core::TrustState> for TrustBadge {
    fn from(s: murmur_core::TrustState) -> Self {
        match s {
            murmur_core::TrustState::Verified => TrustBadge::Verified,
            murmur_core::TrustState::VerifiedContinuation => TrustBadge::VerifiedContinuation,
            murmur_core::TrustState::NonContinuationWarning => TrustBadge::NonContinuationWarning,
        }
    }
}

/// The murmur-core version string, surfaced to the shells' about screen and to
/// the probe harness so it can confirm the embedded engine is the built one.
#[uniffi::export]
pub fn core_version() -> String {
    murmur_core::VERSION.to_string()
}

/// Wrap a textual AID (`did:keri:…` / `did:webs:…`) and echo its canonical
/// string — the cheapest end-to-end FFI round-trip the shells use to prove the
/// engine is embedded and callable. No phone number or email appears anywhere.
#[uniffi::export]
pub fn address_canonical(text: String) -> String {
    murmur_core::Aid::new(text).as_str().to_string()
}

/// Seal a plaintext message addressed to a recipient AID. SKELETON: the KERI
/// bind + Signal ratchet are unbuilt in the engine, so this returns
/// [`MurmurError::NotBuilt`] across the FFI — the shell renders "feature absent"
/// rather than a fake sent state.
#[uniffi::export]
pub fn seal_message(to: String, from: String, body: String) -> Result<Vec<u8>, MurmurError> {
    let msg = murmur_core::Message {
        to: murmur_core::Aid::new(to),
        from: murmur_core::Aid::new(from),
        body,
    };
    let outer = murmur_core::seal(&msg)?;
    serde_json::to_vec(&outer).map_err(|e| MurmurError::Malformed(e.to_string()))
}

/// Evaluate the trust transition for a contact (prior vs current key-state).
/// SKELETON: the pre-rotation commitment check is unbuilt, so this fails closed
/// — the shell never claims "verified" without the replay.
#[uniffi::export]
pub fn evaluate_trust(prior_keystate: String, current_keystate: String) -> Result<TrustBadge, MurmurError> {
    let verdict = murmur_core::trust::evaluate(&prior_keystate, &current_keystate)?;
    Ok(verdict.state.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_version_is_nonempty() {
        assert!(!core_version().is_empty());
    }

    #[test]
    fn address_round_trips() {
        assert_eq!(address_canonical("did:keri:abc".into()), "did:keri:abc");
    }

    #[test]
    fn seal_is_honestly_unbuilt_across_the_ffi() {
        let r = seal_message("did:keri:to".into(), "did:keri:from".into(), "hi".into());
        assert!(matches!(r, Err(MurmurError::NotBuilt(_))));
    }

    #[test]
    fn trust_is_honestly_unbuilt_across_the_ffi() {
        let r = evaluate_trust("prior".into(), "current".into());
        assert!(matches!(r, Err(MurmurError::NotBuilt(_))));
    }
}
