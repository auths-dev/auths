//! The trust state — the one thing Liquid Glass must never dilute.
//!
//! For a messenger the content is the conversation *and* the trust in who sent
//! it. The headline win (a verified, pre-committed continuation of the same
//! identity instead of a scary safety-number warning) and its adversarial twin
//! (a non-continuation key-change warning) are surfaced as a [`TrustState`].
//!
//! The product rule the apps enforce: a trust state must read unmistakably
//! behind glass, on any backdrop, holding WCAG AA — translucency never weakens a
//! security signal. This crate only models the *state*; the contrast guarantee
//! lives in the SwiftUI token layer and is gated by the app's contrast test.

use serde::{Deserialize, Serialize};

/// The trust verdict the UI renders beside a contact or a received message.
/// SKELETON: derived by replaying the sender's key log; the replay lives in the
/// auths engine and is not wired here yet, so [`evaluate`] fails closed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustState {
    /// A contact whose current key-state we verified by KEL replay.
    Verified,
    /// The headline win: the contact rotated keys and the new key was
    /// pre-committed by the prior key-state — a verified continuation of the
    /// *same* identity, not a re-pin.
    VerifiedContinuation,
    /// The adversarial case: a key change that is NOT a pre-committed
    /// continuation. This must read unmistakably as a warning behind glass.
    NonContinuationWarning,
}

/// The result of evaluating one trust transition for the UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustVerdict {
    /// The state to render.
    pub state: TrustState,
    /// A short, human-readable reason the UI can show under the badge.
    pub reason: String,
}

/// Evaluate the trust state for a contact given the prior and current key-state.
/// SKELETON: the pre-rotation commitment check (`verify_commitment` over a
/// replayed KEL) is not wired here yet, so this fails closed — the UI never
/// claims "verified" without the replay.
pub fn evaluate(_prior_keystate: &str, _current_keystate: &str) -> crate::CoreResult<TrustVerdict> {
    Err(crate::CoreError::NotBuilt(
        "trust: KEL replay + pre-rotation commitment check",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_is_honestly_unbuilt() {
        assert!(matches!(
            evaluate("prior", "current"),
            Err(crate::CoreError::NotBuilt(_))
        ));
    }
}
