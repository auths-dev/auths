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
///
/// Each argument is a JSON-encoded [`crate::rotation::KeyState`] — the shape a KEL
/// replay yields (the stable AID, the current key it resolves to, and the
/// pre-rotation commitment to the next key). The verdict is decided by the
/// pre-rotation commitment check ([`crate::rotation::verify_continuation`]): a
/// rotation whose new key the prior state pre-committed to is a
/// [`TrustState::VerifiedContinuation`]; a substituted key the prior state never
/// pre-committed to is a [`TrustState::NonContinuationWarning`], **never** a soft
/// re-pin. A malformed key-state is rejected — the UI never claims "verified"
/// without a key-state it could replay.
pub fn evaluate(prior_keystate: &str, current_keystate: &str) -> crate::CoreResult<TrustVerdict> {
    let prior: crate::rotation::KeyState = serde_json::from_str(prior_keystate)
        .map_err(|e| crate::CoreError::Malformed(format!("parse prior key-state: {e}")))?;
    let current: crate::rotation::KeyState = serde_json::from_str(current_keystate)
        .map_err(|e| crate::CoreError::Malformed(format!("parse current key-state: {e}")))?;
    Ok(crate::rotation::verify_continuation(&prior, &current))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Aid;
    use crate::identity::Identity;
    use crate::rotation::KeyState;

    fn keystate_json(aid: &Aid, current: &Identity, next_public_key: &[u8]) -> String {
        serde_json::to_string(&KeyState::new(aid.clone(), current, next_public_key)).unwrap()
    }

    #[test]
    fn evaluate_surfaces_a_verified_continuation_for_a_pre_committed_rotation() {
        let aid = Aid::new("did:keri:stable");
        let prior_key = Identity::from_seed([1u8; 32]).unwrap();
        let rotated_key = Identity::from_seed([2u8; 32]).unwrap();
        let prior = keystate_json(&aid, &prior_key, rotated_key.public_key());
        let current = keystate_json(&aid, &rotated_key, rotated_key.public_key());
        let verdict = evaluate(&prior, &current).unwrap();
        assert_eq!(verdict.state, TrustState::VerifiedContinuation);
    }

    #[test]
    fn evaluate_warns_on_a_substituted_key_rather_than_re_pinning() {
        let aid = Aid::new("did:keri:stable");
        let prior_key = Identity::from_seed([1u8; 32]).unwrap();
        let rotated_key = Identity::from_seed([2u8; 32]).unwrap();
        let substitute = Identity::from_seed([9u8; 32]).unwrap();
        // The prior state pre-committed to the rotated key, but the substitute is a
        // key it never pre-committed to.
        let prior = keystate_json(&aid, &prior_key, rotated_key.public_key());
        let current = keystate_json(&aid, &substitute, substitute.public_key());
        let verdict = evaluate(&prior, &current).unwrap();
        assert_eq!(verdict.state, TrustState::NonContinuationWarning);
    }

    #[test]
    fn evaluate_rejects_a_malformed_key_state() {
        assert!(matches!(
            evaluate("not json", "also not json"),
            Err(crate::CoreError::Malformed(_))
        ));
    }
}
