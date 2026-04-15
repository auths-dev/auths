//! Key state derived from replaying a KERI event log.
//!
//! The `KeyState` represents the current cryptographic state of a KERI
//! identity after processing all events in its KEL. This is the "resolved"
//! state used for signature verification and capability checking.

use serde::{Deserialize, Serialize};

use crate::types::{CesrKey, ConfigTrait, Prefix, Said, Threshold};

/// Current key state derived from replaying a KEL.
///
/// This struct captures the complete state of a KERI identity at a given
/// point in its event log. It is computed by walking the KEL from inception
/// to the latest event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct KeyState {
    /// The KERI identifier prefix (used in `did:keri:<prefix>`)
    pub prefix: Prefix,

    /// Current signing key(s), CESR-encoded.
    pub current_keys: Vec<CesrKey>,

    /// Next key commitment(s) for pre-rotation (Blake3 digests).
    pub next_commitment: Vec<Said>,

    /// Current sequence number (0 for inception, increments with each event)
    pub sequence: u128,

    /// SAID of the last processed event
    pub last_event_said: Said,

    /// Whether this identity has been abandoned (empty next commitment in rotation)
    pub is_abandoned: bool,
    /// Current signing threshold
    pub threshold: Threshold,
    /// Next signing threshold (committed)
    pub next_threshold: Threshold,
    /// Current backer/witness list
    #[serde(default)]
    pub backers: Vec<Prefix>,
    /// Current backer threshold
    #[serde(default)]
    pub backer_threshold: Threshold,
    /// Configuration traits from inception (and rotation for RB/NRB)
    #[serde(default)]
    pub config_traits: Vec<ConfigTrait>,
    /// Whether this identity is non-transferable (inception `n` was empty)
    #[serde(default)]
    pub is_non_transferable: bool,
    /// Delegator AID (if this is a delegated identity)
    #[serde(default)]
    pub delegator: Option<Prefix>,
}

impl KeyState {
    /// Create initial state from an inception event.
    ///
    /// Args:
    /// * `prefix` - The KERI identifier (same as inception SAID)
    /// * `keys` - The initial signing key(s)
    /// * `next` - The next-key commitment(s)
    /// * `threshold` - Initial signing threshold
    /// * `next_threshold` - Committed next signing threshold
    /// * `said` - The inception event SAID
    /// * `backers` - Initial witness/backer list
    /// * `backer_threshold` - Witness/backer threshold
    /// * `config_traits` - Configuration traits from inception
    #[allow(clippy::too_many_arguments)]
    pub fn from_inception(
        prefix: Prefix,
        keys: Vec<CesrKey>,
        next: Vec<Said>,
        threshold: Threshold,
        next_threshold: Threshold,
        said: Said,
        backers: Vec<Prefix>,
        backer_threshold: Threshold,
        config_traits: Vec<ConfigTrait>,
    ) -> Self {
        let is_non_transferable = next.is_empty();
        Self {
            prefix,
            current_keys: keys,
            next_commitment: next.clone(),
            sequence: 0,
            last_event_said: said,
            is_abandoned: next.is_empty(),
            threshold,
            next_threshold,
            backers,
            backer_threshold,
            config_traits,
            is_non_transferable,
            delegator: None,
        }
    }

    /// Apply a rotation event to update state.
    ///
    /// This should only be called after verifying:
    /// 1. The new key matches the previous next_commitment
    /// 2. The event's previous SAID matches last_event_said
    /// 3. The sequence is exactly last_sequence + 1
    #[allow(clippy::too_many_arguments)]
    pub fn apply_rotation(
        &mut self,
        new_keys: Vec<CesrKey>,
        new_next: Vec<Said>,
        threshold: Threshold,
        next_threshold: Threshold,
        sequence: u128,
        said: Said,
        backers_to_remove: &[Prefix],
        backers_to_add: &[Prefix],
        backer_threshold: Threshold,
        config_traits: Vec<ConfigTrait>,
    ) {
        self.current_keys = new_keys;
        self.next_commitment = new_next.clone();
        self.threshold = threshold;
        self.next_threshold = next_threshold;
        self.sequence = sequence;
        self.last_event_said = said;
        self.is_abandoned = new_next.is_empty();

        // Apply backer deltas: remove first, then add
        self.backers.retain(|b| !backers_to_remove.contains(b));
        self.backers.extend(backers_to_add.iter().cloned());
        self.backer_threshold = backer_threshold;

        // Update config traits (RB/NRB can change in rotation)
        if !config_traits.is_empty() {
            self.config_traits = config_traits;
        }
    }

    /// Apply an interaction event (updates sequence and SAID only).
    ///
    /// Interaction events anchor data but don't change keys.
    pub fn apply_interaction(&mut self, sequence: u128, said: Said) {
        self.sequence = sequence;
        self.last_event_said = said;
    }

    /// Get the current signing key (first key for single-sig).
    pub fn current_key(&self) -> Option<&CesrKey> {
        self.current_keys.first()
    }

    /// Check if key can be rotated.
    ///
    /// Returns `false` if the identity has been abandoned (empty next commitment).
    pub fn can_rotate(&self) -> bool {
        !self.is_abandoned && !self.next_commitment.is_empty()
    }

    /// Get the DID for this identity.
    pub fn did(&self) -> String {
        format!("did:keri:{}", self.prefix.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_key(s: &str) -> CesrKey {
        CesrKey::new_unchecked(s.to_string())
    }

    fn make_state() -> KeyState {
        KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec![make_key("DKey1")],
            vec![Said::new_unchecked("ENext1".to_string())],
            Threshold::Simple(1),
            Threshold::Simple(1),
            Said::new_unchecked("ESAID".to_string()),
            vec![],
            Threshold::Simple(0),
            vec![],
        )
    }

    #[test]
    fn key_state_from_inception() {
        let state = make_state();
        assert_eq!(state.sequence, 0);
        assert!(!state.is_abandoned);
        assert!(state.can_rotate());
        assert_eq!(state.current_key().map(|k| k.as_str()), Some("DKey1"));
        assert_eq!(state.did(), "did:keri:EPrefix");
    }

    #[test]
    fn key_state_apply_rotation() {
        let mut state = make_state();

        state.apply_rotation(
            vec![make_key("DKey2")],
            vec![Said::new_unchecked("ENext2".to_string())],
            Threshold::Simple(1),
            Threshold::Simple(1),
            1,
            Said::new_unchecked("ESAID2".to_string()),
            &[],
            &[],
            Threshold::Simple(0),
            vec![],
        );

        assert_eq!(state.sequence, 1);
        assert_eq!(state.current_keys[0].as_str(), "DKey2");
        assert_eq!(state.next_commitment[0], "ENext2");
        assert_eq!(state.last_event_said, "ESAID2");
        assert!(state.can_rotate());
    }

    #[test]
    fn key_state_apply_interaction() {
        let mut state = make_state();
        state.apply_interaction(1, Said::new_unchecked("ESAID_IXN".to_string()));

        assert_eq!(state.sequence, 1);
        assert_eq!(state.current_keys[0].as_str(), "DKey1");
        assert_eq!(state.last_event_said, "ESAID_IXN");
    }

    #[test]
    fn abandoned_identity_cannot_rotate() {
        let state = KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec![make_key("DKey1")],
            vec![],
            Threshold::Simple(1),
            Threshold::Simple(0),
            Said::new_unchecked("ESAID".to_string()),
            vec![],
            Threshold::Simple(0),
            vec![],
        );
        assert!(state.is_abandoned);
        assert!(!state.can_rotate());
    }

    #[test]
    fn key_state_serializes() {
        let state = make_state();
        let json = serde_json::to_string(&state).unwrap();
        let parsed: KeyState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, parsed);
    }

    #[test]
    fn rotation_applies_backer_deltas() {
        let mut state = KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec![make_key("DKey1")],
            vec![Said::new_unchecked("ENext1".to_string())],
            Threshold::Simple(1),
            Threshold::Simple(1),
            Said::new_unchecked("ESAID".to_string()),
            vec![
                Prefix::new_unchecked("DWit1".to_string()),
                Prefix::new_unchecked("DWit2".to_string()),
            ],
            Threshold::Simple(2),
            vec![],
        );

        state.apply_rotation(
            vec![make_key("DKey2")],
            vec![Said::new_unchecked("ENext2".to_string())],
            Threshold::Simple(1),
            Threshold::Simple(1),
            1,
            Said::new_unchecked("ESAID2".to_string()),
            &[Prefix::new_unchecked("DWit1".to_string())],
            &[Prefix::new_unchecked("DWit3".to_string())],
            Threshold::Simple(2),
            vec![],
        );

        assert_eq!(state.backers.len(), 2);
        assert_eq!(state.backers[0].as_str(), "DWit2");
        assert_eq!(state.backers[1].as_str(), "DWit3");
    }
}
