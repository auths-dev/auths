//! Key state derived from replaying a KERI event log.
//!
//! The `KeyState` represents the current cryptographic state of a KERI
//! identity after processing all events in its KEL. This is the "resolved"
//! state used for signature verification and capability checking.

use serde::{Deserialize, Serialize};

use super::types::{Prefix, Said};

/// Current key state derived from replaying a KEL.
///
/// This struct captures the complete state of a KERI identity at a given
/// point in its event log. It is computed by walking the KEL from inception
/// to the latest event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyState {
    /// The KERI identifier prefix (used in did:keri:<prefix>)
    pub prefix: Prefix,

    /// Current signing key(s), Base64url encoded with derivation code prefix.
    /// For Ed25519 keys, this is "D" + base64url(pubkey).
    pub current_keys: Vec<String>,

    /// Next key commitment(s) for pre-rotation.
    /// These are Blake3 hashes of the next public key(s).
    pub next_commitment: Vec<String>,

    /// Current sequence number (0 for inception, increments with each event)
    pub sequence: u64,

    /// SAID of the last processed event
    pub last_event_said: Said,

    /// Whether this identity has been abandoned (empty next commitment)
    pub is_abandoned: bool,
}

impl KeyState {
    /// Create initial state from an inception event.
    ///
    /// # Arguments
    /// * `prefix` - The KERI identifier (same as inception SAID)
    /// * `keys` - The initial signing key(s)
    /// * `next` - The next-key commitment(s)
    /// * `said` - The inception event SAID
    pub fn from_inception(
        prefix: Prefix,
        keys: Vec<String>,
        next: Vec<String>,
        said: Said,
    ) -> Self {
        Self {
            prefix,
            current_keys: keys,
            next_commitment: next.clone(),
            sequence: 0,
            last_event_said: said,
            is_abandoned: next.is_empty(),
        }
    }

    /// Apply a rotation event to update state.
    ///
    /// This should only be called after verifying:
    /// 1. The new key matches the previous next_commitment
    /// 2. The event's previous SAID matches last_event_said
    /// 3. The sequence is exactly last_sequence + 1
    pub fn apply_rotation(
        &mut self,
        new_keys: Vec<String>,
        new_next: Vec<String>,
        sequence: u64,
        said: Said,
    ) {
        self.current_keys = new_keys;
        self.next_commitment = new_next.clone();
        self.sequence = sequence;
        self.last_event_said = said;
        self.is_abandoned = new_next.is_empty();
    }

    /// Apply an interaction event (updates sequence and SAID only).
    ///
    /// Interaction events anchor data but don't change keys.
    pub fn apply_interaction(&mut self, sequence: u64, said: Said) {
        self.sequence = sequence;
        self.last_event_said = said;
    }

    /// Get the current signing key (first key for single-sig).
    ///
    /// Returns the encoded key string (e.g., "DBase64EncodedKey...")
    pub fn current_key(&self) -> Option<&str> {
        self.current_keys.first().map(|s| s.as_str())
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
mod tests {
    use super::*;

    #[test]
    fn key_state_from_inception() {
        let state = KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            Said::new_unchecked("ESAID".to_string()),
        );
        assert_eq!(state.sequence, 0);
        assert!(!state.is_abandoned);
        assert!(state.can_rotate());
        assert_eq!(state.current_key(), Some("DKey1"));
        assert_eq!(state.did(), "did:keri:EPrefix");
    }

    #[test]
    fn key_state_apply_rotation() {
        let mut state = KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            Said::new_unchecked("ESAID1".to_string()),
        );

        state.apply_rotation(
            vec!["DKey2".to_string()],
            vec!["ENext2".to_string()],
            1,
            Said::new_unchecked("ESAID2".to_string()),
        );

        assert_eq!(state.sequence, 1);
        assert_eq!(state.current_keys[0], "DKey2");
        assert_eq!(state.next_commitment[0], "ENext2");
        assert_eq!(state.last_event_said, "ESAID2");
        assert!(state.can_rotate());
    }

    #[test]
    fn key_state_apply_interaction() {
        let mut state = KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            Said::new_unchecked("ESAID1".to_string()),
        );

        state.apply_interaction(1, Said::new_unchecked("ESAID_IXN".to_string()));

        assert_eq!(state.sequence, 1);
        // Keys should not change
        assert_eq!(state.current_keys[0], "DKey1");
        assert_eq!(state.last_event_said, "ESAID_IXN");
    }

    #[test]
    fn abandoned_identity_cannot_rotate() {
        let state = KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec!["DKey1".to_string()],
            vec![], // Empty next commitment = abandoned
            Said::new_unchecked("ESAID".to_string()),
        );
        assert!(state.is_abandoned);
        assert!(!state.can_rotate());
    }

    #[test]
    fn key_state_serializes() {
        let state = KeyState::from_inception(
            Prefix::new_unchecked("EPrefix".to_string()),
            vec!["DKey1".to_string()],
            vec!["ENext1".to_string()],
            Said::new_unchecked("ESAID".to_string()),
        );

        let json = serde_json::to_string(&state).unwrap();
        let parsed: KeyState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, parsed);
    }
}
