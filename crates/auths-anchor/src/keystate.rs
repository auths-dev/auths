//! The KEL → [`ControllerKeys`] bridge.
//!
//! KEL replay is I/O-orchestration that lives above the protocol core (D3), but
//! the mapping from an already-resolved [`auths_keri::KeyState`] to the pure
//! [`ControllerKeys`] the acceptance rule consumes is a small, total function —
//! it belongs beside the rule so every caller resolves keys the same way.

use auths_keri::KeyState;

use crate::error::AnchorError;
use crate::types::{ControllerKeys, CurrentKey};

impl ControllerKeys {
    /// Resolve the controller's current keys from an authoritative key state.
    ///
    /// Each CESR-qualified current key is parsed into its curve and raw bytes;
    /// the curve is taken from the parsed key, never inferred from length.
    ///
    /// Args:
    /// * `key_state`: the KEL-replayed key state of the anchor's controller.
    ///
    /// Usage:
    /// ```ignore
    /// let keys = ControllerKeys::from_key_state(&key_state)?;
    /// accept_anchor(&req, &keys, prior.as_ref(), now)?;
    /// ```
    pub fn from_key_state(key_state: &KeyState) -> Result<Self, AnchorError> {
        let mut current = Vec::with_capacity(key_state.current_keys.len());
        for cesr in &key_state.current_keys {
            let parsed = cesr
                .parse()
                .map_err(|e| AnchorError::MalformedMaterial(e.to_string()))?;
            current.push(CurrentKey {
                curve: parsed.curve(),
                public_key: parsed.raw_bytes().to_vec(),
            });
        }
        Ok(Self { current })
    }
}
