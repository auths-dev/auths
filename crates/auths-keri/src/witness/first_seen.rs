//! First-seen policy for KERI event acceptance.
//!
//! The spec rule: "First seen, always seen, never unseen."
//! Once a validator accepts an event at a given (prefix, sequence), it must
//! reject any DIFFERENT event at that same (prefix, sequence).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::types::{Prefix, Said};

/// Error when a conflicting event is detected at the same (prefix, sequence).
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[error(
    "Conflicting event at prefix={prefix}, sn={sn}: first-seen SAID={first_seen}, new SAID={new_said}"
)]
pub struct FirstSeenConflict {
    /// The prefix of the identity.
    pub prefix: String,
    /// The sequence number where conflict was detected.
    pub sn: u64,
    /// The SAID of the first-seen event.
    pub first_seen: String,
    /// The SAID of the conflicting new event.
    pub new_said: String,
}

/// Policy for enforcing first-seen event acceptance.
///
/// Implementations track which events have been accepted at each (prefix, sequence)
/// location and reject conflicting events.
///
/// Usage:
/// ```ignore
/// let policy = InMemoryFirstSeen::new();
/// policy.try_accept(&prefix, 0, &said)?;  // first event accepted
/// policy.try_accept(&prefix, 0, &said)?;  // same event, idempotent
/// policy.try_accept(&prefix, 0, &other)?; // CONFLICT: different event at same location
/// ```
pub trait FirstSeenPolicy: Send + Sync {
    /// Accept an event if no conflicting event was previously seen.
    ///
    /// Returns `Ok(())` if the event is accepted (first-seen or same as first-seen).
    /// Returns `Err(FirstSeenConflict)` if a DIFFERENT event was already accepted at this location.
    fn try_accept(&self, prefix: &Prefix, sn: u64, said: &Said) -> Result<(), FirstSeenConflict>;

    /// Check if an event was already seen at this location.
    ///
    /// Returns the SAID of the first-seen event, or None if no event was seen.
    fn was_seen(&self, prefix: &Prefix, sn: u64) -> Option<Said>;

    /// Attempt to supersede a previously accepted event with a recovery rotation.
    ///
    /// Per the spec, a rotation event at sequence N can supersede a previously
    /// accepted interaction event at the same N. This is the mechanism for
    /// recovering from key compromise.
    ///
    /// Returns `Ok(())` if the superseding succeeded, or `Err` if superseding
    /// is not allowed (e.g., trying to supersede a rotation with an interaction).
    fn try_supersede(
        &self,
        prefix: &Prefix,
        sn: u64,
        new_said: &Said,
        is_new_establishment: bool,
    ) -> Result<(), FirstSeenConflict>;
}

/// In-memory first-seen policy (HashMap-based).
///
/// Suitable for single-process validators. For persistent validators,
/// wrap a database-backed implementation.
pub struct InMemoryFirstSeen {
    seen: Mutex<HashMap<(String, u64), SeenEntry>>,
}

#[derive(Clone)]
struct SeenEntry {
    said: Said,
    is_establishment: bool,
}

impl InMemoryFirstSeen {
    /// Create a new empty first-seen policy.
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryFirstSeen {
    fn default() -> Self {
        Self::new()
    }
}

impl FirstSeenPolicy for InMemoryFirstSeen {
    fn try_accept(&self, prefix: &Prefix, sn: u64, said: &Said) -> Result<(), FirstSeenConflict> {
        let key = (prefix.as_str().to_string(), sn);
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(existing) = seen.get(&key) {
            if existing.said != *said {
                return Err(FirstSeenConflict {
                    prefix: prefix.as_str().to_string(),
                    sn,
                    first_seen: existing.said.as_str().to_string(),
                    new_said: said.as_str().to_string(),
                });
            }
            Ok(())
        } else {
            seen.insert(
                key,
                SeenEntry {
                    said: said.clone(),
                    is_establishment: false, // caller should use try_accept_establishment for establishment events
                },
            );
            Ok(())
        }
    }

    fn was_seen(&self, prefix: &Prefix, sn: u64) -> Option<Said> {
        let key = (prefix.as_str().to_string(), sn);
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.get(&key).map(|e| e.said.clone())
    }

    fn try_supersede(
        &self,
        prefix: &Prefix,
        sn: u64,
        new_said: &Said,
        is_new_establishment: bool,
    ) -> Result<(), FirstSeenConflict> {
        let key = (prefix.as_str().to_string(), sn);
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(existing) = seen.get(&key) {
            if existing.said == *new_said {
                return Ok(()); // Same event, no superseding needed
            }

            // Superseding rule: establishment can supersede non-establishment, not vice versa
            if is_new_establishment && !existing.is_establishment {
                // Allowed: rotation supersedes interaction
                seen.insert(
                    key,
                    SeenEntry {
                        said: new_said.clone(),
                        is_establishment: true,
                    },
                );
                Ok(())
            } else {
                Err(FirstSeenConflict {
                    prefix: prefix.as_str().to_string(),
                    sn,
                    first_seen: existing.said.as_str().to_string(),
                    new_said: new_said.as_str().to_string(),
                })
            }
        } else {
            // No existing event — just accept
            seen.insert(
                key,
                SeenEntry {
                    said: new_said.clone(),
                    is_establishment: is_new_establishment,
                },
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn first_event_accepted() {
        let policy = InMemoryFirstSeen::new();
        let prefix = Prefix::new_unchecked("ETest".to_string());
        let said = Said::new_unchecked("ESAID1".to_string());
        assert!(policy.try_accept(&prefix, 0, &said).is_ok());
    }

    #[test]
    fn same_event_idempotent() {
        let policy = InMemoryFirstSeen::new();
        let prefix = Prefix::new_unchecked("ETest".to_string());
        let said = Said::new_unchecked("ESAID1".to_string());
        policy.try_accept(&prefix, 0, &said).unwrap();
        assert!(policy.try_accept(&prefix, 0, &said).is_ok());
    }

    #[test]
    fn different_event_rejected() {
        let policy = InMemoryFirstSeen::new();
        let prefix = Prefix::new_unchecked("ETest".to_string());
        let said1 = Said::new_unchecked("ESAID1".to_string());
        let said2 = Said::new_unchecked("ESAID2".to_string());
        policy.try_accept(&prefix, 0, &said1).unwrap();
        let err = policy.try_accept(&prefix, 0, &said2).unwrap_err();
        assert_eq!(err.first_seen, "ESAID1");
        assert_eq!(err.new_said, "ESAID2");
    }

    #[test]
    fn different_sequences_independent() {
        let policy = InMemoryFirstSeen::new();
        let prefix = Prefix::new_unchecked("ETest".to_string());
        let said1 = Said::new_unchecked("ESAID1".to_string());
        let said2 = Said::new_unchecked("ESAID2".to_string());
        policy.try_accept(&prefix, 0, &said1).unwrap();
        assert!(policy.try_accept(&prefix, 1, &said2).is_ok());
    }

    #[test]
    fn was_seen_returns_said() {
        let policy = InMemoryFirstSeen::new();
        let prefix = Prefix::new_unchecked("ETest".to_string());
        let said = Said::new_unchecked("ESAID1".to_string());

        assert!(policy.was_seen(&prefix, 0).is_none());
        policy.try_accept(&prefix, 0, &said).unwrap();
        assert_eq!(policy.was_seen(&prefix, 0), Some(said));
    }

    // ── Superseding recovery ────────────────────────────────────────────

    #[test]
    fn rotation_supersedes_interaction() {
        let policy = InMemoryFirstSeen::new();
        let prefix = Prefix::new_unchecked("ETest".to_string());
        let ixn_said = Said::new_unchecked("ESAID_IXN".to_string());
        let rot_said = Said::new_unchecked("ESAID_ROT".to_string());

        // First-seen: interaction
        policy.try_accept(&prefix, 1, &ixn_said).unwrap();

        // Supersede with rotation (establishment event)
        let result = policy.try_supersede(&prefix, 1, &rot_said, true);
        assert!(result.is_ok());

        // Now the first-seen is the rotation
        assert_eq!(policy.was_seen(&prefix, 1), Some(rot_said));
    }

    #[test]
    fn interaction_cannot_supersede_rotation() {
        let policy = InMemoryFirstSeen::new();
        let prefix = Prefix::new_unchecked("ETest".to_string());
        let rot_said = Said::new_unchecked("ESAID_ROT".to_string());
        let ixn_said = Said::new_unchecked("ESAID_IXN".to_string());

        // First-seen: rotation (establishment)
        policy.try_supersede(&prefix, 1, &rot_said, true).unwrap();

        // Try to supersede with interaction (non-establishment)
        let result = policy.try_supersede(&prefix, 1, &ixn_said, false);
        assert!(result.is_err());
    }

    #[test]
    fn rotation_cannot_supersede_rotation() {
        let policy = InMemoryFirstSeen::new();
        let prefix = Prefix::new_unchecked("ETest".to_string());
        let rot1 = Said::new_unchecked("ESAID_ROT1".to_string());
        let rot2 = Said::new_unchecked("ESAID_ROT2".to_string());

        policy.try_supersede(&prefix, 1, &rot1, true).unwrap();
        let result = policy.try_supersede(&prefix, 1, &rot2, true);
        assert!(result.is_err());
    }
}
