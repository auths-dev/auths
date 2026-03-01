//! Trust resolution implementation for auths-id.
//!
//! This module implements the [`KelContinuityChecker`] trait from auths-core,
//! providing Git-backed KEL replay for verifying rotation continuity.

use auths_core::trust::continuity::{KelContinuityChecker, RotationProof};
use auths_crypto::KeriPublicKey;
use git2::Repository;

use crate::keri::{Event, GitKel, Said, did_to_prefix, validate_kel};

/// KEL-based rotation continuity checker backed by a Git repository.
///
/// This implementation verifies that there is a valid, unbroken event chain
/// from a pinned KEL tip to the current state, enabling trust to be maintained
/// across key rotations.
///
/// # Example
///
/// ```ignore
/// use git2::Repository;
/// use auths_id::trust::GitKelContinuityChecker;
/// use auths_core::trust::KelContinuityChecker;
///
/// let repo = Repository::open("~/.auths")?;
/// let checker = GitKelContinuityChecker::new(&repo);
///
/// let proof = checker.verify_rotation_continuity(
///     "did:keri:EPrefix...",
///     "EOldTipSaid",
///     &presented_public_key,
/// )?;
/// ```
pub struct GitKelContinuityChecker<'a> {
    repo: &'a Repository,
}

impl<'a> GitKelContinuityChecker<'a> {
    /// Create a new continuity checker for the given repository.
    pub fn new(repo: &'a Repository) -> Self {
        Self { repo }
    }
}

impl KelContinuityChecker for GitKelContinuityChecker<'_> {
    fn verify_rotation_continuity(
        &self,
        did: &str,
        pinned_tip_said: &str,
        presented_pk: &[u8],
    ) -> anyhow::Result<Option<RotationProof>> {
        let pinned_said = Said::new_unchecked(pinned_tip_said.to_string());
        let prefix = did_to_prefix(did)
            .ok_or_else(|| anyhow::anyhow!("Invalid did:keri format: {}", did))?;

        let kel = GitKel::new(self.repo, prefix);
        if !kel.exists() {
            return Ok(None);
        }

        let events = kel.get_events()?;

        // 1. Locate the pinned tip event by SAID
        let pinned_idx = events.iter().position(|e| e.said() == pinned_tip_said);
        let Some(pinned_idx) = pinned_idx else {
            return Ok(None); // Pinned tip not in this KEL
        };

        // 2. Validate the FULL KEL from inception to get correct state
        //    (we can't trust a partial replay — need full chain integrity)
        let full_state = validate_kel(&events)?;

        // 3. Verify the sub-chain from pinned_idx forward is unbroken.
        //    This ensures the pinned tip is an ancestor of the current tip,
        //    not just present in a forked history.
        if !verify_chain_from_index(&events, pinned_idx, &pinned_said) {
            return Ok(None); // Chain forks after pinned tip
        }

        // 4. Confirm the replayed state's current key matches presented_pk
        let current_key_encoded = match full_state.current_key() {
            Some(k) => k,
            None => return Ok(None),
        };
        let current_key_bytes = KeriPublicKey::parse(current_key_encoded)
            .map_err(|e| anyhow::anyhow!("KERI key decode failed: {e}"))?;

        if current_key_bytes.as_bytes().as_slice() != presented_pk {
            return Ok(None); // KEL is valid but leads to a different key
        }

        Ok(Some(RotationProof {
            new_public_key: current_key_bytes.as_bytes().to_vec(),
            new_kel_tip: full_state.last_event_said.to_string(),
            new_sequence: full_state.sequence,
        }))
    }
}

/// Verify that the event chain from `pinned_idx` forward is unbroken.
///
/// Walks from `pinned_idx + 1` to end, verifying each event's `p` field
/// links back to the previous event's SAID.
fn verify_chain_from_index(events: &[Event], pinned_idx: usize, pinned_tip_said: &Said) -> bool {
    let mut expected_prev = pinned_tip_said.clone();

    for event in events.iter().skip(pinned_idx + 1) {
        let prev = match event.previous() {
            Some(p) => p,
            None => return false, // Non-inception event missing previous SAID
        };
        if *prev != expected_prev {
            return false; // Chain forks after pinned tip
        }
        expected_prev = event.said().clone();
    }

    true
}

#[cfg(test)]
mod tests {
    use auths_crypto::KeriPublicKey;

    #[test]
    fn test_keri_key_parse_valid() {
        let encoded = "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = KeriPublicKey::parse(encoded).unwrap();
        assert_eq!(key.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_keri_key_parse_invalid_prefix() {
        let result = KeriPublicKey::parse("XInvalidPrefix");
        assert!(result.is_err());
    }

    #[test]
    fn test_keri_key_parse_invalid_base64() {
        let result = KeriPublicKey::parse("D!!!invalid!!!");
        assert!(result.is_err());
    }
}
