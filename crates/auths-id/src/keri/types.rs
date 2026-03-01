//! KERI identifier newtypes and conversion helpers.
//!
//! Re-exports `Prefix`, `Said`, and `KeriTypeError` from `auths-verifier`
//! (the leaf dependency shared by all crates). Adds `IdentityDID` conversion
//! helpers that require `auths-core` types.

pub use auths_verifier::keri::{KeriTypeError, Prefix, Said};

use auths_core::error::AgentError;
use auths_core::storage::keychain::IdentityDID;

/// Convert a `Prefix` to a `did:keri:` identity DID.
///
/// Usage:
/// ```ignore
/// let did = prefix_to_did(&prefix);
/// assert_eq!(did.as_str(), "did:keri:ETest123abc");
/// ```
pub fn prefix_to_did(prefix: &Prefix) -> IdentityDID {
    IdentityDID::new_unchecked(format!("did:keri:{}", prefix.as_str()))
}

/// Extract a `Prefix` from a `did:keri:` identity DID.
///
/// Usage:
/// ```ignore
/// let prefix = prefix_from_did(&did)?;
/// assert_eq!(prefix.as_str(), "ETest123abc");
/// ```
pub fn prefix_from_did(did: &IdentityDID) -> Result<Prefix, AgentError> {
    let raw = did.as_str().strip_prefix("did:keri:").ok_or_else(|| {
        AgentError::InvalidInput(format!("Expected did:keri: prefix, got '{}'", did.as_str()))
    })?;
    Prefix::new(raw.to_string()).map_err(|e| AgentError::InvalidInput(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_to_did_converts() {
        let p = Prefix::new("ETest123abc".to_string()).unwrap();
        let did = prefix_to_did(&p);
        assert_eq!(did.as_str(), "did:keri:ETest123abc");
    }

    #[test]
    fn prefix_from_did_roundtrip() {
        let p = Prefix::new("ETest123abc".to_string()).unwrap();
        let did = prefix_to_did(&p);
        let back = prefix_from_did(&did).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn prefix_from_did_rejects_non_keri() {
        let did = IdentityDID::new_unchecked("did:key:z6Mk".to_string());
        let err = prefix_from_did(&did).unwrap_err();
        assert!(err.to_string().contains("Expected did:keri:"));
    }

    #[test]
    fn prefix_and_said_are_distinct_types() {
        let prefix = Prefix::new("ETest123".to_string()).unwrap();
        let said = Said::new("ETest123".to_string()).unwrap();
        assert_eq!(prefix.as_str(), said.as_str());
    }
}
