//! KERI identifier newtypes and conversion helpers.
//!
//! Re-exports `Prefix`, `Said`, and `KeriTypeError` from `auths-verifier`
//! (the leaf dependency shared by all crates). Adds `IdentityDID` conversion
//! helpers that require `auths-core` types.

pub use auths_keri::{KeriTypeError, Prefix, Said};

use auths_core::error::AgentError;
use auths_core::storage::keychain::IdentityDID;

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
        let did = IdentityDID::try_from(&p).unwrap();
        assert_eq!(did.as_str(), "did:keri:ETest123abc");
    }

    #[test]
    fn prefix_from_did_roundtrip() {
        let p = Prefix::new("ETest123abc".to_string()).unwrap();
        let did = IdentityDID::try_from(&p).unwrap();
        let back = prefix_from_did(&did).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn non_keri_did_is_rejected_at_parse_boundary() {
        // A `did:key:` value can never become a valid `IdentityDID`; the scheme
        // check that `prefix_from_did` once performed is now enforced earlier, at
        // construction, so the rejection is asserted at the parse boundary.
        assert!(IdentityDID::parse("did:key:z6Mk").is_err());
    }

    #[test]
    fn prefix_and_said_are_distinct_types() {
        let prefix = Prefix::new("ETest123".to_string()).unwrap();
        let said = Said::new("ETest123".to_string()).unwrap();
        assert_eq!(prefix.as_str(), said.as_str());
    }
}
