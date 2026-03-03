use auths_verifier::core::Attestation;

/// Determines the commit message for an attestation export.
///
/// This is a pure function — it compares the new attestation against
/// the previous one (if any) and returns the appropriate human-readable
/// message describing the change.
///
/// Args:
/// * `attestation`: The attestation being exported.
/// * `previous`: The previously stored attestation, if any.
///
/// Usage:
/// ```ignore
/// use auths_id::domain::attestation_message::determine_commit_message;
///
/// let msg = determine_commit_message(&new_att, previous.as_ref());
/// ```
pub fn determine_commit_message(
    attestation: &Attestation,
    previous: Option<&Attestation>,
) -> &'static str {
    if attestation.is_revoked() && !previous.as_ref().is_some_and(|pa| pa.is_revoked()) {
        "Revoked device attestation"
    } else if previous.is_none() {
        "Linked device attestation"
    } else if *attestation != *previous.unwrap() {
        "Updated device attestation"
    } else {
        "Updated device attestation record (no change detected)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_core::storage::keychain::IdentityDID;
    use auths_verifier::core::{Ed25519PublicKey, Ed25519Signature, ResourceId};
    use auths_verifier::types::DeviceDID;
    use chrono::Utc;

    fn make_attestation(subject: &str, revoked: bool) -> Attestation {
        Attestation {
            version: 1,
            rid: ResourceId::new("test-rid"),
            issuer: IdentityDID::new("did:keri:EIssuer"),
            subject: DeviceDID::new(subject),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: if revoked { Some(Utc::now()) } else { None },
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        }
    }

    #[test]
    fn first_attestation_returns_linked() {
        let att = make_attestation("did:key:z1", false);
        assert_eq!(
            determine_commit_message(&att, None),
            "Linked device attestation"
        );
    }

    #[test]
    fn revocation_returns_revoked() {
        let att = make_attestation("did:key:z1", true);
        let prev = make_attestation("did:key:z1", false);
        assert_eq!(
            determine_commit_message(&att, Some(&prev)),
            "Revoked device attestation"
        );
    }

    #[test]
    fn changed_attestation_returns_updated() {
        let att = make_attestation("did:key:z1", false);
        let mut prev = make_attestation("did:key:z1", false);
        prev.rid = ResourceId::new("different-rid");
        assert_eq!(
            determine_commit_message(&att, Some(&prev)),
            "Updated device attestation"
        );
    }

    #[test]
    fn identical_attestation_returns_no_change() {
        let att = make_attestation("did:key:z1", false);
        let prev = att.clone();
        assert_eq!(
            determine_commit_message(&att, Some(&prev)),
            "Updated device attestation record (no change detected)"
        );
    }

    #[test]
    fn already_revoked_stays_revoked_message() {
        let att = make_attestation("did:key:z1", true);
        let prev = att.clone();
        assert_eq!(
            determine_commit_message(&att, Some(&prev)),
            "Updated device attestation record (no change detected)"
        );
    }
}
