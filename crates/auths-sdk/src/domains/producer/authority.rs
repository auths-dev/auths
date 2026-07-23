use super::error::AuthorityError;
use auths_keri::KeriPublicKey;
use chrono::{DateTime, Utc};

/// Trait abstraction for identity registry backend lookups.
pub trait RegistryBackend {
    /// Resolves identity DID associated with a hardware or direct public key.
    fn resolve_identity_for_key(&self, key: &KeriPublicKey) -> Result<Option<String>, AuthorityError>;

    /// Checks whether a given key was revoked in the resolved identity KEL at signed_at timestamp.
    fn is_key_revoked_at(
        &self,
        identity_did: &str,
        key: &KeriPublicKey,
        signed_at: DateTime<Utc>,
    ) -> Result<bool, AuthorityError>;
}

/// Validates that a device signing key was authorized and active at the payload's `signed_at` timestamp.
///
/// Args:
/// * `signer_key`: The typed KeriPublicKey being checked.
/// * `signed_at`: The payload's signing timestamp for historical point-in-time check.
/// * `registry`: Reference to the identity registry backend.
///
/// Usage:
/// ```ignore
/// enforce_signer_authority(&pubkey, signed_at, &registry)?;
/// ```
pub fn enforce_signer_authority(
    signer_key: &KeriPublicKey,
    signed_at: DateTime<Utc>,
    registry: &dyn RegistryBackend,
) -> Result<String, AuthorityError> {
    let identity_did = registry
        .resolve_identity_for_key(signer_key)?
        .ok_or_else(|| {
            let key_str = signer_key.to_qb64().unwrap_or_else(|_| "invalid_key".into());
            tracing::warn!(event = "producer_authority_unbound_key", key = %key_str);
            AuthorityError::UnboundKey(format!("Key {} has no associated identity DID", key_str))
        })?;

    if registry.is_key_revoked_at(&identity_did, signer_key, signed_at)? {
        let key_str = signer_key.to_qb64().unwrap_or_else(|_| "invalid_key".into());
        tracing::warn!(
            event = "producer_authority_key_revoked",
            identity_did = %identity_did,
            key = %key_str,
            signed_at = %signed_at.to_rfc3339()
        );
        return Err(AuthorityError::RevokedKey(format!(
            "Signer key {} was revoked prior to or at {}",
            key_str,
            signed_at.to_rfc3339()
        )));
    }

    tracing::info!(
        event = "producer_authority_verified",
        identity_did = %identity_did,
        signed_at = %signed_at.to_rfc3339()
    );

    Ok(identity_did)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRegistry {
        bound_did: Option<String>,
        revoked: bool,
    }

    impl RegistryBackend for MockRegistry {
        fn resolve_identity_for_key(
            &self,
            _key: &KeriPublicKey,
        ) -> Result<Option<String>, AuthorityError> {
            Ok(self.bound_did.clone())
        }

        fn is_key_revoked_at(
            &self,
            _identity_did: &str,
            _key: &KeriPublicKey,
            _signed_at: DateTime<Utc>,
        ) -> Result<bool, AuthorityError> {
            Ok(self.revoked)
        }
    }

    #[test]
    fn test_enforce_authority_valid() {
        let pk = KeriPublicKey::ed25519(&[1u8; 32]).unwrap();
        let reg = MockRegistry {
            bound_did: Some("did:keri:z123".into()),
            revoked: false,
        };
        let res = enforce_signer_authority(&pk, Utc::now(), &reg);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "did:keri:z123");
    }

    #[test]
    fn test_enforce_authority_revoked() {
        let pk = KeriPublicKey::ed25519(&[1u8; 32]).unwrap();
        let reg = MockRegistry {
            bound_did: Some("did:keri:z123".into()),
            revoked: true,
        };
        let res = enforce_signer_authority(&pk, Utc::now(), &reg);
        assert!(res.is_err());
    }
}
