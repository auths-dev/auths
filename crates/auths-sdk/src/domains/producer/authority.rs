use super::error::AuthorityError;

/// Trait abstraction for identity registry backend lookups.
pub trait RegistryBackend {
    /// Resolves identity DID associated with a hardware or direct public key.
    fn resolve_identity_for_key(&self, key_hex: &str) -> Result<Option<String>, AuthorityError>;

    /// Checks whether a given key has been revoked in the resolved identity KEL.
    fn is_key_revoked(&self, identity_did: &str, key_hex: &str) -> Result<bool, AuthorityError>;
}

/// Validates that a device signing key is authorized and not revoked in the identity KEL (Issue #355).
///
/// Args:
/// * `signer_key_hex`: The hex-encoded device public key being checked.
/// * `registry`: Reference to the identity registry backend.
///
/// Usage:
/// ```ignore
/// enforce_signer_authority(&device_key_hex, &registry)?;
/// ```
pub fn enforce_signer_authority(
    signer_key_hex: &str,
    registry: &dyn RegistryBackend,
) -> Result<String, AuthorityError> {
    let identity_did = registry
        .resolve_identity_for_key(signer_key_hex)?
        .ok_or_else(|| {
            AuthorityError::UnboundKey(format!(
                "Key {} has no associated identity DID",
                signer_key_hex
            ))
        })?;

    if registry.is_key_revoked(&identity_did, signer_key_hex)? {
        return Err(AuthorityError::RevokedKey(format!(
            "Signer key {} has been revoked",
            signer_key_hex
        )));
    }

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
            _key_hex: &str,
        ) -> Result<Option<String>, AuthorityError> {
            Ok(self.bound_did.clone())
        }

        fn is_key_revoked(
            &self,
            _identity_did: &str,
            _key_hex: &str,
        ) -> Result<bool, AuthorityError> {
            Ok(self.revoked)
        }
    }

    #[test]
    fn test_enforce_authority_valid() {
        let reg = MockRegistry {
            bound_did: Some("did:keri:z123".into()),
            revoked: false,
        };
        let res = enforce_signer_authority("01020304", &reg);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "did:keri:z123");
    }

    #[test]
    fn test_enforce_authority_revoked() {
        let reg = MockRegistry {
            bound_did: Some("did:keri:z123".into()),
            revoked: true,
        };
        let res = enforce_signer_authority("01020304", &reg);
        assert!(res.is_err());
    }
}
