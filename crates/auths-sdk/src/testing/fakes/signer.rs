use auths_core::AgentError;
use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias};

/// Fake [`SecureSigner`] that returns a dummy 64-byte signature.
///
/// Usage:
/// ```ignore
/// let signer = FakeSecureSigner;
/// let sig = signer.sign_with_alias(&alias, &provider, b"msg").unwrap();
/// assert_eq!(sig.len(), 64);
/// ```
pub struct FakeSecureSigner;

impl SecureSigner for FakeSecureSigner {
    fn sign_with_alias(
        &self,
        _alias: &KeyAlias,
        _passphrase_provider: &dyn PassphraseProvider,
        _message: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        Ok(vec![1u8; 64])
    }

    fn sign_for_identity(
        &self,
        _identity_did: &IdentityDID,
        _passphrase_provider: &dyn PassphraseProvider,
        _message: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        Ok(vec![1u8; 64])
    }
}
