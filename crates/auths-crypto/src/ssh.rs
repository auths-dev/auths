//! OpenSSH public key parsing for Ed25519 keys.

use ssh_key::PublicKey;

/// Errors from parsing an OpenSSH Ed25519 public key.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SshKeyError {
    #[error("Malformed or invalid OpenSSH public key: {0}")]
    InvalidFormat(String),

    #[error("Unsupported key type: expected ssh-ed25519")]
    UnsupportedKeyType,
}

impl crate::AuthsErrorInfo for SshKeyError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidFormat(_) => "AUTHS-E1301",
            Self::UnsupportedKeyType => "AUTHS-E1302",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InvalidFormat(_) => Some("Check that the public key is a valid OpenSSH format"),
            Self::UnsupportedKeyType => Some("Only ssh-ed25519 keys are supported"),
        }
    }
}

/// Parse an OpenSSH Ed25519 public key line and return the raw 32-byte public key.
///
/// Args:
/// * `openssh_pub`: A full OpenSSH public key line, e.g. `"ssh-ed25519 AAAA... comment"`.
///
/// Usage:
/// ```ignore
/// let raw = openssh_pub_to_raw_ed25519("ssh-ed25519 AAAA...")?;
/// assert_eq!(raw.len(), 32);
/// ```
pub fn openssh_pub_to_raw_ed25519(openssh_pub: &str) -> Result<[u8; 32], SshKeyError> {
    let public_key = PublicKey::from_openssh(openssh_pub)
        .map_err(|e| SshKeyError::InvalidFormat(e.to_string()))?;

    let ed25519_key = public_key
        .key_data()
        .ed25519()
        .ok_or(SshKeyError::UnsupportedKeyType)?;

    Ok(ed25519_key.0)
}
