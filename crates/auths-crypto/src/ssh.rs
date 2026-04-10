//! OpenSSH public key parsing for Ed25519 and P-256 keys.

use ssh_key::PublicKey;

/// Errors from parsing an OpenSSH public key.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SshKeyError {
    #[error("Malformed or invalid OpenSSH public key: {0}")]
    InvalidFormat(String),

    #[error("Unsupported key type: expected ssh-ed25519 or ecdsa-sha2-nistp256")]
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
            Self::UnsupportedKeyType => {
                Some("Supported key types: ssh-ed25519, ecdsa-sha2-nistp256")
            }
        }
    }
}

/// Parse an OpenSSH public key line and return the curve type and raw key bytes.
///
/// Supports `ssh-ed25519` (returns 32-byte key) and `ecdsa-sha2-nistp256`
/// (returns 33-byte compressed SEC1 point).
///
/// Args:
/// * `openssh_pub`: A full OpenSSH public key line, e.g. `"ssh-ed25519 AAAA... comment"`.
///
/// Usage:
/// ```ignore
/// let (curve, raw) = openssh_pub_to_raw("ssh-ed25519 AAAA...")?;
/// assert_eq!(curve, CurveType::Ed25519);
/// assert_eq!(raw.len(), 32);
/// ```
pub fn openssh_pub_to_raw(openssh_pub: &str) -> Result<(crate::CurveType, Vec<u8>), SshKeyError> {
    let public_key = PublicKey::from_openssh(openssh_pub)
        .map_err(|e| SshKeyError::InvalidFormat(e.to_string()))?;

    if let Some(ed) = public_key.key_data().ed25519() {
        return Ok((crate::CurveType::Ed25519, ed.0.to_vec()));
    }

    if let Some(ssh_key::public::EcdsaPublicKey::NistP256(point)) = public_key.key_data().ecdsa() {
        return Ok((crate::CurveType::P256, point.as_ref().to_vec()));
    }

    Err(SshKeyError::UnsupportedKeyType)
}

/// Parse an OpenSSH Ed25519 public key line and return the raw 32-byte public key.
#[deprecated(note = "use openssh_pub_to_raw() which returns (CurveType, Vec<u8>)")]
pub fn openssh_pub_to_raw_ed25519(openssh_pub: &str) -> Result<[u8; 32], SshKeyError> {
    let (curve, bytes) = openssh_pub_to_raw(openssh_pub)?;
    if curve != crate::CurveType::Ed25519 {
        return Err(SshKeyError::UnsupportedKeyType);
    }
    bytes
        .try_into()
        .map_err(|_| SshKeyError::InvalidFormat("expected 32 bytes".into()))
}
