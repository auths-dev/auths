//! Error types for commit signature verification.

use thiserror::Error;

use crate::error::AuthsErrorInfo;

/// Errors from commit signature parsing and verification.
///
/// Usage:
/// ```ignore
/// match result {
///     Err(CommitVerificationError::UnsignedCommit) => { /* no signature */ }
///     Err(CommitVerificationError::SignatureInvalid) => { /* bad sig */ }
///     Ok(verified) => { /* success */ }
/// }
/// ```
#[derive(Error, Debug)]
pub enum CommitVerificationError {
    /// The commit has no signature at all.
    #[error("commit is unsigned")]
    UnsignedCommit,

    /// The commit uses a GPG signature, which is not supported.
    #[error("GPG signatures not supported, use SSH signing")]
    GpgNotSupported,

    /// The SSHSIG envelope could not be parsed.
    #[error("SSHSIG parse failed: {0}")]
    SshSigParseFailed(String),

    /// The SSH key type is not supported (must be Ed25519 or ECDSA P-256).
    #[error("unsupported SSH key type: {found}")]
    UnsupportedKeyType {
        /// The key type string found in the envelope.
        found: String,
    },

    /// The SSHSIG namespace does not match the expected value.
    #[error("namespace mismatch: expected \"{expected}\", found \"{found}\"")]
    NamespaceMismatch {
        /// The expected namespace.
        expected: String,
        /// The namespace found in the signature.
        found: String,
    },

    /// The hash algorithm in the SSHSIG envelope is not supported.
    #[error("unsupported hash algorithm: {0}")]
    HashAlgorithmUnsupported(String),

    /// The Ed25519 signature did not verify against the signed data.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// The signer's public key is not in the allowed keys list.
    #[error("signer key not in allowed keys")]
    UnknownSigner,

    /// The raw commit object could not be parsed.
    #[error("commit parse failed: {0}")]
    CommitParseFailed(String),
}

impl AuthsErrorInfo for CommitVerificationError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::UnsignedCommit => "AUTHS-E2101",
            Self::GpgNotSupported => "AUTHS-E2102",
            Self::SshSigParseFailed(_) => "AUTHS-E2103",
            Self::UnsupportedKeyType { .. } => "AUTHS-E2104",
            Self::NamespaceMismatch { .. } => "AUTHS-E2105",
            Self::HashAlgorithmUnsupported(_) => "AUTHS-E2106",
            Self::SignatureInvalid => "AUTHS-E2107",
            Self::UnknownSigner => "AUTHS-E2108",
            Self::CommitParseFailed(_) => "AUTHS-E2109",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::UnsignedCommit => Some("Sign commits with: git commit -S"),
            Self::GpgNotSupported => Some("Configure SSH signing: git config gpg.format ssh"),
            Self::UnsupportedKeyType { .. } => {
                Some("Use an Ed25519 or ECDSA P-256 SSH key for signing")
            }
            Self::UnknownSigner => Some("Add the signer's key to the allowed signers list"),
            Self::SshSigParseFailed(_) => Some(
                "The SSH signature could not be parsed; verify the commit was signed correctly",
            ),
            Self::NamespaceMismatch { .. } => Some(
                "The signature namespace doesn't match; ensure git config gpg.ssh.defaultKeyCommand is set correctly",
            ),
            Self::HashAlgorithmUnsupported(_) => {
                Some("Use SHA-256 or SHA-512 hash algorithm for signing")
            }
            Self::SignatureInvalid => Some(
                "The commit signature does not match the signed data; the commit may have been modified after signing",
            ),
            Self::CommitParseFailed(_) => Some(
                "The Git commit object is malformed; check repository integrity with `git fsck`",
            ),
        }
    }
}
