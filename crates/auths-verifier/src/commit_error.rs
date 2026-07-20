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

    /// The commit uses a GPG signature, which Auths does not verify.
    #[error("GPG signatures are not verified by Auths — use did:keri trailers via `auths init`")]
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

    /// The signer's identity is not trusted (no matching pinned root).
    #[error("signer identity is not trusted (no matching pinned root)")]
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
            Self::UnsignedCommit => Some(
                "This commit has no Auths-Id/Auths-Device trailer. Run `auths init` so the \
                 prepare-commit-msg hook signs future commits, or backfill with `auths sign <ref>`.",
            ),
            Self::GpgNotSupported => Some(
                "Auths verifies its own did:keri commit trailers, not GPG or SSH signatures. \
                 Run `auths init` to enable Auths signing.",
            ),
            Self::UnsupportedKeyType { .. } => {
                Some("Use an Ed25519 or ECDSA P-256 SSH key for signing")
            }
            Self::UnknownSigner => Some(
                "The signer's identity is not trusted here. Pin it with `auths trust pin --did <did>`, \
                 or add it to .auths/roots.",
            ),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_advice_is_gone() {
        // The pre-KEL SSH/GPG advice would send a user to produce a commit `auths
        // verify` still rejects. Every commit-verification suggestion must speak the
        // KEL-native flow (`auths <verb>`) and name none of the retired mechanisms.
        let retired = ["git commit -S", "gpg.format", "allowed signers"];
        for err in [
            CommitVerificationError::UnsignedCommit,
            CommitVerificationError::GpgNotSupported,
            CommitVerificationError::UnknownSigner,
        ] {
            let suggestion = err.suggestion().expect("headline verdicts carry advice");
            for phrase in retired {
                assert!(
                    !suggestion.contains(phrase),
                    "{} still advises `{phrase}`: {suggestion}",
                    err.error_code()
                );
            }
            assert!(
                suggestion.contains("auths "),
                "{} must speak the KEL-native flow: {suggestion}",
                err.error_code()
            );
        }
    }
}
