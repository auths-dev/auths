//! Git commit SSH signature extraction and verification.
//!
//! Provides native Rust verification of SSH-signed git commits,
//! replacing the `ssh-keygen -Y verify` subprocess pipeline.

use std::path::Path;

use sha2::{Digest, Sha256, Sha512};

use crate::commit_error::CommitVerificationError;
use crate::core::DevicePublicKey;
use crate::ssh_sig::parse_sshsig_pem;

/// A successfully verified commit signature.
///
/// Usage:
/// ```ignore
/// let verified = verify_commit_signature(content, &keys, provider, None).await?;
/// println!("Signed by: {}", hex::encode(verified.signer_key.as_bytes()));
/// ```
#[derive(Debug)]
pub struct VerifiedCommit {
    /// The public key that produced the valid signature (Ed25519 or P-256).
    pub signer_key: DevicePublicKey,
}

/// Verify an SSH-signed git commit against a list of allowed keys.
///
/// Supports both Ed25519 and ECDSA P-256 signatures. The key type is
/// auto-detected from the SSHSIG envelope.
///
/// Args:
/// * `commit_content`: Raw output of `git cat-file commit <sha>`.
/// * `allowed_keys`: Public keys authorized to sign (Ed25519 or P-256).
/// * `provider`: Crypto backend for Ed25519 verification.
/// * `repo_path`: Optional path to the git repository.
///
/// Usage:
/// ```ignore
/// let verified = verify_commit_signature(content, &keys, &provider, Some(Path::new("/repo"))).await?;
/// ```
pub async fn verify_commit_signature(
    commit_content: &[u8],
    allowed_keys: &[DevicePublicKey],
    provider: &dyn auths_crypto::CryptoProvider,
    _repo_path: Option<&Path>,
) -> Result<VerifiedCommit, CommitVerificationError> {
    let content_str = std::str::from_utf8(commit_content)
        .map_err(|e| CommitVerificationError::CommitParseFailed(format!("invalid UTF-8: {e}")))?;

    if content_str.contains("-----BEGIN PGP SIGNATURE-----") {
        return Err(CommitVerificationError::GpgNotSupported);
    }

    let extracted = extract_ssh_signature(content_str)?;
    let envelope = parse_sshsig_pem(&extracted.signature_pem)?;

    if envelope.namespace != "git" {
        return Err(CommitVerificationError::NamespaceMismatch {
            expected: "git".into(),
            found: envelope.namespace,
        });
    }

    if !allowed_keys.contains(&envelope.public_key) {
        return Err(CommitVerificationError::UnknownSigner);
    }

    let signed_data = compute_sshsig_signed_data(
        &envelope.namespace,
        &envelope.hash_algorithm,
        extracted.signed_payload.as_bytes(),
    )?;

    match envelope.public_key.curve() {
        auths_crypto::CurveType::Ed25519 => {
            provider
                .verify_ed25519(
                    envelope.public_key.as_bytes(),
                    &signed_data,
                    &envelope.signature,
                )
                .await
                .map_err(|_| CommitVerificationError::SignatureInvalid)?;
        }
        auths_crypto::CurveType::P256 => {
            #[cfg(feature = "native")]
            {
                auths_crypto::RingCryptoProvider::p256_verify(
                    envelope.public_key.as_bytes(),
                    &signed_data,
                    &envelope.signature,
                )
                .map_err(|_| CommitVerificationError::SignatureInvalid)?;
            }
            #[cfg(not(feature = "native"))]
            {
                return Err(CommitVerificationError::SshSigParseFailed(
                    "P-256 verification not available on this platform".into(),
                ));
            }
        }
    }

    Ok(VerifiedCommit {
        signer_key: envelope.public_key,
    })
}

/// Extracted SSH signature and signed payload from a git commit object.
#[derive(Debug)]
pub struct ExtractedSignature {
    /// The SSH signature PEM block.
    pub signature_pem: String,
    /// The commit content with the gpgsig header removed (the signed payload).
    pub signed_payload: String,
}

/// Extract the SSH signature PEM and signed payload from a raw git commit object.
///
/// The signed payload is the commit object with the `gpgsig` header block removed,
/// preserving exact byte content including trailing newlines.
///
/// Args:
/// * `commit_content`: The raw commit object as a string.
///
/// Usage:
/// ```ignore
/// let extracted = extract_ssh_signature(content)?;
/// ```
pub fn extract_ssh_signature(
    commit_content: &str,
) -> Result<ExtractedSignature, CommitVerificationError> {
    if !commit_content.contains("-----BEGIN SSH SIGNATURE-----") {
        return Err(CommitVerificationError::UnsignedCommit);
    }

    let mut sig_lines: Vec<&str> = Vec::new();
    let mut payload = String::with_capacity(commit_content.len());
    let mut in_sig = false;

    let mut remaining = commit_content;
    while !remaining.is_empty() {
        let (line_with_nl, rest) = match remaining.find('\n') {
            Some(i) => (&remaining[..=i], &remaining[i + 1..]),
            None => (remaining, ""),
        };
        remaining = rest;

        let line = line_with_nl.strip_suffix('\n').unwrap_or(line_with_nl);

        if line.starts_with("gpgsig ") {
            in_sig = true;
            sig_lines.push(line.strip_prefix("gpgsig ").unwrap_or(line));
        } else if in_sig && line.starts_with(' ') {
            sig_lines.push(line.strip_prefix(' ').unwrap_or(line));
        } else {
            in_sig = false;
            payload.push_str(line_with_nl);
        }
    }

    if sig_lines.is_empty() {
        return Err(CommitVerificationError::UnsignedCommit);
    }

    let signature_pem = sig_lines.join("\n");

    Ok(ExtractedSignature {
        signature_pem,
        signed_payload: payload,
    })
}

/// Construct the SSHSIG "signed data" blob.
///
/// This is the data that the Ed25519 signature actually covers:
/// ```text
/// "SSHSIG" (6 raw bytes)
/// string  namespace
/// string  reserved (empty)
/// string  hash_algorithm
/// string  H(message)
/// ```
fn compute_sshsig_signed_data(
    namespace: &str,
    hash_algorithm: &str,
    message: &[u8],
) -> Result<Vec<u8>, CommitVerificationError> {
    let hash = match hash_algorithm {
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        other => {
            return Err(CommitVerificationError::HashAlgorithmUnsupported(
                other.into(),
            ));
        }
    };

    let mut blob = Vec::new();

    // Magic preamble (raw bytes, NOT length-prefixed)
    blob.extend_from_slice(b"SSHSIG");

    // Namespace
    blob.extend_from_slice(&(namespace.len() as u32).to_be_bytes());
    blob.extend_from_slice(namespace.as_bytes());

    // Reserved (empty)
    blob.extend_from_slice(&0u32.to_be_bytes());

    // Hash algorithm
    blob.extend_from_slice(&(hash_algorithm.len() as u32).to_be_bytes());
    blob.extend_from_slice(hash_algorithm.as_bytes());

    // Hash of message
    blob.extend_from_slice(&(hash.len() as u32).to_be_bytes());
    blob.extend_from_slice(&hash);

    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED_COMMIT: &str = "tree abc123\n\
        parent def456\n\
        author Test <test@test.com> 1700000000 +0000\n\
        committer Test <test@test.com> 1700000000 +0000\n\
        gpgsig -----BEGIN SSH SIGNATURE-----\n \
        U1NIU0lHAAAAAQ==\n \
        -----END SSH SIGNATURE-----\n\
        \n\
        test commit message\n";

    const UNSIGNED_COMMIT: &str = "tree abc123\n\
        parent def456\n\
        author Test <test@test.com> 1700000000 +0000\n\
        committer Test <test@test.com> 1700000000 +0000\n\
        \n\
        test commit message\n";

    const GPG_COMMIT: &str = "tree abc123\n\
        gpgsig -----BEGIN PGP SIGNATURE-----\n \
        iQEzBAAB\n \
        -----END PGP SIGNATURE-----\n\
        \n\
        test commit message\n";

    #[test]
    fn extract_returns_unsigned_for_plain_commit() {
        let err = extract_ssh_signature(UNSIGNED_COMMIT).unwrap_err();
        assert!(matches!(err, CommitVerificationError::UnsignedCommit));
    }

    #[test]
    fn extract_signature_present() {
        let result = extract_ssh_signature(SIGNED_COMMIT).unwrap();
        assert!(result.signature_pem.contains("BEGIN SSH SIGNATURE"));
        assert!(!result.signed_payload.contains("gpgsig"));
        assert!(result.signed_payload.contains("tree abc123"));
        assert!(result.signed_payload.contains("test commit message"));
    }

    #[test]
    fn extract_preserves_trailing_newline() {
        let result = extract_ssh_signature(SIGNED_COMMIT).unwrap();
        assert!(result.signed_payload.ends_with('\n'));
    }

    #[test]
    fn gpg_commit_detected_by_verify() {
        let content = GPG_COMMIT.as_bytes();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let provider = auths_crypto::RingCryptoProvider;
        let result = rt.block_on(verify_commit_signature(content, &[], &provider, None));
        assert!(matches!(
            result,
            Err(CommitVerificationError::GpgNotSupported)
        ));
    }
}
