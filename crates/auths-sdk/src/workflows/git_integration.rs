//! Git allowed-signers file computation from device attestations.

use auths_id::error::StorageError;
use auths_id::storage::attestation::AttestationSource;
use auths_verifier::core::Attestation;
use ssh_key::PublicKey as SshPublicKey;
use ssh_key::public::Ed25519PublicKey;
use thiserror::Error;

/// A single entry in a Git allowed_signers file.
#[derive(Debug, Clone)]
pub struct AllowedSignerEntry {
    /// Email or principal used by Git to identify the signer.
    pub principal: String,
    /// OpenSSH public key string (e.g. `"ssh-ed25519 AAAA..."`).
    pub ssh_public_key: String,
}

/// Errors that can occur during Git integration operations.
#[derive(Debug, Error)]
pub enum GitIntegrationError {
    /// Attestation storage could not be read.
    #[error("failed to load attestations: {0}")]
    Storage(#[from] StorageError),
    /// Raw public key bytes have an unexpected length.
    #[error("invalid Ed25519 public key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
    /// SSH key encoding failed.
    #[error("failed to encode SSH public key: {0}")]
    SshKeyEncoding(String),
}

/// Compute the list of allowed-signer entries from an attestation source.
///
/// Skips revoked attestations and devices whose public key cannot be
/// parsed; those are silently dropped.
///
/// Args:
/// * `source`: Attestation storage backend.
///
/// Usage:
/// ```ignore
/// let entries = generate_allowed_signers(&storage)?;
/// let file_content = format_allowed_signers_file(&entries);
/// ```
pub fn generate_allowed_signers(
    source: &dyn AttestationSource,
) -> Result<Vec<AllowedSignerEntry>, GitIntegrationError> {
    let attestations = source.load_all_attestations()?;
    let mut entries: Vec<AllowedSignerEntry> = attestations
        .iter()
        .filter(|att| !att.is_revoked())
        .filter_map(|att| {
            let ssh_key = public_key_to_ssh(att.device_public_key.as_bytes()).ok()?;
            Some(AllowedSignerEntry {
                principal: principal_for(att),
                ssh_public_key: ssh_key,
            })
        })
        .collect();
    entries.sort_by(|a, b| a.principal.cmp(&b.principal));
    entries.dedup_by(|a, b| a.principal == b.principal && a.ssh_public_key == b.ssh_public_key);
    Ok(entries)
}

/// Format a list of `AllowedSignerEntry` values as an `allowed_signers` file.
///
/// Each line has the form `<principal> namespaces="git" <ssh-key>`.
/// Returns an empty string when `entries` is empty, otherwise the file
/// ends with a trailing newline.
///
/// Args:
/// * `entries`: Computed allowed-signer entries.
///
/// Usage:
/// ```ignore
/// let content = format_allowed_signers_file(&entries);
/// std::fs::write(path, content)?;
/// ```
pub fn format_allowed_signers_file(entries: &[AllowedSignerEntry]) -> String {
    if entries.is_empty() {
        return String::new();
    }
    let lines: Vec<String> = entries
        .iter()
        .map(|e| format!("{} namespaces=\"git\" {}", e.principal, e.ssh_public_key))
        .collect();
    format!("{}\n", lines.join("\n"))
}

/// Convert raw Ed25519 public key bytes to an OpenSSH public key string.
///
/// Args:
/// * `public_key_bytes`: 32-byte Ed25519 public key.
///
/// Usage:
/// ```ignore
/// let openssh = public_key_to_ssh(&bytes)?;
/// ```
pub fn public_key_to_ssh(public_key_bytes: &[u8]) -> Result<String, GitIntegrationError> {
    if public_key_bytes.len() != 32 {
        return Err(GitIntegrationError::InvalidKeyLength(
            public_key_bytes.len(),
        ));
    }
    let ed25519_pk = Ed25519PublicKey::try_from(public_key_bytes)
        .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))?;
    let ssh_pk = SshPublicKey::from(ed25519_pk);
    ssh_pk
        .to_openssh()
        .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))
}

fn principal_for(att: &Attestation) -> String {
    if let Some(ref payload) = att.payload
        && let Some(email) = payload.get("email").and_then(|v| v.as_str())
        && !email.is_empty()
    {
        return email.to_string();
    }
    let did_str = att.subject.to_string();
    let local_part = did_str.strip_prefix("did:key:").unwrap_or(&did_str);
    format!("{}@auths.local", local_part)
}
