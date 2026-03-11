//! AllowedSigners management — structured SSH allowed_signers file operations.

use std::fmt;
use std::path::{Path, PathBuf};

use auths_core::error::AuthsErrorInfo;
use auths_id::error::StorageError;
use auths_id::storage::attestation::AttestationSource;
use auths_verifier::core::Ed25519PublicKey;
use auths_verifier::types::DeviceDID;
use serde::{Deserialize, Serialize};
use ssh_key::PublicKey as SshPublicKey;
use thiserror::Error;

use super::git_integration::public_key_to_ssh;

// ── Section markers ────────────────────────────────────────────────

const MANAGED_HEADER: &str = "# auths:managed — do not edit manually";
const ATTESTATION_MARKER: &str = "# auths:attestation";
const MANUAL_MARKER: &str = "# auths:manual";

// ── Types ──────────────────────────────────────────────────────────

/// A single entry in an AllowedSigners file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignerEntry {
    /// The principal (email or DID) that identifies this signer.
    pub principal: SignerPrincipal,
    /// The Ed25519 public key for this signer.
    pub public_key: Ed25519PublicKey,
    /// Whether this entry is attestation-managed or user-added.
    pub source: SignerSource,
}

/// The principal (identity) associated with a signer entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignerPrincipal {
    /// A device DID-derived principal (from attestation without email payload).
    DeviceDid(DeviceDID),
    /// An email address principal (from manual entry or attestation with email).
    Email(EmailAddress),
}

impl fmt::Display for SignerPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceDid(did) => {
                let did_str = did.as_str();
                let local_part = did_str.strip_prefix("did:key:").unwrap_or(did_str);
                write!(f, "{}@auths.local", local_part)
            }
            Self::Email(addr) => write!(f, "{}", addr),
        }
    }
}

/// Whether a signer entry is auto-managed (attestation) or user-added (manual).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignerSource {
    /// Managed by `sync()`, regenerated from attestation storage.
    Attestation,
    /// User-added, preserved across `sync()` operations.
    Manual,
}

/// Validated email address with basic sanity checking.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Creates a validated email address.
    ///
    /// Args:
    /// * `email`: The email string to validate.
    ///
    /// Usage:
    /// ```ignore
    /// let addr = EmailAddress::new("user@example.com")?;
    /// ```
    pub fn new(email: &str) -> Result<Self, AllowedSignersError> {
        if email.len() > 254 {
            return Err(AllowedSignersError::InvalidEmail(
                "exceeds 254 characters".to_string(),
            ));
        }
        if email.contains('\0') || email.contains('\n') || email.contains('\r') {
            return Err(AllowedSignersError::InvalidEmail(
                "contains null byte or newline".to_string(),
            ));
        }
        if email.chars().any(|c| c.is_whitespace()) {
            return Err(AllowedSignersError::InvalidEmail(
                "contains whitespace".to_string(),
            ));
        }
        let parts: Vec<&str> = email.splitn(2, '@').collect();
        if parts.len() != 2 {
            return Err(AllowedSignersError::InvalidEmail(
                "missing @ symbol".to_string(),
            ));
        }
        let (local, domain) = (parts[0], parts[1]);
        if local.is_empty() {
            return Err(AllowedSignersError::InvalidEmail(
                "empty local part".to_string(),
            ));
        }
        if domain.is_empty() {
            return Err(AllowedSignersError::InvalidEmail(
                "empty domain part".to_string(),
            ));
        }
        if !domain.contains('.') {
            return Err(AllowedSignersError::InvalidEmail(
                "domain must contain a dot".to_string(),
            ));
        }
        Ok(Self(email.to_string()))
    }

    /// Returns the email as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for EmailAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EmailAddress {
    type Error = AllowedSignersError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

/// Report returned by `AllowedSigners::sync()`.
#[derive(Debug, Clone, Serialize)]
pub struct SyncReport {
    /// Number of attestation entries added in this sync.
    pub added: usize,
    /// Number of stale attestation entries removed.
    pub removed: usize,
    /// Number of manual entries preserved untouched.
    pub preserved: usize,
}

// ── Errors ─────────────────────────────────────────────────────────

/// Errors from allowed_signers file operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AllowedSignersError {
    /// Email address validation failed.
    #[error("invalid email address: {0}")]
    InvalidEmail(String),

    /// SSH key parsing or encoding failed.
    #[error("invalid SSH key: {0}")]
    InvalidKey(String),

    /// Could not read the allowed_signers file.
    #[error("failed to read {path}: {source}")]
    FileRead {
        /// Path to the file that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Could not write the allowed_signers file.
    #[error("failed to write {path}: {source}")]
    FileWrite {
        /// Path to the file that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A line in the file could not be parsed.
    #[error("line {line}: {detail}")]
    ParseError {
        /// 1-based line number of the malformed entry.
        line: usize,
        /// Description of the parse error.
        detail: String,
    },

    /// An entry with this principal already exists.
    #[error("principal already exists: {0}")]
    DuplicatePrincipal(String),

    /// Attempted to remove an attestation-managed entry.
    #[error("cannot remove attestation-managed entry: {0}")]
    AttestationEntryProtected(String),

    /// Attestation storage operation failed.
    #[error("attestation storage error: {0}")]
    Storage(#[from] StorageError),
}

impl AuthsErrorInfo for AllowedSignersError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidEmail(_) => "AUTHS_INVALID_EMAIL",
            Self::InvalidKey(_) => "AUTHS_INVALID_SSH_KEY",
            Self::FileRead { .. } => "AUTHS_SIGNERS_FILE_READ",
            Self::FileWrite { .. } => "AUTHS_SIGNERS_FILE_WRITE",
            Self::ParseError { .. } => "AUTHS_SIGNERS_PARSE_ERROR",
            Self::DuplicatePrincipal(_) => "AUTHS_DUPLICATE_PRINCIPAL",
            Self::AttestationEntryProtected(_) => "AUTHS_ATTESTATION_ENTRY_PROTECTED",
            Self::Storage(_) => "AUTHS_SIGNERS_STORAGE_ERROR",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InvalidEmail(_) => Some("Email must be in user@domain.tld format"),
            Self::InvalidKey(_) => {
                Some("Key must be a valid ssh-ed25519 public key (ssh-ed25519 AAAA...)")
            }
            Self::FileRead { .. } => Some("Check file exists and has correct permissions"),
            Self::FileWrite { .. } => Some("Check directory exists and has write permissions"),
            Self::ParseError { .. } => Some(
                "Check the allowed_signers file format: <email> namespaces=\"git\" ssh-ed25519 <key>",
            ),
            Self::DuplicatePrincipal(_) => {
                Some("Remove the existing entry first with `auths signers remove`")
            }
            Self::AttestationEntryProtected(_) => Some(
                "Attestation entries are managed by `auths signers sync` — revoke the attestation instead",
            ),
            Self::Storage(_) => Some("Check the auths repository at ~/.auths"),
        }
    }
}

// ── AllowedSigners struct ──────────────────────────────────────────

/// Manages an SSH allowed_signers file with attestation and manual sections.
pub struct AllowedSigners {
    entries: Vec<SignerEntry>,
    file_path: PathBuf,
}

impl AllowedSigners {
    /// Creates an empty AllowedSigners bound to a file path.
    pub fn new(file_path: impl Into<PathBuf>) -> Self {
        Self {
            entries: Vec::new(),
            file_path: file_path.into(),
        }
    }

    /// Loads and parses an allowed_signers file via the given store.
    ///
    /// If the file doesn't exist, returns an empty instance.
    /// Files without section markers are treated as all-manual entries.
    ///
    /// Args:
    /// * `path`: Path to the allowed_signers file.
    /// * `store`: I/O backend for reading the file.
    ///
    /// Usage:
    /// ```ignore
    /// let signers = AllowedSigners::load("~/.ssh/allowed_signers", &store)?;
    /// ```
    pub fn load(
        path: impl Into<PathBuf>,
        store: &dyn crate::ports::allowed_signers::AllowedSignersStore,
    ) -> Result<Self, AllowedSignersError> {
        let path = path.into();
        let content = match store.read(&path)? {
            Some(c) => c,
            None => return Ok(Self::new(path)),
        };
        let mut signers = Self::new(path);
        signers.parse_content(&content)?;
        Ok(signers)
    }

    /// Atomically writes the allowed_signers file via the given store.
    ///
    /// Args:
    /// * `store`: I/O backend for writing the file.
    ///
    /// Usage:
    /// ```ignore
    /// signers.save(&store)?;
    /// ```
    pub fn save(
        &self,
        store: &dyn crate::ports::allowed_signers::AllowedSignersStore,
    ) -> Result<(), AllowedSignersError> {
        let content = self.format_content();
        store.write(&self.file_path, &content)
    }

    /// Returns all signer entries.
    pub fn list(&self) -> &[SignerEntry] {
        &self.entries
    }

    /// Returns the file path this instance is bound to.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Adds a new signer entry. Rejects duplicates by principal.
    pub fn add(
        &mut self,
        principal: SignerPrincipal,
        pubkey: Ed25519PublicKey,
        source: SignerSource,
    ) -> Result<(), AllowedSignersError> {
        let principal_str = principal.to_string();
        if self.entries.iter().any(|e| e.principal == principal) {
            return Err(AllowedSignersError::DuplicatePrincipal(principal_str));
        }
        self.entries.push(SignerEntry {
            principal,
            public_key: pubkey,
            source,
        });
        Ok(())
    }

    /// Removes a manual entry by principal. Returns true if an entry was removed.
    pub fn remove(&mut self, principal: &SignerPrincipal) -> Result<bool, AllowedSignersError> {
        if let Some(entry) = self.entries.iter().find(|e| &e.principal == principal)
            && entry.source == SignerSource::Attestation
        {
            return Err(AllowedSignersError::AttestationEntryProtected(
                principal.to_string(),
            ));
        }
        let before = self.entries.len();
        self.entries.retain(|e| &e.principal != principal);
        Ok(self.entries.len() < before)
    }

    /// Regenerates attestation entries from storage, preserving manual entries.
    pub fn sync(
        &mut self,
        storage: &dyn AttestationSource,
    ) -> Result<SyncReport, AllowedSignersError> {
        let manual_count = self
            .entries
            .iter()
            .filter(|e| e.source == SignerSource::Manual)
            .count();

        let old_attestation_count = self
            .entries
            .iter()
            .filter(|e| e.source == SignerSource::Attestation)
            .count();

        self.entries.retain(|e| e.source == SignerSource::Manual);

        let attestations = storage.load_all_attestations()?;
        let mut new_entries: Vec<SignerEntry> = attestations
            .iter()
            .filter(|att| !att.is_revoked())
            .map(|att| {
                let principal = principal_from_attestation(att);
                SignerEntry {
                    principal,
                    public_key: att.device_public_key,
                    source: SignerSource::Attestation,
                }
            })
            .collect();

        new_entries.sort_by(|a, b| a.principal.to_string().cmp(&b.principal.to_string()));
        new_entries.dedup_by(|a, b| a.principal == b.principal);

        let added = new_entries.len();
        for (i, entry) in new_entries.into_iter().enumerate() {
            self.entries.insert(i, entry);
        }

        Ok(SyncReport {
            added,
            removed: old_attestation_count,
            preserved: manual_count,
        })
    }

    // ── Private helpers ────────────────────────────────────────────

    fn parse_content(&mut self, content: &str) -> Result<(), AllowedSignersError> {
        let has_markers = content.contains(ATTESTATION_MARKER) || content.contains(MANUAL_MARKER);
        let mut current_source = if has_markers {
            None
        } else {
            Some(SignerSource::Manual)
        };

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed == ATTESTATION_MARKER || trimmed.starts_with(ATTESTATION_MARKER) {
                current_source = Some(SignerSource::Attestation);
                continue;
            }
            if trimmed == MANUAL_MARKER || trimmed.starts_with(MANUAL_MARKER) {
                current_source = Some(SignerSource::Manual);
                continue;
            }

            if trimmed.starts_with('#') {
                continue;
            }

            let source = match current_source {
                Some(s) => s,
                None => continue,
            };

            let entry = parse_entry_line(trimmed, line_num + 1, source)?;
            self.entries.push(entry);
        }
        Ok(())
    }

    fn format_content(&self) -> String {
        let mut out = String::new();
        out.push_str(MANAGED_HEADER);
        out.push('\n');

        out.push_str(ATTESTATION_MARKER);
        out.push('\n');
        for entry in &self.entries {
            if entry.source == SignerSource::Attestation {
                out.push_str(&format_entry(entry));
                out.push('\n');
            }
        }

        out.push_str(MANUAL_MARKER);
        out.push('\n');
        for entry in &self.entries {
            if entry.source == SignerSource::Manual {
                out.push_str(&format_entry(entry));
                out.push('\n');
            }
        }

        out
    }
}

// ── Free functions ─────────────────────────────────────────────────

fn principal_from_attestation(att: &auths_verifier::core::Attestation) -> SignerPrincipal {
    if let Some(ref payload) = att.payload
        && let Some(email) = payload.get("email").and_then(|v| v.as_str())
        && !email.is_empty()
        && let Ok(addr) = EmailAddress::new(email)
    {
        return SignerPrincipal::Email(addr);
    }
    SignerPrincipal::DeviceDid(att.subject.clone())
}

fn parse_entry_line(
    line: &str,
    line_num: usize,
    source: SignerSource,
) -> Result<SignerEntry, AllowedSignersError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(AllowedSignersError::ParseError {
            line: line_num,
            detail: "expected at least: <principal> <key-type> <base64-key>".to_string(),
        });
    }

    let principal_str = parts[0];

    let key_type_idx = parts
        .iter()
        .position(|&p| p == "ssh-ed25519")
        .ok_or_else(|| AllowedSignersError::ParseError {
            line: line_num,
            detail: "only ssh-ed25519 keys are supported".to_string(),
        })?;

    if key_type_idx + 1 >= parts.len() {
        return Err(AllowedSignersError::ParseError {
            line: line_num,
            detail: "missing base64 key data after ssh-ed25519".to_string(),
        });
    }

    let key_data = parts[key_type_idx + 1];
    let openssh_str = format!("ssh-ed25519 {}", key_data);

    let ssh_pk =
        SshPublicKey::from_openssh(&openssh_str).map_err(|e| AllowedSignersError::ParseError {
            line: line_num,
            detail: format!("invalid SSH key: {}", e),
        })?;

    let raw_bytes = match ssh_pk.key_data() {
        ssh_key::public::KeyData::Ed25519(ed) => ed.0,
        _ => {
            return Err(AllowedSignersError::ParseError {
                line: line_num,
                detail: "expected Ed25519 key".to_string(),
            });
        }
    };

    let public_key = Ed25519PublicKey::from_bytes(raw_bytes);
    let principal = parse_principal(principal_str);

    Ok(SignerEntry {
        principal,
        public_key,
        source,
    })
}

fn parse_principal(s: &str) -> SignerPrincipal {
    if let Some(local) = s.strip_suffix("@auths.local") {
        let did_str = format!("did:key:{}", local);
        return SignerPrincipal::DeviceDid(DeviceDID::new(did_str));
    }
    if s.starts_with("did:key:") {
        return SignerPrincipal::DeviceDid(DeviceDID::new(s));
    }
    match EmailAddress::new(s) {
        Ok(addr) => SignerPrincipal::Email(addr),
        Err(_) => SignerPrincipal::DeviceDid(DeviceDID::new(s)),
    }
}

fn format_entry(entry: &SignerEntry) -> String {
    #[allow(clippy::expect_used)] // INVARIANT: Ed25519PublicKey is always 32 valid bytes
    let ssh_key = public_key_to_ssh(entry.public_key.as_bytes())
        .expect("Ed25519PublicKey always encodes to valid SSH key");
    format!("{} namespaces=\"git\" {}", entry.principal, ssh_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_valid() {
        assert!(EmailAddress::new("user@example.com").is_ok());
        assert!(EmailAddress::new("a@b.co").is_ok());
        assert!(EmailAddress::new("test+tag@domain.org").is_ok());
    }

    #[test]
    fn email_invalid() {
        assert!(EmailAddress::new("").is_err());
        assert!(EmailAddress::new("@").is_err());
        assert!(EmailAddress::new("user@").is_err());
        assert!(EmailAddress::new("@domain.com").is_err());
        assert!(EmailAddress::new("user@domain").is_err());
        assert!(EmailAddress::new("invalid").is_err());
    }

    #[test]
    fn email_injection_defense() {
        assert!(EmailAddress::new("a\0b@evil.com").is_err());
        assert!(EmailAddress::new("a\n@evil.com").is_err());
        assert!(EmailAddress::new("a b@evil.com").is_err());
    }

    #[test]
    fn principal_display_email() {
        let p = SignerPrincipal::Email(EmailAddress::new("user@example.com").unwrap());
        assert_eq!(p.to_string(), "user@example.com");
    }

    #[test]
    fn principal_display_did() {
        let did = DeviceDID::new("did:key:z6MkTest123");
        let p = SignerPrincipal::DeviceDid(did);
        assert_eq!(p.to_string(), "z6MkTest123@auths.local");
    }

    #[test]
    fn principal_roundtrip() {
        let email_p = SignerPrincipal::Email(EmailAddress::new("user@example.com").unwrap());
        let parsed = parse_principal(&email_p.to_string());
        assert_eq!(parsed, email_p);

        let did = DeviceDID::new("did:key:z6MkTest123");
        let did_p = SignerPrincipal::DeviceDid(did);
        let parsed = parse_principal(&did_p.to_string());
        assert_eq!(parsed, did_p);
    }

    #[test]
    fn error_codes_and_suggestions() {
        let err = AllowedSignersError::InvalidEmail("test".to_string());
        assert_eq!(err.error_code(), "AUTHS_INVALID_EMAIL");
        assert!(err.suggestion().is_some());
    }
}
