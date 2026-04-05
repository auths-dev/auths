//! CI token format for bundling all signing/verification secrets into one portable JSON blob.

use super::error::CiError;
use serde::{Deserialize, Serialize};

/// Current token format version.
const CURRENT_VERSION: u32 = 1;

/// Size threshold (bytes) above which a warning is emitted about GitHub secrets limits.
const SIZE_WARNING_THRESHOLD: usize = 40_960; // 40 KB

/// Single portable token containing everything CI needs for signing and verification.
///
/// Set as one GitHub/GitLab/etc secret (`AUTHS_CI_TOKEN`). The CLI produces it;
/// the sign/verify actions consume it. Users never see the internals.
///
/// Args:
/// * `version`: Format version for forward compatibility (currently 1).
/// * `passphrase`: Passphrase for the CI device key.
/// * `keychain`: Base64-encoded encrypted keychain file (file-backend).
/// * `identity_repo`: Base64-encoded tar.gz of `~/.auths` (flat format).
/// * `verify_bundle`: Identity bundle JSON for verification.
/// * `created_at`: ISO 8601 timestamp of when this token was created.
/// * `max_valid_for_secs`: Max age of the verify bundle in seconds.
///
/// Usage:
/// ```ignore
/// let token = CiToken::new(passphrase, keychain_b64, repo_b64, bundle_json, 31536000);
/// let json = token.to_json()?;
/// let parsed = CiToken::from_json(&json)?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiToken {
    /// Format version for forward compatibility.
    pub version: u32,

    /// Passphrase for the CI device key.
    pub passphrase: String,

    /// Base64-encoded encrypted keychain file (file-backend).
    pub keychain: String,

    /// Base64-encoded tar.gz of `~/.auths` (flat format: contents at root, no `.auths/` prefix).
    pub identity_repo: String,

    /// Identity bundle JSON for verification (output of `auths id export-bundle`).
    pub verify_bundle: serde_json::Value,

    /// When this token was created (ISO 8601).
    pub created_at: String,

    /// Max age of the verify bundle in seconds.
    pub max_valid_for_secs: u64,
}

impl CiToken {
    /// Create a new `CiToken` with the current version and timestamp.
    ///
    /// Args:
    /// * `passphrase`: Passphrase for the CI device key.
    /// * `keychain`: Base64-encoded encrypted keychain.
    /// * `identity_repo`: Base64-encoded tar.gz of the identity repo.
    /// * `verify_bundle`: Verify bundle JSON value.
    /// * `created_at`: ISO 8601 timestamp string.
    /// * `max_valid_for_secs`: TTL for the verify bundle.
    ///
    /// Usage:
    /// ```ignore
    /// let token = CiToken::new(pass, kc, repo, bundle, now_str, 31536000);
    /// ```
    pub fn new(
        passphrase: String,
        keychain: String,
        identity_repo: String,
        verify_bundle: serde_json::Value,
        created_at: String,
        max_valid_for_secs: u64,
    ) -> Self {
        Self {
            version: CURRENT_VERSION,
            passphrase,
            keychain,
            identity_repo,
            verify_bundle,
            created_at,
            max_valid_for_secs,
        }
    }

    /// Serialize this token to a JSON string.
    ///
    /// Usage:
    /// ```ignore
    /// let json_str = token.to_json()?;
    /// ```
    pub fn to_json(&self) -> Result<String, CiError> {
        serde_json::to_string(self).map_err(|e| CiError::TokenSerializationFailed {
            reason: e.to_string(),
        })
    }

    /// Deserialize a token from a JSON string, validating the version.
    ///
    /// Args:
    /// * `json`: JSON string representing a `CiToken`.
    ///
    /// Usage:
    /// ```ignore
    /// let token = CiToken::from_json(&json_str)?;
    /// ```
    pub fn from_json(json: &str) -> Result<Self, CiError> {
        let token: Self =
            serde_json::from_str(json).map_err(|e| CiError::TokenDeserializationFailed {
                reason: e.to_string(),
            })?;

        if token.version != CURRENT_VERSION {
            return Err(CiError::TokenVersionUnsupported {
                version: token.version,
            });
        }

        Ok(token)
    }

    /// Estimate the byte size of this token when serialized to JSON.
    ///
    /// Usage:
    /// ```ignore
    /// let size = token.estimated_size();
    /// ```
    pub fn estimated_size(&self) -> usize {
        // Approximate: sum of field lengths plus JSON overhead
        self.passphrase.len()
            + self.keychain.len()
            + self.identity_repo.len()
            + self.verify_bundle.to_string().len()
            + self.created_at.len()
            + 200 // JSON keys, braces, commas, version, max_valid_for_secs
    }

    /// Returns `true` if the token exceeds the size warning threshold (40 KB).
    ///
    /// The caller is responsible for displaying any warning to the user.
    ///
    /// Usage:
    /// ```ignore
    /// if token.is_large() {
    ///     eprintln!("Warning: token is ~{} KB", token.estimated_size() / 1024);
    /// }
    /// ```
    pub fn is_large(&self) -> bool {
        self.estimated_size() > SIZE_WARNING_THRESHOLD
    }
}
