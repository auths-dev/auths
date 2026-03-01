use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use auths_core::signing::{SecureSigner, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, get_platform_keychain};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformClaim {
    #[serde(rename = "type")]
    pub claim_type: String,
    pub platform: String,
    pub namespace: String,
    pub did: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Creates a signed platform claim linking a DID to a platform username.
///
/// The claim is JSON-canonicalized (RFC 8785) before signing, ensuring
/// deterministic verification without the original OAuth token.
///
/// Args:
/// * `platform`: Platform name (e.g., "github").
/// * `namespace`: Username on the platform.
/// * `did`: The controller DID (e.g., "did:keri:E...").
/// * `key_alias`: Keychain alias for the signing key.
/// * `passphrase_provider`: Provider for key decryption passphrase.
///
/// Usage:
/// ```ignore
/// let claim_json = create_signed_platform_claim("github", "octocat", "did:keri:E...", "main", provider)?;
/// ```
pub fn create_signed_platform_claim(
    platform: &str,
    namespace: &str,
    did: &str,
    key_alias: &str,
    passphrase_provider: &dyn auths_core::signing::PassphraseProvider,
) -> Result<String> {
    let mut claim = PlatformClaim {
        claim_type: "platform_claim".to_string(),
        platform: platform.to_string(),
        namespace: namespace.to_string(),
        did: did.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        signature: None,
    };

    // Canonicalize the unsigned claim for signing
    let unsigned_json = serde_json::to_value(&claim).context("Failed to serialize claim")?;
    let canonical =
        json_canon::to_string(&unsigned_json).context("Failed to canonicalize claim")?;

    // Sign with the identity key
    let signer = StorageSigner::new(get_platform_keychain().map_err(|e| anyhow::anyhow!(e))?);
    let alias_typed = KeyAlias::new_unchecked(key_alias);
    let signature_bytes = signer
        .sign_with_alias(&alias_typed, passphrase_provider, canonical.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to sign platform claim: {e}"))?;

    claim.signature = Some(URL_SAFE_NO_PAD.encode(&signature_bytes));

    serde_json::to_string_pretty(&claim).context("Failed to serialize signed claim")
}
