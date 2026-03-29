use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use auths_core::ports::clock::ClockProvider;
use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::KeyAlias;

use crate::domains::identity::error::SetupError;

/// A signed platform claim linking a DID to a platform username.
///
/// Usage:
/// ```ignore
/// let claim: PlatformClaim = serde_json::from_str(&claim_json)?;
/// assert_eq!(claim.platform, "github");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformClaim {
    /// The claim type identifier (always `"platform_claim"`).
    #[serde(rename = "type")]
    pub claim_type: String,
    /// The platform name (e.g. `"github"`, `"gitlab"`).
    pub platform: String,
    /// The username on the platform.
    pub namespace: String,
    /// The controller DID (e.g. `"did:keri:E..."`).
    pub did: String,
    /// ISO-8601 timestamp of when the claim was created.
    pub timestamp: String,
    /// Base64url-encoded Ed25519 signature over the canonicalized claim.
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
/// * `signer`: Secure signer for creating the claim signature.
/// * `passphrase_provider`: Provider for key decryption passphrase.
///
/// Usage:
/// ```ignore
/// let claim_json = create_platform_claim("github", "octocat", "did:keri:E...", "main", &signer, &provider)?;
/// ```
pub fn create_platform_claim(
    platform: &str,
    namespace: &str,
    did: &str,
    key_alias: &KeyAlias,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    clock: &dyn ClockProvider,
) -> Result<String, SetupError> {
    let mut claim = PlatformClaim {
        claim_type: "platform_claim".to_string(),
        platform: platform.to_string(),
        namespace: namespace.to_string(),
        did: did.to_string(),
        timestamp: clock.now().to_rfc3339(),
        signature: None,
    };

    let unsigned_json = serde_json::to_value(&claim)
        .map_err(|e| SetupError::PlatformVerificationFailed(format!("serialize claim: {e}")))?;
    let canonical = json_canon::to_string(&unsigned_json)
        .map_err(|e| SetupError::PlatformVerificationFailed(format!("canonicalize claim: {e}")))?;

    let signature_bytes = signer
        .sign_with_alias(key_alias, passphrase_provider, canonical.as_bytes())
        .map_err(|e| SetupError::PlatformVerificationFailed(format!("sign claim: {e}")))?;

    claim.signature = Some(URL_SAFE_NO_PAD.encode(&signature_bytes));

    serde_json::to_string_pretty(&claim)
        .map_err(|e| SetupError::PlatformVerificationFailed(format!("serialize signed claim: {e}")))
}
