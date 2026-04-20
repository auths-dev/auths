// crate-level allow during curve-agnostic refactor.
#![allow(clippy::disallowed_methods)]

//! UniFFI bindings for Auths mobile identity + pairing + auth flows.
//!
//! Every private-key operation lives off-Rust: the mobile side holds
//! the keys in the Secure Enclave (iOS) or Keystore StrongBox / TEE
//! (Android) and produces signatures externally. This crate only ever
//! sees public keys and signatures.
//!
//! Curve: P-256 only. Ed25519 has been removed.
//! Wire formats: see ADRs 002 (signatures = raw r‖s) and 003 (pubkeys
//! = 33-byte compressed SEC1).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

uniffi::setup_scaffolding!();

// Signature-injection FFI. The mobile side holds the private key in
// the Secure Enclave / StrongBox / TEE; the FFI only ever sees pubkeys
// + signatures.
pub mod auth_challenge_context;
pub mod identity_context;
pub mod pairing_context;

pub use auth_challenge_context::{
    AuthChallengeContext, assemble_auth_challenge_response, build_auth_challenge_signing_payload,
};
pub use identity_context::{
    P256IdentityInceptionContext, assemble_p256_identity, build_p256_identity_inception_payload,
};
pub use pairing_context::{
    PairingBindingContext, assemble_pairing_response_body, build_pairing_binding_message,
};

/// KERI protocol version string.
pub(crate) const KERI_VERSION: &str = "KERI10JSON";

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid key data: {0}")]
    InvalidKeyData(String),

    #[error("Keychain error: {0}")]
    KeychainError(String),

    #[error("Identity already exists")]
    IdentityExists,

    #[error("Identity not found")]
    IdentityNotFound,

    #[error("Pairing session expired")]
    PairingExpired,

    #[error("Pairing failed: {0}")]
    PairingFailed(String),
}

// ============================================================================
// Result Types
// ============================================================================

/// Result of creating a new P-256 KERI identity.
///
/// The private keys stayed in the Secure Enclave — they never appear
/// here. The inception-event JSON goes to the registry at
/// `/v1/identities/{prefix}/kel`; the DID is what's shown to the user.
#[derive(Debug, Clone, uniffi::Record)]
pub struct IdentityResult {
    /// The KERI prefix (identifier without the `did:keri:` scheme).
    pub prefix: String,

    /// The full DID: `did:keri:{prefix}`.
    pub did: String,

    /// The device name provided by the user (display-only).
    pub device_name: String,

    /// The signed inception event as JSON. POST to the registry at
    /// `/v1/identities/{prefix}/kel`.
    pub inception_event_json: String,
}

// ============================================================================
// Pairing Types
// ============================================================================

/// Parsed pairing token info for display before user approves.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PairingInfo {
    pub controller_did: String,
    pub endpoint: String,
    pub short_code: String,
    pub capabilities: Vec<String>,
    pub expires_at_unix: i64,
}

/// The response payload for Swift to POST to the registry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct PairingResponsePayload {
    pub device_ephemeral_pubkey: String,
    pub device_signing_pubkey: String,
    /// Signing curve for `device_signing_pubkey` / `signature`. Carried
    /// in-band per the wire-format-curve-tagging rule so verifiers
    /// never infer curve from byte length. Emitted as `"p256"`.
    pub curve: String,
    pub device_did: String,
    pub signature: String,
    pub device_name: String,
}

// ============================================================================
// Internal KERI Event Types
// ============================================================================

/// Internal representation of an ICP event used by the FFI's own
/// builders. The authoritative typed form lives in `auths-keri`; this
/// one exists because the FFI assembles the JSON directly and needs
/// the `x` signature field (which `auths-keri::events::IcpEvent` does
/// not model — signatures there are attached out-of-band).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct IcpEvent {
    /// Type tag (`"icp"`).
    pub(crate) t: String,
    /// Version string.
    pub(crate) v: String,
    /// SAID (empty pre-finalization, filled after).
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub(crate) d: String,
    /// Identifier prefix (equals `d` for inception).
    pub(crate) i: String,
    /// Sequence number.
    pub(crate) s: String,
    /// Key threshold.
    pub(crate) kt: String,
    /// Current public keys (CESR-prefixed, base64url-no-pad).
    pub(crate) k: Vec<String>,
    /// Next-key threshold.
    pub(crate) nt: String,
    /// Next-key commitments (Blake3 of committed pubkey, `E`-prefixed).
    pub(crate) n: Vec<String>,
    /// Witness threshold.
    pub(crate) bt: String,
    /// Witness list.
    pub(crate) b: Vec<String>,
    /// Anchored seals.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) a: Vec<serde_json::Value>,
    /// Signature (empty pre-signing).
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub(crate) x: String,
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// The 44-character `#` placeholder used in SAID computation (Trust over IP KERI v0.9).
const SAID_PLACEHOLDER: &str = "############################################";

/// Compute a spec-compliant SAID (Self-Addressing Identifier) using Blake3.
///
/// Injects the 44-char `#` placeholder into `d` (and `i` for inception events),
/// removes `x`, serializes with insertion-order serde_json, then Blake3-256 hashes.
fn compute_said(event: &serde_json::Value) -> Option<String> {
    let mut obj = event.as_object()?.clone();
    obj.insert(
        "d".to_string(),
        serde_json::Value::String(SAID_PLACEHOLDER.to_string()),
    );
    let event_type = obj.get("t").and_then(|v| v.as_str()).unwrap_or("");
    if event_type == "icp" {
        obj.insert(
            "i".to_string(),
            serde_json::Value::String(SAID_PLACEHOLDER.to_string()),
        );
    }
    obj.remove("x");
    let serialized = serde_json::to_vec(&serde_json::Value::Object(obj)).ok()?;
    let hash = blake3::hash(&serialized);
    Some(format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes())))
}

/// Compute next-key commitment (Blake3 hash of public key).
pub(crate) fn compute_next_commitment(public_key: &[u8]) -> String {
    let hash = blake3::hash(public_key);
    let encoded = URL_SAFE_NO_PAD.encode(hash.as_bytes());
    format!("E{}", encoded)
}

/// Finalize an ICP event by computing and setting the SAID.
pub(crate) fn finalize_icp_event(mut icp: IcpEvent) -> Result<IcpEvent, MobileError> {
    let value = serde_json::to_value(&icp).map_err(|e| MobileError::Serialization(e.to_string()))?;
    let said = compute_said(&value)
        .ok_or_else(|| MobileError::Serialization("SAID computation failed".to_string()))?;
    icp.d = said.clone();
    icp.i = said;
    Ok(icp)
}

/// Serialize an ICP event in its signing-canonical form (empty `x`).
pub(crate) fn serialize_for_signing(icp: &IcpEvent) -> Result<Vec<u8>, MobileError> {
    serde_json::to_vec(icp).map_err(|e| MobileError::Serialization(e.to_string()))
}

// ============================================================================
// Inception event validation (for the mobile side to sanity-check before POST)
// ============================================================================

/// Validate that an inception-event JSON is well-formed and carries a
/// non-empty signature. Does NOT re-verify the signature — the
/// assemblers already did that at creation time; this is a structural
/// check the mobile side can run before posting to the registry.
#[uniffi::export]
pub fn validate_inception_event(inception_event_json: String) -> Result<String, MobileError> {
    let event: IcpEvent = serde_json::from_str(&inception_event_json)
        .map_err(|e| MobileError::Serialization(format!("Invalid JSON: {}", e)))?;
    if event.t != "icp" {
        return Err(MobileError::Serialization(format!(
            "Expected icp event, got {}",
            event.t
        )));
    }
    if event.i.is_empty() {
        return Err(MobileError::Serialization(
            "Missing identifier prefix".to_string(),
        ));
    }
    if event.x.is_empty() {
        return Err(MobileError::Serialization("Missing signature".to_string()));
    }
    Ok(event.i)
}

// ============================================================================
// Auth Challenge Types
// ============================================================================

/// Parsed auth challenge URI for display before user approves.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AuthChallengeInfo {
    pub session_id: String,
    pub challenge: String,
    pub domain: String,
    pub auth_server_url: String,
}

// ============================================================================
// Auth Challenge URI Parser
// ============================================================================

/// Parse an auth challenge QR code URI of the form
/// `auths://auth?id={id}&c={challenge}&d={domain}&e={base64(server_url)}`.
#[uniffi::export]
pub fn parse_auth_challenge_uri(uri: String) -> Result<AuthChallengeInfo, MobileError> {
    let rest = uri
        .strip_prefix("auths://auth?")
        .ok_or_else(|| MobileError::PairingFailed("Expected auths://auth? scheme".to_string()))?;

    let mut session_id = None;
    let mut challenge = None;
    let mut domain = None;
    let mut endpoint_b64 = None;

    for param in rest.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            match key {
                "id" => session_id = Some(value.to_string()),
                "c" => challenge = Some(value.to_string()),
                "d" => domain = Some(value.to_string()),
                "e" => endpoint_b64 = Some(value.to_string()),
                _ => {}
            }
        }
    }

    let session_id = session_id
        .ok_or_else(|| MobileError::PairingFailed("Missing session ID (id)".to_string()))?;
    let challenge = challenge
        .ok_or_else(|| MobileError::PairingFailed("Missing challenge (c)".to_string()))?;
    let domain =
        domain.ok_or_else(|| MobileError::PairingFailed("Missing domain (d)".to_string()))?;
    let endpoint_b64 = endpoint_b64
        .ok_or_else(|| MobileError::PairingFailed("Missing endpoint (e)".to_string()))?;

    let endpoint_bytes = URL_SAFE_NO_PAD
        .decode(&endpoint_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&endpoint_b64))
        .map_err(|e| MobileError::PairingFailed(format!("Invalid endpoint encoding: {e}")))?;
    let auth_server_url = String::from_utf8(endpoint_bytes)
        .map_err(|e| MobileError::PairingFailed(format!("Invalid endpoint UTF-8: {e}")))?;

    Ok(AuthChallengeInfo {
        session_id,
        challenge,
        domain,
        auth_server_url,
    })
}

// ============================================================================
// Pairing URI Parser
// ============================================================================

/// Internal parsed token fields shared between parse and create functions.
pub(crate) struct TokenFields {
    pub(crate) controller_did: String,
    pub(crate) endpoint: String,
    pub(crate) short_code: String,
    pub(crate) session_id: String,
    pub(crate) ephemeral_pubkey: String,
    pub(crate) expires_at_unix: i64,
    pub(crate) capabilities: Vec<String>,
}

/// Parse the query parameters from an `auths://pair?...` URI.
pub(crate) fn parse_token_fields(uri: &str) -> Result<TokenFields, MobileError> {
    let rest = uri
        .strip_prefix("auths://pair?")
        .ok_or_else(|| MobileError::PairingFailed("Expected auths://pair? scheme".to_string()))?;

    let mut controller_did = None;
    let mut endpoint_b64 = None;
    let mut ephemeral_pubkey = None;
    let mut short_code = None;
    let mut session_id = None;
    let mut expires_unix = None;
    let mut caps_str = None;

    for param in rest.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            match key {
                "d" => controller_did = Some(value.to_string()),
                "e" => endpoint_b64 = Some(value.to_string()),
                "k" => ephemeral_pubkey = Some(value.to_string()),
                "sc" => short_code = Some(value.to_string()),
                "sid" => session_id = Some(value.to_string()),
                "x" => expires_unix = value.parse::<i64>().ok(),
                "c" => caps_str = Some(value.to_string()),
                _ => {}
            }
        }
    }

    let controller_did = controller_did
        .ok_or_else(|| MobileError::PairingFailed("Missing controller DID (d)".to_string()))?;
    let endpoint_b64 = endpoint_b64
        .ok_or_else(|| MobileError::PairingFailed("Missing endpoint (e)".to_string()))?;
    let endpoint_bytes = URL_SAFE_NO_PAD
        .decode(&endpoint_b64)
        .map_err(|e| MobileError::PairingFailed(format!("Invalid endpoint encoding: {}", e)))?;
    let endpoint = String::from_utf8(endpoint_bytes)
        .map_err(|e| MobileError::PairingFailed(format!("Invalid endpoint UTF-8: {}", e)))?;
    let ephemeral_pubkey = ephemeral_pubkey
        .ok_or_else(|| MobileError::PairingFailed("Missing ephemeral pubkey (k)".to_string()))?;
    let short_code = short_code
        .ok_or_else(|| MobileError::PairingFailed("Missing short code (sc)".to_string()))?;
    let session_id = session_id
        .ok_or_else(|| MobileError::PairingFailed("Missing session id (sid)".to_string()))?;
    let expires_at_unix = expires_unix
        .ok_or_else(|| MobileError::PairingFailed("Missing or invalid expiry (x)".to_string()))?;

    let capabilities = caps_str
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(|c| c.to_string()).collect())
        .unwrap_or_default();

    Ok(TokenFields {
        controller_did,
        endpoint,
        short_code,
        session_id,
        ephemeral_pubkey,
        expires_at_unix,
        capabilities,
    })
}

/// Parse a pairing URI for display before user approves.
#[uniffi::export]
pub fn parse_pairing_uri(uri: String) -> Result<PairingInfo, MobileError> {
    let fields = parse_token_fields(&uri)?;
    Ok(PairingInfo {
        controller_did: fields.controller_did,
        endpoint: fields.endpoint,
        short_code: fields.short_code,
        capabilities: fields.capabilities,
        expires_at_unix: fields.expires_at_unix,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_inception_event_rejects_wrong_type() {
        let r = validate_inception_event(r#"{"t":"rot","i":"x","x":"y"}"#.to_string());
        assert!(r.is_err());
    }

    #[test]
    fn validate_inception_event_rejects_missing_prefix() {
        let r = validate_inception_event(r#"{"t":"icp","i":"","x":"y"}"#.to_string());
        assert!(r.is_err());
    }

    #[test]
    fn validate_inception_event_rejects_missing_signature() {
        let r = validate_inception_event(r#"{"t":"icp","i":"Eabc","x":""}"#.to_string());
        assert!(r.is_err());
    }

    #[test]
    fn test_parse_auth_challenge_uri() {
        let uri = "auths://auth?id=550e8400-e29b-41d4-a716-446655440000&c=deadbeef&d=192.168.1.40&e=aHR0cDovLzE5Mi4xNjguMS40MDozMDAx".to_string();
        let info = parse_auth_challenge_uri(uri).unwrap();
        assert_eq!(info.session_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(info.challenge, "deadbeef");
        assert_eq!(info.domain, "192.168.1.40");
        assert_eq!(info.auth_server_url, "http://192.168.1.40:3001");
    }

    #[test]
    fn test_parse_auth_challenge_uri_rejects_wrong_scheme() {
        assert!(parse_auth_challenge_uri("auths://pair?id=test".to_string()).is_err());
        assert!(parse_auth_challenge_uri("https://example.com".to_string()).is_err());
    }

    fn make_test_pairing_uri() -> String {
        use rand_core::OsRng;
        use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

        let secret = EphemeralSecret::random_from_rng(OsRng);
        let pubkey = X25519PublicKey::from(&secret);
        let pubkey_b64 = URL_SAFE_NO_PAD.encode(pubkey.as_bytes());
        let endpoint_b64 = URL_SAFE_NO_PAD.encode(b"http://localhost:3000");
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        format!(
            "auths://pair?d=did:keri:test123&e={}&k={}&sc=AB3DEF&sid=sess-test&x={}&c=sign_commit",
            endpoint_b64, pubkey_b64, expires
        )
    }

    #[test]
    fn test_parse_pairing_uri() {
        let info = parse_pairing_uri(make_test_pairing_uri()).unwrap();
        assert_eq!(info.controller_did, "did:keri:test123");
        assert_eq!(info.endpoint, "http://localhost:3000");
        assert_eq!(info.short_code, "AB3DEF");
        assert_eq!(info.capabilities, vec!["sign_commit"]);
    }

    #[test]
    fn test_parse_pairing_uri_invalid() {
        assert!(parse_pairing_uri("https://example.com".to_string()).is_err());
        assert!(parse_pairing_uri("auths://pair?d=did:keri:test".to_string()).is_err());
    }
}
