//! UniFFI bindings for Auths mobile identity creation.
//!
//! This crate provides Swift and Kotlin bindings for creating KERI identities
//! on mobile devices. It generates keypairs and inception events without
//! requiring Git storage - the inception event is returned for the app to
//! POST to the registry server.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::rngs::OsRng;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroizing;

// Use proc-macro based approach (no UDL)
uniffi::setup_scaffolding!();

/// KERI protocol version string.
const KERI_VERSION: &str = "KERI10JSON";

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

/// Result of creating a new KERI identity.
///
/// Contains all the data needed to:
/// 1. Store keys in iOS Keychain (current_key_pkcs8, next_key_pkcs8)
/// 2. POST inception event to server (inception_event_json)
/// 3. Display the DID to the user (did)
#[derive(Debug, Clone, uniffi::Record)]
pub struct IdentityResult {
    /// The KERI prefix (the identifier without "did:keri:" prefix)
    pub prefix: String,

    /// The full DID: "did:keri:{prefix}"
    pub did: String,

    /// The device name provided by the user
    pub device_name: String,

    /// Current signing keypair in PKCS8 DER format (hex encoded for safe FFI)
    /// Store this in iOS Keychain
    pub current_key_pkcs8_hex: String,

    /// Next rotation keypair in PKCS8 DER format (hex encoded for safe FFI)
    /// Store this in iOS Keychain for future key rotation
    pub next_key_pkcs8_hex: String,

    /// Current public key (32 bytes, hex encoded)
    pub current_public_key_hex: String,

    /// Next public key (32 bytes, hex encoded)
    pub next_public_key_hex: String,

    /// The signed inception event as JSON string.
    /// POST this to the registry server at /v1/identities/{prefix}/kel
    pub inception_event_json: String,
}

/// Pending sync status for offline-first architecture.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PendingSync {
    /// The KERI prefix that needs syncing
    pub prefix: String,

    /// The DID that needs syncing
    pub did: String,

    /// The inception event JSON to POST
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
///
/// This matches `SubmitResponseRequest` in the registry server.
/// The session ID is NOT included here — it's a URL path parameter,
/// not a POST body field. Swift should look up the session ID via
/// `GET /v1/pairing/sessions/by-code/{short_code}` before POSTing.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PairingResponsePayload {
    pub device_x25519_pubkey: String,
    pub device_signing_pubkey: String,
    pub device_did: String,
    pub signature: String,
    pub device_name: String,
}

/// Result of creating a pairing response (crypto side).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PairingResult {
    pub controller_did: String,
    pub device_did: String,
    pub shared_secret_hex: String,
    pub capabilities: Vec<String>,
    /// The short code from the URI, used to look up the session ID
    /// via `GET /v1/pairing/sessions/by-code/{short_code}`.
    pub short_code: String,
    /// The registry endpoint URL decoded from the URI.
    pub endpoint: String,
    pub response_payload: PairingResponsePayload,
}

// ============================================================================
// Internal KERI Event Types (for serialization)
// ============================================================================

/// Internal representation of ICP event for serialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IcpEvent {
    /// Type tag
    t: String,
    /// Version string
    v: String,
    /// SAID (empty for pre-finalization, filled after)
    #[serde(skip_serializing_if = "String::is_empty", default)]
    d: String,
    /// Identifier prefix (same as d for inception)
    i: String,
    /// Sequence number
    s: String,
    /// Key threshold
    kt: String,
    /// Current public keys
    k: Vec<String>,
    /// Next key threshold
    nt: String,
    /// Next key commitments
    n: Vec<String>,
    /// Witness threshold
    bt: String,
    /// Witness list
    b: Vec<String>,
    /// Anchored seals
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    a: Vec<serde_json::Value>,
    /// Signature (empty for pre-signing)
    #[serde(skip_serializing_if = "String::is_empty", default)]
    x: String,
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
fn compute_next_commitment(public_key: &[u8]) -> String {
    let hash = blake3::hash(public_key);
    let encoded = URL_SAFE_NO_PAD.encode(hash.as_bytes());
    format!("E{}", encoded)
}

/// Finalize an ICP event by computing and setting the SAID.
fn finalize_icp_event(mut icp: IcpEvent) -> Result<IcpEvent, MobileError> {
    let value = serde_json::to_value(&icp)
        .map_err(|e| MobileError::Serialization(e.to_string()))?;

    let said = compute_said(&value)
        .ok_or_else(|| MobileError::Serialization("SAID computation failed".to_string()))?;

    // Set both d and i to the SAID (for inception, prefix = SAID)
    icp.d = said.clone();
    icp.i = said;

    Ok(icp)
}

/// Serialize event for signing (canonical JSON with empty signature field).
fn serialize_for_signing(icp: &IcpEvent) -> Result<Vec<u8>, MobileError> {
    let mut signing_icp = icp.clone();
    signing_icp.x = String::new();

    serde_json::to_vec(&signing_icp).map_err(|e| MobileError::Serialization(e.to_string()))
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Create a new KERI identity for this device.
///
/// This generates:
/// - Two Ed25519 keypairs (current + next for pre-rotation)
/// - A signed KERI inception event
///
/// The returned data should be:
/// 1. Keys stored in iOS Keychain (current_key_pkcs8_hex, next_key_pkcs8_hex)
/// 2. Inception event POSTed to registry server
///
/// # Arguments
/// * `device_name` - Friendly name for this device (e.g., "Pierre's iPhone")
///
/// # Returns
/// IdentityResult containing keys and inception event
#[uniffi::export]
pub fn create_identity(device_name: String) -> Result<IdentityResult, MobileError> {
    let rng = SystemRandom::new();

    // Generate current keypair
    let current_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| MobileError::KeyGeneration(e.to_string()))?;
    let current_keypair = Ed25519KeyPair::from_pkcs8(current_pkcs8.as_ref())
        .map_err(|e| MobileError::KeyGeneration(e.to_string()))?;

    // Generate next keypair (for pre-rotation)
    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| MobileError::KeyGeneration(e.to_string()))?;
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref())
        .map_err(|e| MobileError::KeyGeneration(e.to_string()))?;

    // Encode current public key with derivation code prefix
    // 'D' prefix indicates Ed25519 in KERI
    let current_pub_encoded = format!(
        "D{}",
        URL_SAFE_NO_PAD.encode(current_keypair.public_key().as_ref())
    );

    // Compute next-key commitment (Blake3 hash of next public key)
    let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

    // Build inception event (without SAID)
    let icp = IcpEvent {
        t: "icp".to_string(),
        v: KERI_VERSION.to_string(),
        d: String::new(),
        i: String::new(),
        s: "0".to_string(),
        kt: "1".to_string(),
        k: vec![current_pub_encoded],
        nt: "1".to_string(),
        n: vec![next_commitment],
        bt: "0".to_string(),
        b: vec![],
        a: vec![],
        x: String::new(),
    };

    // Finalize event (computes and sets SAID)
    let mut finalized = finalize_icp_event(icp)?;
    let prefix = finalized.i.clone();

    // Sign the event with the current key
    let canonical = serialize_for_signing(&finalized)?;
    let sig = current_keypair.sign(&canonical);
    finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    // Serialize the final signed event
    let inception_event_json =
        serde_json::to_string(&finalized).map_err(|e| MobileError::Serialization(e.to_string()))?;

    Ok(IdentityResult {
        prefix: prefix.clone(),
        did: format!("did:keri:{}", prefix),
        device_name,
        current_key_pkcs8_hex: hex::encode(current_pkcs8.as_ref()),
        next_key_pkcs8_hex: hex::encode(next_pkcs8.as_ref()),
        current_public_key_hex: hex::encode(current_keypair.public_key().as_ref()),
        next_public_key_hex: hex::encode(next_keypair.public_key().as_ref()),
        inception_event_json,
    })
}

/// Sign arbitrary data with the identity's current key.
///
/// # Arguments
/// * `current_key_pkcs8_hex` - The current signing key in PKCS8 DER format (hex encoded)
/// * `data_to_sign` - The data to sign (as bytes)
///
/// # Returns
/// The Ed25519 signature as hex-encoded bytes
#[uniffi::export]
pub fn sign_with_identity(
    current_key_pkcs8_hex: String,
    data_to_sign: Vec<u8>,
) -> Result<String, MobileError> {
    let pkcs8_bytes = hex::decode(&current_key_pkcs8_hex)
        .map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;

    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes)
        .map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;

    let signature = keypair.sign(&data_to_sign);
    Ok(hex::encode(signature.as_ref()))
}

/// Get the public key from a PKCS8-encoded private key.
///
/// # Arguments
/// * `pkcs8_hex` - The private key in PKCS8 DER format (hex encoded)
///
/// # Returns
/// The Ed25519 public key as hex-encoded bytes (32 bytes)
#[uniffi::export]
pub fn get_public_key_from_pkcs8(pkcs8_hex: String) -> Result<String, MobileError> {
    let pkcs8_bytes =
        hex::decode(&pkcs8_hex).map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;

    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes)
        .map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;

    Ok(hex::encode(keypair.public_key().as_ref()))
}

/// Generate a device DID (did:key) from a public key.
///
/// This creates a did:key identifier in the Ed25519 multicodec format.
///
/// # Arguments
/// * `public_key_hex` - The Ed25519 public key (32 bytes, hex encoded)
///
/// # Returns
/// A did:key identifier like "did:key:z6Mk..."
#[uniffi::export]
pub fn generate_device_did(public_key_hex: String) -> Result<String, MobileError> {
    let public_key =
        hex::decode(&public_key_hex).map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;

    if public_key.len() != 32 {
        return Err(MobileError::InvalidKeyData(format!(
            "Expected 32 bytes, got {}",
            public_key.len()
        )));
    }

    // Ed25519 multicodec prefix: 0xed01
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(&public_key);

    // Base58btc encode with 'z' prefix
    let encoded = bs58::encode(&multicodec).into_string();
    Ok(format!("did:key:z{}", encoded))
}

/// Validate that an inception event JSON is well-formed.
///
/// # Arguments
/// * `inception_event_json` - The inception event as JSON string
///
/// # Returns
/// The KERI prefix if valid, or an error
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

/// Input for signing an authentication challenge from a QR code.
#[derive(Debug, uniffi::Record)]
pub struct AuthChallengeInput {
    /// Hex-encoded challenge nonce from the auth server.
    pub nonce: String,
    /// Domain from the QR code (anti-phishing binding).
    pub domain: String,
}

/// Result of signing an auth challenge.
#[derive(Debug, uniffi::Record)]
pub struct SignedAuthChallenge {
    /// Hex-encoded Ed25519 signature of the canonical challenge payload.
    pub signature_hex: String,
    /// Hex-encoded 32-byte Ed25519 public key.
    pub public_key_hex: String,
    /// The identity DID (did:keri:...).
    pub did: String,
}

/// Parsed auth challenge URI for display before user approves.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AuthChallengeInfo {
    /// Session ID from the auth server.
    pub session_id: String,
    /// Hex-encoded challenge nonce.
    pub challenge: String,
    /// Domain the challenge is bound to (anti-phishing).
    pub domain: String,
    /// Auth server endpoint URL to POST the signed response to.
    pub auth_server_url: String,
}

// ============================================================================
// Auth Challenge API
// ============================================================================

/// Parse an auth challenge QR code URI.
///
/// The QR code contains: `auths://auth?id={id}&c={challenge}&d={domain}&e={base64(server_url)}`
///
/// Returns the parsed fields so the app can display them and then call
/// `sign_auth_challenge()` + POST the result.
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
    let domain = domain
        .ok_or_else(|| MobileError::PairingFailed("Missing domain (d)".to_string()))?;
    let endpoint_b64 = endpoint_b64
        .ok_or_else(|| MobileError::PairingFailed("Missing endpoint (e)".to_string()))?;

    // The endpoint is base64-encoded (standard encoding, as produced by browser btoa())
    let endpoint_bytes = URL_SAFE_NO_PAD
        .decode(&endpoint_b64)
        .or_else(|_| {
            // Browser btoa() uses standard base64 with padding, try that too
            base64::engine::general_purpose::STANDARD.decode(&endpoint_b64)
        })
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

/// Sign an authentication challenge for "Login with Auths".
///
/// Constructs a canonical JSON payload from the challenge nonce and domain,
/// signs it with the identity's current key, and returns the signature +
/// public key for the mobile app to POST to the auth server.
///
/// # Arguments
/// * `current_key_pkcs8_hex` - The current signing key in PKCS8 DER format (hex encoded)
/// * `identity_did` - The identity's DID (e.g. "did:keri:EPREFIX")
/// * `challenge` - The challenge input from the QR code
#[uniffi::export]
pub fn sign_auth_challenge(
    current_key_pkcs8_hex: String,
    identity_did: String,
    challenge: AuthChallengeInput,
) -> Result<SignedAuthChallenge, MobileError> {
    let pkcs8_bytes = hex::decode(&current_key_pkcs8_hex)
        .map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;

    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes)
        .map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;

    // Build canonical JSON payload: { "domain": ..., "nonce": ... }
    let payload = serde_json::json!({
        "domain": challenge.domain,
        "nonce": challenge.nonce,
    });
    let canonical = json_canon::to_string(&payload)
        .map_err(|e| MobileError::Serialization(e.to_string()))?;

    let signature = keypair.sign(canonical.as_bytes());
    let public_key = keypair.public_key().as_ref();

    Ok(SignedAuthChallenge {
        signature_hex: hex::encode(signature.as_ref()),
        public_key_hex: hex::encode(public_key),
        did: identity_did,
    })
}

// ============================================================================
// Internal Pairing Helpers
// ============================================================================

/// Internal parsed token fields shared between parse and create functions.
struct TokenFields {
    controller_did: String,
    endpoint: String,
    short_code: String,
    ephemeral_pubkey: String,
    expires_at_unix: i64,
    capabilities: Vec<String>,
}

/// Parse the query parameters from an `auths://pair?...` URI.
fn parse_token_fields(uri: &str) -> Result<TokenFields, MobileError> {
    let rest = uri
        .strip_prefix("auths://pair?")
        .ok_or_else(|| MobileError::PairingFailed("Expected auths://pair? scheme".to_string()))?;

    let mut controller_did = None;
    let mut endpoint_b64 = None;
    let mut ephemeral_pubkey = None;
    let mut short_code = None;
    let mut expires_unix = None;
    let mut caps_str = None;

    for param in rest.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            match key {
                "d" => controller_did = Some(value.to_string()),
                "e" => endpoint_b64 = Some(value.to_string()),
                "k" => ephemeral_pubkey = Some(value.to_string()),
                "sc" => short_code = Some(value.to_string()),
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
        ephemeral_pubkey,
        expires_at_unix,
        capabilities,
    })
}

// ============================================================================
// Pairing API Functions
// ============================================================================

/// Parse a pairing URI for display before user approves.
///
/// Extracts the pairing token info from an `auths://pair?...` URI so the
/// app can show the controller DID, short code, and capabilities before
/// the user confirms pairing.
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

/// Create a pairing response with ECDH key exchange and Ed25519 signature.
///
/// This mirrors `PairingResponse::create()` from auths-core. It:
/// 1. Parses the URI and checks expiry
/// 2. Generates a device X25519 ephemeral key
/// 3. Performs ECDH with the initiator's X25519 public key
/// 4. Signs the binding message (short_code || initiator_x25519 || device_x25519)
/// 5. Returns the response payload for Swift to POST to the registry
///
/// # Arguments
/// * `uri` - The full `auths://pair?...` URI from the QR code
/// * `current_key_pkcs8_hex` - The device's Ed25519 signing key (PKCS8 DER, hex encoded)
/// * `device_name` - Friendly name for this device
#[uniffi::export]
pub fn create_pairing_response(
    uri: String,
    current_key_pkcs8_hex: String,
    device_name: String,
) -> Result<PairingResult, MobileError> {
    let fields = parse_token_fields(&uri)?;

    // Check expiry using system time (no chrono dependency)
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| MobileError::PairingFailed(format!("System time error: {}", e)))?
        .as_secs() as i64;

    if now_unix > fields.expires_at_unix {
        return Err(MobileError::PairingExpired);
    }

    // Decode the Ed25519 signing key
    let pkcs8_bytes = hex::decode(&current_key_pkcs8_hex)
        .map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;
    let ed25519_keypair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes)
        .map_err(|e| MobileError::InvalidKeyData(e.to_string()))?;

    // Generate device X25519 ephemeral key
    let device_x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let device_x25519_public = X25519PublicKey::from(&device_x25519_secret);

    // Decode initiator's X25519 public key from token
    let initiator_x25519_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&fields.ephemeral_pubkey)
        .map_err(|e| MobileError::PairingFailed(format!("Invalid pubkey encoding: {}", e)))?
        .try_into()
        .map_err(|_| MobileError::PairingFailed("Invalid X25519 pubkey length".to_string()))?;
    let initiator_x25519 = X25519PublicKey::from(initiator_x25519_bytes);

    // Perform ECDH — wrap raw bytes in Zeroizing so they're wiped on drop
    let shared = device_x25519_secret.diffie_hellman(&initiator_x25519);
    let shared_bytes = Zeroizing::new(*shared.as_bytes());
    let shared_secret_hex = hex::encode(*shared_bytes);

    // Get device Ed25519 public key (base64url encoded)
    let device_signing_pubkey = URL_SAFE_NO_PAD.encode(ed25519_keypair.public_key().as_ref());

    // Encode device X25519 public key (base64url encoded)
    let device_x25519_pubkey_str = URL_SAFE_NO_PAD.encode(device_x25519_public.as_bytes());

    // Build binding message: short_code || initiator_x25519 || device_x25519
    let mut message = Vec::new();
    message.extend_from_slice(fields.short_code.as_bytes());
    message.extend_from_slice(&initiator_x25519_bytes);
    message.extend_from_slice(device_x25519_public.as_bytes());

    // Sign with Ed25519
    let sig = ed25519_keypair.sign(&message);
    let signature = URL_SAFE_NO_PAD.encode(sig.as_ref());

    // Derive device DID (did:key) from public key
    let device_public_key_hex = hex::encode(ed25519_keypair.public_key().as_ref());
    let device_did = generate_device_did(device_public_key_hex)?;

    let response_payload = PairingResponsePayload {
        device_x25519_pubkey: device_x25519_pubkey_str,
        device_signing_pubkey,
        device_did: device_did.clone(),
        signature,
        device_name: device_name.clone(),
    };

    Ok(PairingResult {
        controller_did: fields.controller_did,
        device_did,
        shared_secret_hex,
        capabilities: fields.capabilities,
        short_code: fields.short_code,
        endpoint: fields.endpoint,
        response_payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_identity_returns_valid_result() {
        let result = create_identity("Test iPhone".to_string()).unwrap();

        // Prefix should start with 'E' (Blake3 SAID prefix)
        assert!(result.prefix.starts_with('E'));

        // DID should be formatted correctly
        assert!(result.did.starts_with("did:keri:E"));

        // Keys should be present and valid hex
        assert!(!result.current_key_pkcs8_hex.is_empty());
        assert!(!result.next_key_pkcs8_hex.is_empty());
        hex::decode(&result.current_key_pkcs8_hex).unwrap();
        hex::decode(&result.next_key_pkcs8_hex).unwrap();

        // Public keys should be 32 bytes (64 hex chars)
        assert_eq!(result.current_public_key_hex.len(), 64);
        assert_eq!(result.next_public_key_hex.len(), 64);

        // Inception event should be valid JSON
        let event: serde_json::Value = serde_json::from_str(&result.inception_event_json).unwrap();
        assert_eq!(event["t"], "icp");
        assert_eq!(event["v"], KERI_VERSION);
        assert!(!event["x"].as_str().unwrap().is_empty());
    }

    #[test]
    fn inception_event_has_correct_structure() {
        let result = create_identity("Test Device".to_string()).unwrap();
        let event: IcpEvent = serde_json::from_str(&result.inception_event_json).unwrap();

        // SAID equals prefix
        assert_eq!(event.d, event.i);
        assert_eq!(event.d, result.prefix);

        // Sequence is 0
        assert_eq!(event.s, "0");

        // Single key
        assert_eq!(event.k.len(), 1);
        assert!(event.k[0].starts_with('D')); // Ed25519 prefix

        // Single next commitment
        assert_eq!(event.n.len(), 1);
        assert!(event.n[0].starts_with('E')); // Blake3 hash prefix

        // No witnesses
        assert_eq!(event.bt, "0");
        assert!(event.b.is_empty());
    }

    #[test]
    fn sign_with_identity_works() {
        let result = create_identity("Test".to_string()).unwrap();
        let data = b"test data to sign".to_vec();

        let signature = sign_with_identity(result.current_key_pkcs8_hex, data).unwrap();

        // Signature should be 64 bytes (128 hex chars)
        assert_eq!(signature.len(), 128);
        hex::decode(&signature).unwrap();
    }

    #[test]
    fn get_public_key_from_pkcs8_works() {
        let result = create_identity("Test".to_string()).unwrap();

        let public_key = get_public_key_from_pkcs8(result.current_key_pkcs8_hex).unwrap();

        // Should match the public key we got during creation
        assert_eq!(public_key, result.current_public_key_hex);
    }

    #[test]
    fn generate_device_did_works() {
        let result = create_identity("Test".to_string()).unwrap();

        let device_did = generate_device_did(result.current_public_key_hex).unwrap();

        assert!(device_did.starts_with("did:key:z"));
    }

    #[test]
    fn validate_inception_event_works() {
        let result = create_identity("Test".to_string()).unwrap();

        let prefix = validate_inception_event(result.inception_event_json).unwrap();

        assert_eq!(prefix, result.prefix);
    }

    #[test]
    fn validate_inception_event_rejects_invalid() {
        let result = validate_inception_event("not json".to_string());
        assert!(result.is_err());

        let result = validate_inception_event(r#"{"t":"rot"}"#.to_string());
        assert!(result.is_err());
    }

    #[test]
    fn multiple_identities_have_different_prefixes() {
        let result1 = create_identity("Device 1".to_string()).unwrap();
        let result2 = create_identity("Device 2".to_string()).unwrap();

        assert_ne!(result1.prefix, result2.prefix);
        assert_ne!(result1.current_key_pkcs8_hex, result2.current_key_pkcs8_hex);
    }

    // ========================================================================
    // Auth challenge tests
    // ========================================================================

    #[test]
    fn test_parse_auth_challenge_uri() {
        // Browser btoa("http://192.168.1.40:3001") = "aHR0cDovLzE5Mi4xNjguMS40MDozMDAx"
        let uri = "auths://auth?id=550e8400-e29b-41d4-a716-446655440000&c=deadbeef&d=192.168.1.40&e=aHR0cDovLzE5Mi4xNjguMS40MDozMDAx".to_string();
        let info = parse_auth_challenge_uri(uri).unwrap();

        assert_eq!(info.session_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(info.challenge, "deadbeef");
        assert_eq!(info.domain, "192.168.1.40");
        assert_eq!(info.auth_server_url, "http://192.168.1.40:3001");
    }

    #[test]
    fn test_parse_auth_challenge_uri_rejects_wrong_scheme() {
        let result = parse_auth_challenge_uri("auths://pair?id=test".to_string());
        assert!(result.is_err());

        let result = parse_auth_challenge_uri("https://example.com".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_auth_challenge() {
        use ring::signature::{ED25519, UnparsedPublicKey};

        let identity = create_identity("Test".to_string()).unwrap();

        let challenge = AuthChallengeInput {
            nonce: "deadbeef".repeat(8), // 64 hex chars = 32 bytes
            domain: "bank.example.com".to_string(),
        };

        let result = sign_auth_challenge(
            identity.current_key_pkcs8_hex.clone(),
            identity.did.clone(),
            challenge,
        )
        .unwrap();

        assert_eq!(result.did, identity.did);
        assert_eq!(result.public_key_hex, identity.current_public_key_hex);
        assert_eq!(result.signature_hex.len(), 128); // 64 bytes = 128 hex chars

        // Verify the signature
        let canonical = json_canon::to_string(&serde_json::json!({
            "domain": "bank.example.com",
            "nonce": "deadbeef".repeat(8),
        }))
        .unwrap();

        let pub_bytes = hex::decode(&result.public_key_hex).unwrap();
        let sig_bytes = hex::decode(&result.signature_hex).unwrap();
        let public_key = UnparsedPublicKey::new(&ED25519, &pub_bytes);
        public_key.verify(canonical.as_bytes(), &sig_bytes).unwrap();
    }

    // ========================================================================
    // Pairing tests
    // ========================================================================

    /// Build a valid test pairing URI with a future expiry.
    fn make_test_pairing_uri() -> String {
        use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

        let secret = EphemeralSecret::random_from_rng(OsRng);
        let pubkey = X25519PublicKey::from(&secret);
        let pubkey_b64 = URL_SAFE_NO_PAD.encode(pubkey.as_bytes());

        let endpoint_b64 = URL_SAFE_NO_PAD.encode(b"http://localhost:3000");
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300; // 5 minutes from now

        format!(
            "auths://pair?d=did:keri:test123&e={}&k={}&sc=AB3DEF&x={}&c=sign_commit",
            endpoint_b64, pubkey_b64, expires
        )
    }

    #[test]
    fn test_parse_pairing_uri() {
        let uri = make_test_pairing_uri();
        let info = parse_pairing_uri(uri).unwrap();

        assert_eq!(info.controller_did, "did:keri:test123");
        assert_eq!(info.endpoint, "http://localhost:3000");
        assert_eq!(info.short_code, "AB3DEF");
        assert_eq!(info.capabilities, vec!["sign_commit"]);
        assert!(info.expires_at_unix > 0);
    }

    #[test]
    fn test_parse_pairing_uri_invalid() {
        // Bad prefix
        let result = parse_pairing_uri("https://example.com".to_string());
        assert!(result.is_err());

        // Missing required params
        let result = parse_pairing_uri("auths://pair?d=did:keri:test".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_create_pairing_response() {
        let uri = make_test_pairing_uri();

        // Generate a test Ed25519 keypair
        let identity = create_identity("Test Device".to_string()).unwrap();

        let result = create_pairing_response(
            uri,
            identity.current_key_pkcs8_hex,
            "Test iPhone".to_string(),
        )
        .unwrap();

        assert_eq!(result.controller_did, "did:keri:test123");
        assert!(result.device_did.starts_with("did:key:z"));
        assert!(!result.shared_secret_hex.is_empty());
        assert_eq!(result.shared_secret_hex.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(result.capabilities, vec!["sign_commit"]);

        // Verify payload fields are populated
        let payload = &result.response_payload;
        assert!(!payload.device_x25519_pubkey.is_empty());
        assert!(!payload.device_signing_pubkey.is_empty());
        assert!(!payload.signature.is_empty());
        assert_eq!(payload.device_name, "Test iPhone");

        // short_code and endpoint are on the result, not the payload
        assert_eq!(result.short_code, "AB3DEF");
        assert_eq!(result.endpoint, "http://localhost:3000");
    }

    #[test]
    fn test_create_pairing_response_expired() {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let pubkey = X25519PublicKey::from(&secret);
        let pubkey_b64 = URL_SAFE_NO_PAD.encode(pubkey.as_bytes());
        let endpoint_b64 = URL_SAFE_NO_PAD.encode(b"http://localhost:3000");

        // Expired timestamp (in the past)
        let uri = format!(
            "auths://pair?d=did:keri:test&e={}&k={}&sc=TSTEXP&x=1000000000&c=",
            endpoint_b64, pubkey_b64
        );

        let identity = create_identity("Test".to_string()).unwrap();
        let result =
            create_pairing_response(uri, identity.current_key_pkcs8_hex, "Test".to_string());

        assert!(matches!(result, Err(MobileError::PairingExpired)));
    }

    #[test]
    fn test_pairing_response_signature_verifiable() {
        use ring::signature::{ED25519, UnparsedPublicKey};

        let uri = make_test_pairing_uri();
        let identity = create_identity("Test Device".to_string()).unwrap();

        let result = create_pairing_response(
            uri.clone(),
            identity.current_key_pkcs8_hex,
            "Test iPhone".to_string(),
        )
        .unwrap();

        // Reconstruct the binding message and verify the signature
        let fields = parse_token_fields(&uri).unwrap();
        let initiator_x25519_bytes = URL_SAFE_NO_PAD.decode(&fields.ephemeral_pubkey).unwrap();
        let device_x25519_bytes = URL_SAFE_NO_PAD
            .decode(&result.response_payload.device_x25519_pubkey)
            .unwrap();
        let signing_pubkey_bytes = URL_SAFE_NO_PAD
            .decode(&result.response_payload.device_signing_pubkey)
            .unwrap();
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&result.response_payload.signature)
            .unwrap();

        // Build the same binding message: short_code || initiator_x25519 || device_x25519
        let mut message = Vec::new();
        message.extend_from_slice(fields.short_code.as_bytes());
        message.extend_from_slice(&initiator_x25519_bytes);
        message.extend_from_slice(&device_x25519_bytes);

        // Verify signature
        let public_key = UnparsedPublicKey::new(&ED25519, &signing_pubkey_bytes);
        public_key.verify(&message, &signature_bytes).unwrap();
    }
}
