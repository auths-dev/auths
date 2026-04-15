use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

/// A base64url-encoded (no padding) byte string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct Base64UrlEncoded(String);

impl Base64UrlEncoded {
    pub fn from_raw(s: String) -> Self {
        Self(s)
    }

    pub fn encode(bytes: &[u8]) -> Self {
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn decode(&self) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(&self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for Base64UrlEncoded {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Base64UrlEncoded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Session status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Pending,
    Responded,
    Confirmed,
    Aborted,
    Completed,
    Cancelled,
    Expired,
}

/// Request to create a new pairing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CreateSessionRequest {
    pub session_id: String,
    pub controller_did: String,
    pub ephemeral_pubkey: Base64UrlEncoded,
    pub short_code: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub expires_at: i64,
}

/// Response to session creation.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub status: SessionStatus,
    pub short_code: String,
    pub uri: String,
    pub ttl_seconds: u64,
}

/// Request to submit a pairing response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SubmitResponseRequest {
    pub device_x25519_pubkey: Base64UrlEncoded,
    pub device_signing_pubkey: Base64UrlEncoded,
    /// Signing curve for `device_signing_pubkey` / `signature`. Carried in-band
    /// per the workspace wire-format curve-tagging rule — verifiers must never
    /// infer curve from pubkey byte length. Defaults to P-256 when absent.
    #[serde(default)]
    pub curve: crate::response::CurveTag,
    /// Responder's DID string (e.g. `did:key:z6Mk...`).
    pub device_did: String,
    pub signature: Base64UrlEncoded,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
}

/// Response when getting session status.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct GetSessionResponse {
    pub session_id: String,
    pub status: SessionStatus,
    pub ttl_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<CreateSessionRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<SubmitResponseRequest>,
}

/// Response for successful operations.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

/// Request to submit a SAS confirmation (or abort).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SubmitConfirmationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_attestation: Option<String>,
    #[serde(default)]
    pub aborted: bool,
}

/// Response when polling for confirmation.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct GetConfirmationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_attestation: Option<String>,
    #[serde(default)]
    pub aborted: bool,
}
