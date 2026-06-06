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
///
/// Pairing is always "add a controller to the shared identity KEL". Key
/// rotation is a local operation on a device's own KEL — it does not flow
/// through pairing sessions at all.
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
    /// Recovery target — populated only by `auths pair --recover`. The DID
    /// of the old device being replaced. The surviving controller's
    /// confirmation triggers a `rot_swap_controller` that drops this DID
    /// and adds the new initiator in a single rotation event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_target: Option<String>,
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
    pub device_ephemeral_pubkey: Base64UrlEncoded,
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
    /// Optional per-pairing subkey chain for controller-correlation
    /// privacy. When present, `device_signing_pubkey` is a fresh
    /// session-only subkey and `subkey_chain.bootstrap_pubkey` holds
    /// the stable phone-level key that signed the subkey binding.
    /// A daemon built with the `subkey-chain-v1` feature verifies the
    /// chain and records `bootstrap_pubkey` as the stable phone
    /// identifier; a daemon built without the feature rejects any
    /// `Some(_)` with an explicit unsupported-extension error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subkey_chain: Option<crate::subkey_chain::SubkeyChain>,
    /// The initiator's device-KEL inception event, base64url-no-pad JSON.
    ///
    /// Both sides validate the other's `icp` before either side signs
    /// the shared-KEL change. The daemon is an untrusted relay and does
    /// not inspect this field. `#[serde(default)]` so legacy pair
    /// responses that pre-date mutual inception exchange continue to
    /// deserialize (the responder-side code must still enforce presence
    /// when it expects the inception data).
    #[serde(default)]
    pub initiator_inception_event: String,
    /// The responder's device-KEL inception event, base64url-no-pad JSON.
    #[serde(default)]
    pub responder_inception_event: String,
    /// Shared-KEL inception event — populated by the Mac (initiator)
    /// when no shared identity KEL exists yet (first-ever pair). The
    /// responder validates self-consistency + Mac's signature, then
    /// replicates. Size-capped at 1 KB on serialize to guard against
    /// future multi-sig KEL inceptions overflowing QR capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_kel_inception_event: Option<String>,
}

/// Maximum size in bytes for `SubmitResponseRequest::shared_kel_inception_event`.
///
/// Single-sig P-256 `icp` events are ~300 bytes base64url-encoded; the cap
/// reserves headroom while refusing to silently accept multi-sig inceptions
/// that would overflow QR capacity.
pub const SHARED_KEL_INCEPTION_EVENT_MAX_BYTES: usize = 1024;

impl SubmitResponseRequest {
    /// Validate payload-size invariants that must hold before transmission.
    ///
    /// Args:
    /// * `self`: The request to check.
    ///
    /// Returns `Err` with a diagnostic string when
    /// `shared_kel_inception_event` exceeds [`SHARED_KEL_INCEPTION_EVENT_MAX_BYTES`].
    ///
    /// Usage:
    /// ```ignore
    /// req.validate()?;
    /// ```
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref inc) = self.shared_kel_inception_event
            && inc.len() > SHARED_KEL_INCEPTION_EVENT_MAX_BYTES
        {
            return Err(format!(
                "shared_kel_inception_event is {} bytes, exceeds cap of {} — multi-sig KEL inception would overflow QR capacity",
                inc.len(),
                SHARED_KEL_INCEPTION_EVENT_MAX_BYTES,
            ));
        }
        Ok(())
    }
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
