use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::codec::{CesrCodec, DigestType};
use crate::error::KeriTranslationError;
use crate::said::SAID_PLACEHOLDER;

/// A KERI event serialized for CESR export with its signature detached.
#[derive(Debug, Clone)]
pub struct SerializedEvent {
    /// The JSON event body with `d` (and `i` for inception) populated
    /// and `x` removed.
    pub body_bytes: Vec<u8>,

    /// The computed SAID for this event.
    pub said: String,

    /// The detached signature bytes (raw Ed25519, 64 bytes).
    pub signature_bytes: Option<Vec<u8>>,

    /// The key index for the signature (0 for single-sig).
    pub signature_key_index: u32,
}

/// Converts a KERI event JSON value into a spec-compliant serialized event.
///
/// Extracts the `x` signature (base64url-no-pad), removes it from the body,
/// computes the version string and SAID per spec, and returns the serialized
/// body alongside the detached signature.
///
/// Args:
/// * `codec`: The CESR codec.
/// * `event`: The KERI event as a JSON object.
///
/// Usage:
/// ```ignore
/// let serialized = serialize_for_cesr(&codec, &event_json)?;
/// ```
pub fn serialize_for_cesr(
    codec: &dyn CesrCodec,
    event: &serde_json::Value,
) -> Result<SerializedEvent, KeriTranslationError> {
    let obj = event
        .as_object()
        .ok_or(KeriTranslationError::MissingField {
            field: "root object",
        })?;

    // Extract signature before clearing it.
    let sig_str = obj
        .get("x")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let signature_bytes = if sig_str.is_empty() {
        None
    } else {
        Some(URL_SAFE_NO_PAD.decode(&sig_str).map_err(|e| {
            KeriTranslationError::SignatureParseError(format!("base64url decode: {e}"))
        })?)
    };

    // Build mutable copy, clear x, insert d/i placeholders.
    let mut obj = obj.clone();
    obj.remove("x");
    obj.insert(
        "d".to_string(),
        serde_json::Value::String(SAID_PLACEHOLDER.to_string()),
    );

    let event_type = obj
        .get("t")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if event_type == "icp" {
        obj.insert(
            "i".to_string(),
            serde_json::Value::String(SAID_PLACEHOLDER.to_string()),
        );
    }

    // Measure byte count → version string.
    // Placeholder "000000" and hex size are both 6 chars, so byte count is stable.
    let placeholder_bytes = serde_json::to_vec(&serde_json::Value::Object(obj.clone()))
        .map_err(KeriTranslationError::SerializationFailed)?;
    let size = placeholder_bytes.len();
    let version_string = format!("KERI10JSON{size:06x}_");
    obj.insert("v".to_string(), serde_json::Value::String(version_string));

    // Serialize with version string + placeholders → hash → SAID.
    let for_said = serde_json::to_vec(&serde_json::Value::Object(obj.clone()))
        .map_err(KeriTranslationError::SerializationFailed)?;
    let hash = blake3::hash(&for_said);
    let said = codec.encode_digest(hash.as_bytes(), DigestType::Blake3_256)?;

    // Replace placeholders with computed SAID (same 44-char length → stable byte count).
    obj.insert("d".to_string(), serde_json::Value::String(said.clone()));
    if event_type == "icp" {
        obj.insert("i".to_string(), serde_json::Value::String(said.clone()));
    }

    let body_bytes = serde_json::to_vec(&serde_json::Value::Object(obj))
        .map_err(KeriTranslationError::SerializationFailed)?;

    Ok(SerializedEvent {
        body_bytes,
        said,
        signature_bytes,
        signature_key_index: 0,
    })
}

/// Re-encodes a CESR-qualified key back to raw bytes for internal use.
///
/// Args:
/// * `codec`: The CESR codec.
/// * `qualified`: The CESR-qualified key string.
pub fn decode_cesr_key(
    codec: &dyn CesrCodec,
    qualified: &str,
) -> Result<Vec<u8>, KeriTranslationError> {
    let decoded = codec.decode_qualified(qualified)?;
    Ok(decoded.raw)
}
