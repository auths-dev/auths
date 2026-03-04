use auths_verifier::keri::{KeriEvent, Prefix, Said};
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

/// Converts an Auths internal event into a spec-compliant serialized event.
///
/// Extracts the `x` signature (base64url-no-pad), removes it from the body,
/// computes the version string and SAID per spec, and returns the serialized
/// body alongside the detached signature.
///
/// Args:
/// * `codec`: The CESR codec.
/// * `event`: The internal Auths event.
///
/// Usage:
/// ```ignore
/// let serialized = serialize_for_cesr(&codec, &keri_event)?;
/// ```
pub fn serialize_for_cesr(
    codec: &dyn CesrCodec,
    event: &KeriEvent,
) -> Result<SerializedEvent, KeriTranslationError> {
    let mut event = event.clone();

    let sig_str = match &event {
        KeriEvent::Inception(e) => e.x.clone(),
        KeriEvent::Rotation(e) => e.x.clone(),
        KeriEvent::Interaction(e) => e.x.clone(),
    };
    let signature_bytes = if sig_str.is_empty() {
        None
    } else {
        Some(URL_SAFE_NO_PAD.decode(&sig_str).map_err(|e| {
            KeriTranslationError::SignatureParseError(format!("base64url decode: {e}"))
        })?)
    };

    // Clear x and set d/i to placeholders.
    match &mut event {
        KeriEvent::Inception(icp) => {
            icp.x = String::new();
            icp.d = Said::new_unchecked(SAID_PLACEHOLDER.to_string());
            icp.i = Prefix::new_unchecked(SAID_PLACEHOLDER.to_string());
        }
        KeriEvent::Rotation(rot) => {
            rot.x = String::new();
            rot.d = Said::new_unchecked(SAID_PLACEHOLDER.to_string());
        }
        KeriEvent::Interaction(ixn) => {
            ixn.x = String::new();
            ixn.d = Said::new_unchecked(SAID_PLACEHOLDER.to_string());
        }
    }

    // Serialize with placeholders → measure byte count → version string.
    // Placeholder "000000" and hex size are both 6 chars, so byte count is stable.
    let placeholder_bytes =
        serde_json::to_vec(&event).map_err(KeriTranslationError::SerializationFailed)?;
    let size = placeholder_bytes.len();
    let version_string = format!("KERI10JSON{size:06x}_");

    set_version(&mut event, &version_string);

    // Serialize with version string + placeholders → hash → SAID.
    let for_said = serde_json::to_vec(&event).map_err(KeriTranslationError::SerializationFailed)?;
    let hash = blake3::hash(&for_said);
    let said = codec.encode_digest(hash.as_bytes(), DigestType::Blake3_256)?;

    // Replace placeholders with computed SAID (same 44-char length → stable byte count).
    match &mut event {
        KeriEvent::Inception(icp) => {
            icp.d = Said::new_unchecked(said.clone());
            icp.i = Prefix::new_unchecked(said.clone());
        }
        KeriEvent::Rotation(rot) => {
            rot.d = Said::new_unchecked(said.clone());
        }
        KeriEvent::Interaction(ixn) => {
            ixn.d = Said::new_unchecked(said.clone());
        }
    }

    let body_bytes =
        serde_json::to_vec(&event).map_err(KeriTranslationError::SerializationFailed)?;

    Ok(SerializedEvent {
        body_bytes,
        said,
        signature_bytes,
        signature_key_index: 0,
    })
}

fn set_version(event: &mut KeriEvent, version: &str) {
    match event {
        KeriEvent::Inception(icp) => icp.v = version.to_string(),
        KeriEvent::Rotation(rot) => rot.v = version.to_string(),
        KeriEvent::Interaction(ixn) => ixn.v = version.to_string(),
    }
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
