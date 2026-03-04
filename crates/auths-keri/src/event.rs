use crate::codec::CesrCodec;
use crate::error::KeriTranslationError;

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
/// Args:
/// * `codec`: The CESR codec.
/// * `event`: The internal Auths event as a JSON value.
pub fn serialize_for_cesr(
    _codec: &dyn CesrCodec,
    _event: &serde_json::Value,
) -> Result<SerializedEvent, KeriTranslationError> {
    todo!("implemented in fn-14.5")
}

/// Re-encodes a CESR-qualified key back to raw bytes for internal use.
///
/// Args:
/// * `codec`: The CESR codec.
/// * `qualified`: The CESR-qualified key string.
pub fn decode_cesr_key(
    _codec: &dyn CesrCodec,
    _qualified: &str,
) -> Result<Vec<u8>, KeriTranslationError> {
    todo!("implemented in fn-14.5")
}
