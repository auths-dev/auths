use crate::codec::CesrCodec;
use crate::error::KeriTranslationError;

/// The 44-character `#` placeholder injected into the `d` field before hashing.
#[allow(dead_code)]
pub const SAID_PLACEHOLDER: &str = "############################################";

/// Computes a spec-compliant SAID for a KERI event.
///
/// Args:
/// * `codec`: The CESR codec for digest encoding.
/// * `event`: The event as a JSON object.
pub fn compute_spec_said(
    _codec: &dyn CesrCodec,
    _event: &serde_json::Value,
) -> Result<String, KeriTranslationError> {
    todo!("implemented in fn-14.3")
}

/// Verifies that an event's `d` field matches the spec-compliant SAID.
///
/// Args:
/// * `codec`: The CESR codec.
/// * `event`: The event JSON with a populated `d` field.
pub fn verify_spec_said(
    _codec: &dyn CesrCodec,
    _event: &serde_json::Value,
) -> Result<(), KeriTranslationError> {
    todo!("implemented in fn-14.3")
}
