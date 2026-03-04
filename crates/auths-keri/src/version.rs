use crate::error::KeriTranslationError;

/// Computes the KERI version string for a serialized event body.
///
/// The version string format is `KERI10JSON{size:06x}_` where `size` is
/// the total byte length of the JSON event body including the version string.
///
/// Args:
/// * `event`: The event JSON object (with a placeholder `v` field).
///
/// Usage:
/// ```ignore
/// let (version_string, serialized_bytes) = compute_version_string(&event_json)?;
/// ```
pub fn compute_version_string(
    _event: &serde_json::Value,
) -> Result<(String, Vec<u8>), KeriTranslationError> {
    todo!("implemented in fn-14.4")
}
