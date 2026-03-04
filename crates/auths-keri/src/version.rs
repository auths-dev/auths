use crate::error::KeriTranslationError;

const PLACEHOLDER_VERSION: &str = "KERI10JSON000000_";

/// Computes the KERI version string for a serialized event body.
///
/// The version string format is `KERI10JSON{size:06x}_` where `size` is
/// the total byte length of the JSON event body including the version string.
/// The size field is always 6 hex chars, so a single pass is sufficient
/// (the placeholder and final string have identical widths).
///
/// Args:
/// * `event`: The event JSON object (with a placeholder `v` field).
///
/// Usage:
/// ```ignore
/// let (version_string, serialized_bytes) = compute_version_string(&event_json)?;
/// ```
pub fn compute_version_string(
    event: &serde_json::Value,
) -> Result<(String, Vec<u8>), KeriTranslationError> {
    let mut obj = event
        .as_object()
        .ok_or(KeriTranslationError::VersionStringError(
            "event must be a JSON object".into(),
        ))?
        .clone();

    obj.insert(
        "v".to_string(),
        serde_json::Value::String(PLACEHOLDER_VERSION.to_string()),
    );
    let first_pass = serde_json::to_vec(&serde_json::Value::Object(obj.clone()))
        .map_err(KeriTranslationError::SerializationFailed)?;
    let size = first_pass.len();

    let version_string = format!("KERI10JSON{size:06x}_");

    if version_string.len() != 17 {
        return Err(KeriTranslationError::VersionStringError(format!(
            "version string has unexpected length {}: '{}'",
            version_string.len(),
            version_string,
        )));
    }

    obj.insert(
        "v".to_string(),
        serde_json::Value::String(version_string.clone()),
    );
    let final_bytes = serde_json::to_vec(&serde_json::Value::Object(obj))
        .map_err(KeriTranslationError::SerializationFailed)?;

    if final_bytes.len() != size {
        return Err(KeriTranslationError::VersionStringError(format!(
            "size mismatch after version string insertion: expected {}, got {}",
            size,
            final_bytes.len(),
        )));
    }

    Ok((version_string, final_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_format() {
        let event = serde_json::json!({
            "v": "",
            "t": "icp",
            "d": "############################################",
            "i": "############################################",
            "s": "0",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": []
        });
        let (vs, bytes) = compute_version_string(&event).unwrap();
        assert!(vs.starts_with("KERI10JSON"));
        assert!(vs.ends_with('_'));
        assert_eq!(vs.len(), 17);

        let hex_part = &vs[10..16];
        let declared_size = usize::from_str_radix(hex_part, 16).unwrap();
        assert_eq!(declared_size, bytes.len());
    }

    #[test]
    fn version_string_size_varies() {
        let small = serde_json::json!({"v":"","t":"icp","d":"","i":"","s":"0","kt":"1","k":[],"nt":"1","n":[],"bt":"0","b":[],"a":[]});
        let large = serde_json::json!({"v":"","t":"icp","d":"","i":"","s":"0","kt":"1","k":["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","DBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"],"nt":"1","n":["E1111111111111111111111111111111111111111111","E2222222222222222222222222222222222222222222"],"bt":"0","b":[],"a":[]});
        let (vs_small, _) = compute_version_string(&small).unwrap();
        let (vs_large, _) = compute_version_string(&large).unwrap();
        assert_ne!(
            vs_small, vs_large,
            "different payloads must produce different sizes"
        );
    }
}
