use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::error::KeriTranslationError;

/// The 44-character `#` placeholder injected into the `d` field (and `i` field
/// for inception events) before hashing. Matches the length of a CESR-qualified
/// Blake3-256 digest (`E` + 43 chars base64url = 44 chars).
pub const SAID_PLACEHOLDER: &str = "############################################";

/// Computes a spec-compliant SAID for a KERI event.
///
/// The algorithm:
/// 1. Set `d` to the 44-char `#` placeholder.
/// 2. For inception events (`t == "icp"`), also set `i` to the placeholder.
/// 3. Remove the `x` field entirely (signatures are detached).
/// 4. Serialize with `serde_json::to_vec` (insertion-order, NOT json-canon).
/// 5. Blake3-256 hash the bytes.
/// 6. CESR-encode the digest: `E` derivation code + base64url-no-pad (Blake3-256).
///
/// Args:
/// * `event`: The event as a JSON object.
pub fn compute_spec_said(event: &serde_json::Value) -> Result<String, KeriTranslationError> {
    let mut obj = event
        .as_object()
        .ok_or(KeriTranslationError::MissingField {
            field: "root object",
        })?
        .clone();

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

    let serialized = serde_json::to_vec(&serde_json::Value::Object(obj))
        .map_err(KeriTranslationError::SerializationFailed)?;

    let hash = blake3::hash(&serialized);
    Ok(format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes())))
}

/// Verifies that an event's `d` field matches the spec-compliant SAID.
///
/// Args:
/// * `event`: The event JSON with a populated `d` field.
pub fn verify_spec_said(event: &serde_json::Value) -> Result<(), KeriTranslationError> {
    let found = event
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or(KeriTranslationError::MissingField { field: "d" })?
        .to_string();

    let computed = compute_spec_said(event)?;

    if computed != found {
        return Err(KeriTranslationError::SaidMismatch { computed, found });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn said_has_correct_length() {
        let event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": []
        });
        let said = compute_spec_said(&event).unwrap();
        assert_eq!(said.len(), 44);
        assert!(said.starts_with('E'));
    }

    #[test]
    fn said_is_deterministic() {
        let event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "rot",
            "d": "",
            "i": "EExistingPrefix",
            "s": "1",
            "p": "EPreviousSaid",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": []
        });
        let said1 = compute_spec_said(&event).unwrap();
        let said2 = compute_spec_said(&event).unwrap();
        assert_eq!(said1, said2);
    }

    #[test]
    fn said_ignores_x_field() {
        let event_with_x = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": [],
            "x": "abcdef1234567890"
        });
        let event_without_x = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": []
        });
        let said_with = compute_spec_said(&event_with_x).unwrap();
        let said_without = compute_spec_said(&event_without_x).unwrap();
        assert_eq!(said_with, said_without, "x field must not affect SAID");
    }

    #[test]
    fn inception_applies_i_placeholder() {
        let event_a = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "some_prefix_a",
            "s": "0",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": []
        });
        let event_b = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "some_prefix_b",
            "s": "0",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": []
        });
        let said_a = compute_spec_said(&event_a).unwrap();
        let said_b = compute_spec_said(&event_b).unwrap();
        assert_eq!(
            said_a, said_b,
            "inception SAID must be independent of initial i value"
        );
    }

    #[test]
    fn verify_spec_said_accepts_correct() {
        let event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "rot",
            "d": "",
            "i": "EExistingPrefix",
            "s": "1",
            "p": "EPreviousSaid",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": []
        });
        let said = compute_spec_said(&event).unwrap();
        let mut event_with_said = event.clone();
        event_with_said["d"] = serde_json::Value::String(said);
        assert!(verify_spec_said(&event_with_said).is_ok());
    }

    #[test]
    fn verify_spec_said_rejects_wrong() {
        let event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "rot",
            "d": "Ewrong_said_value_that_doesnt_match_at_all!",
            "i": "EExistingPrefix",
            "s": "1",
            "p": "EPreviousSaid",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": []
        });
        assert!(verify_spec_said(&event).is_err());
    }
}
