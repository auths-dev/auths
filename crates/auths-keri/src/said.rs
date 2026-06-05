use crate::error::KeriTranslationError;
use crate::types::Said;

/// The 44-character `#` placeholder injected into the `d` field (and `i` field
/// for inception events) before hashing. Matches the length of a CESR-qualified
/// Blake3-256 digest (`E` + 43 chars base64url = 44 chars).
pub const SAID_PLACEHOLDER: &str = "############################################";

/// The 17-character protocol/version tag families used by SAID-ification.
///
/// KERI events (KEL: `icp`/`rot`/`ixn`/`dip`/`drt`) carry `KERI10JSON…`; ACDC
/// credentials carry `ACDC10JSON…`. Both share the identical 17-char layout
/// (`<TAG>10JSON{size:06x}_`), so the two-pass size assertion in
/// [`compute_said_with_protocol`] holds unchanged for either family.
///
/// Usage:
/// ```ignore
/// let said = compute_said_with_protocol(&acdc_json, Protocol::Acdc)?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// KERI key-event protocol (`KERI10JSON…`) — the default for all KEL events.
    Keri,
    /// ACDC credential protocol (`ACDC10JSON…`).
    Acdc,
}

impl Protocol {
    /// The 17-char placeholder version string for this protocol (size field zeroed).
    fn version_placeholder(self) -> &'static str {
        match self {
            Protocol::Keri => "KERI10JSON000000_",
            Protocol::Acdc => "ACDC10JSON000000_",
        }
    }

    /// The 4-char protocol code prefixing the version string (`KERI` / `ACDC`).
    fn code(self) -> &'static str {
        match self {
            Protocol::Keri => "KERI",
            Protocol::Acdc => "ACDC",
        }
    }

    /// Whether the `i` field is self-addressing (blanked during SAID-ification).
    ///
    /// KERI inception events (`icp`/`dip`) derive their prefix from the SAID, so
    /// `i` is blanked. ACDC `i` is the *issuer* AID (an external reference), so it
    /// is never blanked — only event protocols consult the `t` field.
    fn blanks_inception_prefix(self) -> bool {
        matches!(self, Protocol::Keri)
    }
}

/// Computes a spec-compliant SAID for a KERI event (`KERI10JSON` protocol tag).
///
/// Thin wrapper over [`compute_said_with_protocol`] pinned to [`Protocol::Keri`];
/// every existing KEL call site stays on this default so KEL SAIDs are unchanged.
///
/// The algorithm (Trust over IP KERI v0.9):
/// 1. Set `d` to the 44-char `#` placeholder.
/// 2. For inception events (`t == "icp"`), also set `i` to the placeholder.
/// 3. Remove the `x` field entirely (signatures are detached from the digest).
/// 4. Serialize with `serde_json::to_vec` (insertion-order, NOT json-canon).
/// 5. Blake3-256 hash the bytes.
/// 6. CESR-encode the digest: `E` derivation code + base64url-no-pad.
///
/// **Why insertion-order, not canonical JSON?** KERI specifies that SAIDs
/// are computed over the insertion-order serialization of the event object.
/// Using `json_canon` (RFC 8785 sorted keys) would produce different SAIDs
/// and break interoperability with other KERI implementations. This depends
/// on `serde_json`'s `preserve_order` feature being enabled in Cargo.toml
/// (which activates `IndexMap` instead of `BTreeMap` for `serde_json::Map`).
///
/// Note: Attestation SAIDs (in `auths-id/src/keri/anchor.rs`) use `json_canon`
/// — that is correct because attestations are an auths-specific format not
/// constrained by the KERI spec.
///
/// Args:
/// * `event`: The event as a JSON object.
pub fn compute_said(event: &serde_json::Value) -> Result<Said, KeriTranslationError> {
    compute_said_with_protocol(event, Protocol::Keri)
}

/// Computes a spec-compliant SAID for a SAID'd JSON object under a chosen protocol.
///
/// Generalises [`compute_said`] over the protocol/version tag (D7): KEL events use
/// [`Protocol::Keri`] (`KERI10JSON…`); ACDC credentials use [`Protocol::Acdc`]
/// (`ACDC10JSON…`). The placeholder + two-pass size machinery is identical because
/// both tags are exactly 17 chars wide.
///
/// Args:
/// * `event`: The SAID'd object as JSON (must contain or accept a `d` field).
/// * `protocol`: Which protocol/version tag and self-addressing rules to apply.
///
/// Usage:
/// ```ignore
/// let said = compute_said_with_protocol(&acdc_json, Protocol::Acdc)?;
/// ```
pub fn compute_said_with_protocol(
    event: &serde_json::Value,
    protocol: Protocol,
) -> Result<Said, KeriTranslationError> {
    let obj = event
        .as_object()
        .ok_or(KeriTranslationError::MissingField {
            field: "root object",
        })?;

    let placeholder = serde_json::Value::String(SAID_PLACEHOLDER.to_string());
    let event_type = obj.get("t").and_then(|v| v.as_str()).unwrap_or("");
    let blank_prefix =
        protocol.blanks_inception_prefix() && (event_type == "icp" || event_type == "dip");

    // Rebuild the map with spec-compliant placeholders and field ordering.
    let mut new_obj = serde_json::Map::new();

    for (k, v) in obj {
        if k == "x" {
            // Signatures are detached from the digest (legacy field, skip)
            continue;
        } else if k == "d" {
            new_obj.insert("d".to_string(), placeholder.clone());
        } else if k == "i" && blank_prefix {
            // Inception events are self-addressing (prefix == SAID), including
            // delegated inception (`dip`): blank `i` so the digest is computed
            // over the placeholder, not the derived prefix.
            new_obj.insert("i".to_string(), placeholder.clone());
        } else {
            new_obj.insert(k.clone(), v.clone());
        }
    }

    // Ensure d is always present (in case input omitted it)
    if !new_obj.contains_key("d") {
        new_obj.insert("d".to_string(), placeholder.clone());
    }

    // Two-pass version string: compute byte count then re-serialize
    let version_placeholder = protocol.version_placeholder();
    new_obj.insert(
        "v".to_string(),
        serde_json::Value::String(version_placeholder.to_string()),
    );

    let pass1 = serde_json::to_vec(&serde_json::Value::Object(new_obj.clone()))
        .map_err(KeriTranslationError::SerializationFailed)?;

    // Size is stable: placeholder and real version string are both 17 chars
    let version_string = format!("{}10JSON{:06x}_", protocol.code(), pass1.len());
    debug_assert_eq!(version_string.len(), version_placeholder.len());
    new_obj.insert("v".to_string(), serde_json::Value::String(version_string));

    let serialized = serde_json::to_vec(&serde_json::Value::Object(new_obj))
        .map_err(KeriTranslationError::SerializationFailed)?;

    let hash = blake3::hash(&serialized);
    // CESR-encode the digest (keripy-identical alignment), not naive `E`+base64url.
    #[allow(clippy::expect_used)] // INVARIANT: a 32-byte Blake3 digest always CESR-encodes
    let said = crate::cesr_encode::encode_blake3_digest(hash.as_bytes())
        .expect("32-byte Blake3 digest always encodes as a CESR Blake3_256 SAID");
    Ok(Said::new_unchecked(said))
}

/// Computes the SAID of a nested SAID'd section that carries no version string.
///
/// Unlike [`compute_said`], a section (e.g. an ACDC `a` attributes block) has no
/// `v` field — its SAID is a plain Blake3-256 over the insertion-order
/// serialization with `d` placeholder-filled. This mirrors keripy's
/// `Saider.saidify(sad=section, label="d")` for blockless sub-objects.
///
/// Args:
/// * `section`: The section as a JSON object (`d` is placeholder-filled before hashing).
///
/// Usage:
/// ```ignore
/// let attr_said = compute_section_said(&attributes_json)?;
/// ```
pub fn compute_section_said(section: &serde_json::Value) -> Result<Said, KeriTranslationError> {
    let obj = section
        .as_object()
        .ok_or(KeriTranslationError::MissingField {
            field: "section object",
        })?;

    let placeholder = serde_json::Value::String(SAID_PLACEHOLDER.to_string());
    let mut new_obj = serde_json::Map::new();
    for (k, v) in obj {
        if k == "d" {
            new_obj.insert("d".to_string(), placeholder.clone());
        } else {
            new_obj.insert(k.clone(), v.clone());
        }
    }
    if !new_obj.contains_key("d") {
        new_obj.insert("d".to_string(), placeholder.clone());
    }

    let serialized = serde_json::to_vec(&serde_json::Value::Object(new_obj))
        .map_err(KeriTranslationError::SerializationFailed)?;
    let hash = blake3::hash(&serialized);
    #[allow(clippy::expect_used)] // INVARIANT: a 32-byte Blake3 digest always CESR-encodes
    let said = crate::cesr_encode::encode_blake3_digest(hash.as_bytes())
        .expect("32-byte Blake3 digest always encodes as a CESR Blake3_256 SAID");
    Ok(Said::new_unchecked(said))
}

/// Verifies that an event's `d` field matches the spec-compliant SAID.
///
/// Args:
/// * `event`: The event JSON with a populated `d` field.
pub fn verify_said(event: &serde_json::Value) -> Result<(), KeriTranslationError> {
    let found = event
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or(KeriTranslationError::MissingField { field: "d" })?
        .to_string();

    let computed = compute_said(event)?;

    if computed.as_str() != found {
        return Err(KeriTranslationError::SaidMismatch {
            computed: computed.into_inner(),
            found,
        });
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
        let said = compute_said(&event).unwrap();
        assert_eq!(said.as_str().len(), 44);
        assert!(said.as_str().starts_with('E'));
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
        let said1 = compute_said(&event).unwrap();
        let said2 = compute_said(&event).unwrap();
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
        let said_with = compute_said(&event_with_x).unwrap();
        let said_without = compute_said(&event_without_x).unwrap();
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
        let said_a = compute_said(&event_a).unwrap();
        let said_b = compute_said(&event_b).unwrap();
        assert_eq!(
            said_a, said_b,
            "inception SAID must be independent of initial i value"
        );
    }

    #[test]
    fn verify_said_accepts_correct() {
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
        let said = compute_said(&event).unwrap();
        let mut event_with_said = event.clone();
        event_with_said["d"] = serde_json::Value::String(said.into_inner());
        assert!(verify_said(&event_with_said).is_ok());
    }

    #[test]
    fn verify_said_rejects_wrong() {
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
        assert!(verify_said(&event).is_err());
    }

    /// Guard: `serde_json::Map` must use `IndexMap` (preserve insertion order).
    ///
    /// If the `preserve_order` feature is accidentally removed from
    /// `auths-keri/Cargo.toml`, `serde_json::Map` falls back to `BTreeMap`
    /// (sorted keys), silently breaking all existing SAIDs. This test catches
    /// that by verifying key order survives a round-trip.
    #[test]
    fn serde_json_map_preserves_insertion_order() {
        let json = r#"{"z":"last","a":"first","m":"middle"}"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        let keys: Vec<&str> = parsed
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            keys,
            vec!["z", "a", "m"],
            "serde_json::Map must preserve insertion order (preserve_order feature required)"
        );
    }
}
