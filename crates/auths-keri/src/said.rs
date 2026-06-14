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

    /// Whether this protocol's inception events *can* carry a self-addressing
    /// prefix in `i` (a prefix derived from the event SAID, blanked during
    /// SAID-ification).
    ///
    /// KERI inception events (`icp`/`dip`) and backerless TEL registry inception
    /// (`vcp`) derive their prefix from the SAID, so a self-addressing `i` is
    /// blanked. ACDC `i` is the *issuer* AID (an external reference), so it is
    /// never blanked — only event protocols consult the `t` field.
    ///
    /// Note: this gates only the protocol/event-type; whether `i` is *actually*
    /// self-addressing for a given event is decided per-value by
    /// [`prefix_is_self_addressing`], because KERI also admits basic-prefix
    /// inceptions where `i` is a public key and must be kept during hashing.
    fn blanks_inception_prefix(self) -> bool {
        matches!(self, Protocol::Keri)
    }
}

/// Whether an inception event's current `i` value is a *self-addressing* prefix
/// (one derived from the event SAID) — the only case in which `i` is blanked
/// before hashing.
///
/// KERI admits two inception prefix kinds for the same keys:
///
/// * **self-addressing** — `i` is the SAID itself (a Blake3-256 digest, CESR
///   code `E`), or, on the emit path, the as-yet-unfilled SAID
///   [`SAID_PLACEHOLDER`]. keripy blanks `i` along with `d` before hashing.
/// * **basic** — `i` is the controlling public key (e.g. an Ed25519 verkey,
///   CESR code `D`/`B`, or a P-256/secp256k1 key, codes `1AAB`/`1AAC`…). It is
///   *not* derived from the SAID, so keripy 1.3.4 keeps `i` present during
///   hashing exactly as any other field.
///
/// Classifying by the value's CESR derivation code (parse, don't validate)
/// rather than by event type lets auths reproduce keripy's SAID byte-exact for
/// *either* prefix kind it ingests, while still emitting only self-addressing
/// AIDs itself.
///
/// Self-addressing `i` is one of:
/// * **empty** — the auths *emit* path (`finalize_icp_event`) hashes the event
///   with `i` unset, then fills `i = d` afterwards; an unset `i` is an
///   as-yet-underived self-addressing prefix, never a basic one (auths emits
///   only self-addressing AIDs).
/// * the [`SAID_PLACEHOLDER`] — the explicit "`d`/`i` to be filled" marker.
/// * a digest prefix (`E…`, Blake3-256) — an already-filled self-addressing AID.
///
/// Anything else is a key prefix (a verkey: `D`/`B`/`1AAB`…) and therefore a
/// *basic* prefix, which keripy keeps during hashing — so auths must too. This
/// mirrors the discriminator `finalize_icp_event` already uses to decide
/// whether to set `i = d`.
fn prefix_is_self_addressing(i: &str) -> bool {
    i.is_empty() || i == SAID_PLACEHOLDER || i.starts_with('E')
}

/// Computes a spec-compliant SAID for a KERI event (`KERI10JSON` protocol tag).
///
/// Thin wrapper over [`compute_said_with_protocol`] pinned to [`Protocol::Keri`];
/// every existing KEL call site stays on this default so KEL SAIDs are unchanged.
///
/// The algorithm (Trust over IP KERI v0.9):
/// 1. Set `d` to the 44-char `#` placeholder.
/// 2. For self-addressing inception events (`t` in `icp`/`dip`/`vcp`), also set
///    `i` to the placeholder.
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
    // Blank `i` only when this is a self-addressing inception: the event type is
    // an inception (`icp`/`dip`/`vcp`) AND its `i` is actually derived from the
    // SAID (a digest prefix or the unfilled placeholder). A basic-prefix
    // inception carries a public key in `i`, which keripy keeps during hashing —
    // so auths must keep it too, or it computes a confidently-wrong SAID.
    let inception_prefix = obj.get("i").and_then(|v| v.as_str()).unwrap_or("");
    let blank_prefix = protocol.blanks_inception_prefix()
        && matches!(event_type, "icp" | "dip" | "vcp")
        && prefix_is_self_addressing(inception_prefix);

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
            // delegated inception (`dip`) and backerless TEL registry inception
            // (`vcp`): blank `i` so the digest is computed over the placeholder,
            // not the derived prefix.
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

    /// A *self-addressing* inception blanks `i`, so its SAID is independent of
    /// the particular (digest-coded) `i` value it carries — including the two
    /// emit-path forms, the [`SAID_PLACEHOLDER`] and an already-filled `E…`
    /// prefix.
    ///
    /// This is the corrected invariant: it holds *only* for self-addressing
    /// prefixes. A basic prefix (a verkey in `i`) is kept during hashing and so
    /// is NOT interchangeable — see [`basic_prefix_inception_keeps_i_matches_keripy`].
    #[test]
    fn self_addressing_inception_said_independent_of_i() {
        let event_placeholder = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": SAID_PLACEHOLDER,
            "s": "0",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": []
        });
        let event_digest = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J",
            "s": "0",
            "kt": "1",
            "k": ["DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "nt": "1",
            "n": ["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            "bt": "0",
            "b": [],
            "a": []
        });
        let said_placeholder = compute_said(&event_placeholder).unwrap();
        let said_digest = compute_said(&event_digest).unwrap();
        assert_eq!(
            said_placeholder, said_digest,
            "self-addressing inception SAID must be independent of the digest i value"
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

    /// keripy oracle (1.3.4): a *basic-prefix* inception keeps `i` (the verkey)
    /// during hashing, so its SAID differs from the self-addressing form.
    ///
    /// Vector: `eventing.incept(keys=[ed.qb64])` (default basic prefix), where
    /// `ed.qb64 == "DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"`. Cross-checked
    /// by the interop suite (`interop/vectors/kel/icp-basic.json`, gap IOP-L1d).
    #[test]
    fn basic_prefix_inception_keeps_i_matches_keripy() {
        let raw = r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EAAD4cS7l9pm_N8JM9UsVeAZhwCIaDkSU341hbhHJbSf","i":"DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f","s":"0","kt":"1","k":["DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}"#;
        let event: serde_json::Value = serde_json::from_str(raw).unwrap();
        let said = compute_said(&event).unwrap();
        assert_eq!(
            said.as_str(),
            "EAAD4cS7l9pm_N8JM9UsVeAZhwCIaDkSU341hbhHJbSf",
            "basic-prefix icp SAID must match keripy (i kept, not blanked)"
        );
        // verify_said must accept the keripy event as-is.
        assert!(verify_said(&event).is_ok());
    }

    /// keripy oracle (1.3.4): a *self-addressing* inception still blanks `i`
    /// (it is the SAID), so this path is unchanged by the basic-prefix fix.
    ///
    /// Vector: `eventing.incept(keys=[ed.qb64], code=Blake3_256)` — `i == d`.
    /// Cross-checked by `interop/vectors/kel/icp-selfaddr.json` (gap IOP-L1a).
    #[test]
    fn self_addressing_inception_blanks_i_matches_keripy() {
        let raw = r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J","i":"EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J","s":"0","kt":"1","k":["DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}"#;
        let event: serde_json::Value = serde_json::from_str(raw).unwrap();
        let said = compute_said(&event).unwrap();
        assert_eq!(
            said.as_str(),
            "EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J",
            "self-addressing icp SAID must still blank i and match keripy"
        );
        assert!(verify_said(&event).is_ok());
    }

    /// The emit path (auths minting its own AID) fills `i` only after the SAID is
    /// known, so `compute_said` sees the [`SAID_PLACEHOLDER`] in `i` and must
    /// still treat it as self-addressing (blank it). Equivalently, an empty `i`
    /// or the placeholder produce the same SAID as the filled self-addressing `i`.
    #[test]
    fn placeholder_inception_prefix_is_self_addressing() {
        let base = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "s": "0",
            "kt": "1",
            "k": ["DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"],
            "nt": "0",
            "n": [],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });
        // i = placeholder
        let mut with_placeholder = base.clone();
        with_placeholder["i"] = serde_json::Value::String(SAID_PLACEHOLDER.to_string());
        // i = a digest prefix (E-coded)
        let mut with_digest = base.clone();
        with_digest["i"] =
            serde_json::Value::String("EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J".to_string());
        assert_eq!(
            compute_said(&with_placeholder).unwrap(),
            compute_said(&with_digest).unwrap(),
            "placeholder and E-coded i are both self-addressing — same SAID"
        );
        assert!(prefix_is_self_addressing(SAID_PLACEHOLDER));
        assert!(prefix_is_self_addressing(
            "EOoC9AuwxiwcyUDsa2yNAaZOVWqfiAt4o3R31_8K2Z1J"
        ));
        assert!(!prefix_is_self_addressing(
            "DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
        ));
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
