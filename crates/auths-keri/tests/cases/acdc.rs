//! ACDC (Epic F.1) conformance + keripy 1.3.4 byte-interop vectors.
//!
//! Asserts the `Acdc {v,d,i,ri,s,a}` type SAID-ifies (nested `a.d` then top-level
//! `d`) byte-equal to keripy 1.3.4 fixtures for BOTH curves (P-256 default +
//! Ed25519), that the version tag is `ACDC10JSON`, that the pinned capability
//! schema SAID is immutable, and that adding a top-level `e` (edges) block re-runs
//! the same algorithm (a v1 credential without `e` keeps its SAID). The KEL-SAID
//! regression lives in `kel_said_still_keri10json`.

use std::path::{Path, PathBuf};

use auths_keri::{
    Acdc, KeriPublicKey, Prefix, Protocol, Said, compute_capability_schema_said, compute_said,
    compute_said_with_protocol,
};
use serde_json::{Map, Value};

const FIXED_DT: &str = "2025-01-01T00:00:00.000000+00:00";

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keripy")
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {} unreadable: {e}", path.display()))
}

fn read_meta(name: &str) -> Value {
    serde_json::from_slice(&read_fixture(name)).expect("meta fixture must be JSON")
}

/// Reconstruct the auths `Acdc` from a keripy fixture's meta, SAID-ified.
fn rebuild_from_meta(meta: &Value) -> Acdc {
    let s = |k: &str| meta[k].as_str().expect("meta string field").to_string();
    let mut data = Map::new();
    data.insert("capability".to_string(), Value::String("sign".to_string()));
    Acdc::new(
        Prefix::new_unchecked(s("issuer_aid")),
        Said::new_unchecked(s("registry_said")),
        Said::new_unchecked(s("schema_said")),
        Prefix::new_unchecked(s("subject_aid")),
        FIXED_DT.to_string(),
        data,
    )
    .saidify()
    .expect("saidify must succeed")
}

/// Self-consistency: an auths-built ACDC verifies its own SAIDs and round-trips
/// through serde with identical wire bytes.
#[test]
fn acdc_said_roundtrips() {
    let meta = read_meta("credential.p256.meta.json");
    let acdc = rebuild_from_meta(&meta);

    acdc.verify_said()
        .expect("freshly saidified ACDC must verify");

    let wire = acdc.to_wire_bytes().unwrap();
    let parsed: Acdc = serde_json::from_slice(&wire).unwrap();
    let again = parsed.to_wire_bytes().unwrap();
    assert_eq!(wire, again, "ACDC must round-trip through serde unchanged");
    parsed
        .verify_said()
        .expect("round-tripped ACDC must still verify");
}

/// Byte-interop: the auths-built P-256 ACDC is byte-equal to keripy 1.3.4.
#[test]
fn acdc_said_matches_keripy_134_fixture_p256() {
    let meta = read_meta("credential.p256.meta.json");
    let acdc = rebuild_from_meta(&meta);

    assert_eq!(
        acdc.d.as_str(),
        meta["said"].as_str().unwrap(),
        "top-level SAID must match keripy"
    );
    assert_eq!(
        acdc.a.d.as_str(),
        meta["attr_said"].as_str().unwrap(),
        "nested a.d must match keripy"
    );
    assert_eq!(
        acdc.to_wire_bytes().unwrap(),
        read_fixture("credential.p256.json"),
        "serialized ACDC bytes must be byte-equal to keripy fixture"
    );
}

/// Byte-interop: the auths-built Ed25519 ACDC is byte-equal to keripy 1.3.4.
#[test]
fn acdc_said_matches_keripy_134_fixture_ed25519() {
    let meta = read_meta("credential.ed25519.meta.json");
    let acdc = rebuild_from_meta(&meta);

    assert_eq!(acdc.d.as_str(), meta["said"].as_str().unwrap());
    assert_eq!(acdc.a.d.as_str(), meta["attr_said"].as_str().unwrap());
    assert_eq!(
        acdc.to_wire_bytes().unwrap(),
        read_fixture("credential.ed25519.json"),
        "serialized Ed25519 ACDC bytes must be byte-equal to keripy fixture"
    );
}

/// The version string is the ACDC protocol family, not KERI.
#[test]
fn acdc_version_string_is_acdc10json() {
    let acdc = rebuild_from_meta(&read_meta("credential.p256.meta.json"));
    assert!(
        acdc.v.starts_with("ACDC10JSON"),
        "version must be ACDC10JSON family, got {}",
        acdc.v
    );
    assert!(acdc.v.ends_with('_'));
    assert_eq!(acdc.v.len(), 17, "ACDC version string is 17 chars");

    let declared = usize::from_str_radix(&acdc.v[10..16], 16).unwrap();
    assert_eq!(
        declared,
        acdc.to_wire_bytes().unwrap().len(),
        "declared size must equal serialized byte count"
    );
}

/// The nested `a.d` is committed: it is the section SAID of the attributes block
/// and any tamper to a subject claim invalidates it.
#[test]
fn nested_attributes_said_is_committed() {
    let acdc = rebuild_from_meta(&read_meta("credential.p256.meta.json"));
    acdc.verify_said().unwrap();

    let mut tampered = acdc.clone();
    tampered
        .a
        .data
        .insert("capability".to_string(), Value::String("admin".to_string()));
    let err = tampered.verify_said().unwrap_err();
    assert!(
        format!("{err}").contains("attributes"),
        "tampering a subject claim must fail at the attributes SAID layer: {err}"
    );
}

/// The subject `a.i` is a KERI AID and the issuing key carries a curve tag in-band
/// (parseable for both curves) — never dispatched by byte length.
#[test]
fn subject_aid_is_curve_tagged() {
    for (fixture, expected_prefix) in [
        ("credential.p256.meta.json", "1AAJ"),
        ("credential.ed25519.meta.json", "D"),
    ] {
        let meta = read_meta(fixture);
        let acdc = rebuild_from_meta(&meta);

        // Subject is a valid KERI AID (holder-bindable for F.8).
        assert!(
            Prefix::new(acdc.a.i.as_str().to_string()).is_ok(),
            "subject a.i must be a valid KERI AID: {}",
            acdc.a.i
        );
        assert!(
            acdc.a.i.as_str().starts_with('E'),
            "self-addressing holder AID is E-prefixed: {}",
            acdc.a.i
        );

        // The underlying issuing/subject key is curve-tagged in-band and parseable.
        let verkey = meta["subject_verkey"].as_str().unwrap();
        assert!(
            verkey.starts_with(expected_prefix),
            "{fixture}: verkey {verkey} must carry the {expected_prefix} curve tag"
        );
        KeriPublicKey::parse(verkey)
            .unwrap_or_else(|e| panic!("{fixture}: curve-tagged verkey must parse: {e}"));
    }
}

/// Most-compact / additive layout: a v1 credential WITHOUT `e` keeps its SAID, and
/// an edged credential built with the same algorithm has an unchanged `a.d` (the
/// attributes block is untouched). Adding `e` is an additive layout — it changes
/// the top-level `d` because the digest covers the whole body — NOT a SAID-
/// preserving mutation. keripy 1.3.4 is the oracle for both.
#[test]
fn top_level_edge_block_is_additive() {
    let meta = read_meta("credential.p256.meta.json");

    // v1 (no `e`) keeps its SAID across rebuild — additive layout is stable.
    let v1 = rebuild_from_meta(&meta);
    assert_eq!(
        v1.d.as_str(),
        meta["said"].as_str().unwrap(),
        "v1 credential SAID is stable"
    );

    // keripy's edged credential: a.d is unchanged (a untouched); top-level d differs.
    let edged: Value = serde_json::from_slice(&read_fixture("credential.p256.edged.json")).unwrap();
    assert_eq!(
        edged["a"]["d"].as_str().unwrap(),
        meta["attr_said"].as_str().unwrap(),
        "edged a.d unchanged: the attributes block is untouched by adding `e`"
    );
    assert_ne!(
        edged["d"].as_str().unwrap(),
        meta["said"].as_str().unwrap(),
        "adding a top-level `e` re-runs the SAID over the larger body (additive layout)"
    );

    // The same algorithm reproduces the edged top-level SAID byte-for-byte.
    let mut blanked = edged.clone();
    let recomputed = compute_said_with_protocol(&blanked, Protocol::Acdc).unwrap();
    assert_eq!(
        recomputed.as_str(),
        meta["edged_said"].as_str().unwrap(),
        "the ACDC algorithm reproduces keripy's edged SAID"
    );
    // The blanked value was consumed read-only above; keep clippy happy on mutability.
    blanked["d"] = Value::String(recomputed.into_inner());
}

/// The pinned v1 capability schema SAID is immutable and byte-equal to keripy's
/// schema SAID-ification (`coring.Saider(sad=schema, label="$id")`).
#[test]
fn schema_said_is_immutable_fixture() {
    let expected = read_meta("credential.schema.meta.json")["schema_said"]
        .as_str()
        .unwrap()
        .to_string();

    let computed = compute_capability_schema_said().unwrap();
    assert_eq!(
        computed.as_str(),
        expected,
        "embedded capability schema SAID must match keripy fixture"
    );

    // The `s` field of every credential fixture pins exactly this schema SAID.
    for f in ["credential.p256.json", "credential.ed25519.json"] {
        let cred: Value = serde_json::from_slice(&read_fixture(f)).unwrap();
        assert_eq!(
            cred["s"].as_str().unwrap(),
            expected,
            "{f}: s must pin the immutable schema SAID"
        );
    }
}

/// Regression: every existing KEL event SAID stays `KERI10JSON` and unchanged —
/// the ACDC protocol parameterization must not touch the KEL default path.
#[test]
fn kel_said_still_keri10json() {
    let icp = serde_json::json!({
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

    // The default path and the explicitly-KERI path agree.
    let via_default = compute_said(&icp).unwrap();
    let via_protocol = compute_said_with_protocol(&icp, Protocol::Keri).unwrap();
    assert_eq!(via_default, via_protocol, "KEL default == Protocol::Keri");

    // The same body under ACDC differs (proves the tag is actually threaded).
    let via_acdc = compute_said_with_protocol(&icp, Protocol::Acdc).unwrap();
    assert_ne!(
        via_default, via_acdc,
        "the protocol tag must affect the SAID (KERI != ACDC)"
    );
}
