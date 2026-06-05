//! Backerless TEL (Epic F.2) conformance + keripy 1.3.4 byte-interop vectors.
//!
//! Asserts the `Vcp`/`Iss`/`Rev` types SAID-ify byte-equal to keripy 1.3.4
//! `keri.vdr.eventing` fixtures for BOTH curves (P-256 default + Ed25519), that the
//! version tag is `KERI10JSON` (TEL events ride the KERI family, NOT `ACDC10JSON`),
//! that the TEL→KEL anchor seal is the `{i,s,d}` shape, and that `validate_tel`
//! enforces the `vcp → iss → rev` chain via typed `TelError`s.

use std::path::{Path, PathBuf};

use auths_keri::tel::{Iss, Rev, TelAnchorSeal, TelEvent, Vcp, validate_tel};
use auths_keri::{KeriPublicKey, Prefix, Said, TelError};
use serde_json::Value;

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

/// Rebuild the auths `Vcp` from a keripy fixture's meta, SAID-ified.
fn rebuild_vcp(meta: &Value) -> Vcp {
    let s = |k: &str| meta[k].as_str().expect("meta string field").to_string();
    Vcp::new(Prefix::new_unchecked(s("issuer_aid")), s("nonce"))
        .saidify()
        .expect("vcp saidify must succeed")
}

/// Rebuild the auths `Iss` from a keripy fixture's meta, SAID-ified.
fn rebuild_iss(meta: &Value) -> Iss {
    let s = |k: &str| meta[k].as_str().expect("meta string field").to_string();
    Iss::new(
        Said::new_unchecked(s("credential_said")),
        Said::new_unchecked(s("registry_said")),
        FIXED_DT.to_string(),
    )
    .saidify()
    .expect("iss saidify must succeed")
}

/// Rebuild the auths `Rev` from a keripy fixture's meta, SAID-ified.
fn rebuild_rev(meta: &Value) -> Rev {
    let s = |k: &str| meta[k].as_str().expect("meta string field").to_string();
    Rev::new(
        Said::new_unchecked(s("credential_said")),
        Said::new_unchecked(s("registry_said")),
        Said::new_unchecked(s("iss_said")),
        FIXED_DT.to_string(),
    )
    .saidify()
    .expect("rev saidify must succeed")
}

/// Self-consistency: a freshly SAID-ified `vcp` verifies and round-trips through serde.
#[test]
fn vcp_said_roundtrips() {
    let vcp = rebuild_vcp(&read_meta("tel.p256.meta.json"));
    vcp.verify_said()
        .expect("freshly saidified vcp must verify");

    // Self-addressing: the registry SAID i == d.
    assert_eq!(vcp.i, vcp.d, "vcp is self-addressing: i must equal d");
    assert_eq!(vcp.registry(), &vcp.d);

    let wire = auths_keri::tel_to_wire_bytes(&vcp).unwrap();
    let parsed: Vcp = serde_json::from_slice(&wire).unwrap();
    let again = auths_keri::tel_to_wire_bytes(&parsed).unwrap();
    assert_eq!(wire, again, "vcp must round-trip through serde unchanged");
    parsed.verify_said().expect("round-tripped vcp must verify");
}

/// Byte-interop: the auths-built P-256 `vcp`/`iss`/`rev` are byte-equal to keripy 1.3.4.
#[test]
fn tel_vcp_iss_rev_said_match_keripy_134() {
    let meta = read_meta("tel.p256.meta.json");
    let vcp = rebuild_vcp(&meta);
    let iss = rebuild_iss(&meta);
    let rev = rebuild_rev(&meta);

    assert_eq!(vcp.d.as_str(), meta["vcp_said"].as_str().unwrap());
    assert_eq!(iss.d.as_str(), meta["iss_said"].as_str().unwrap());
    assert_eq!(rev.d.as_str(), meta["rev_said"].as_str().unwrap());

    assert_eq!(
        auths_keri::tel_to_wire_bytes(&vcp).unwrap(),
        read_fixture("tel.p256.vcp.json"),
        "vcp bytes must be byte-equal to keripy fixture"
    );
    assert_eq!(
        auths_keri::tel_to_wire_bytes(&iss).unwrap(),
        read_fixture("tel.p256.iss.json"),
        "iss bytes must be byte-equal to keripy fixture"
    );
    assert_eq!(
        auths_keri::tel_to_wire_bytes(&rev).unwrap(),
        read_fixture("tel.p256.rev.json"),
        "rev bytes must be byte-equal to keripy fixture"
    );
}

/// Byte-interop on the Ed25519 curve: the issuing key carries a `D`-prefix curve tag.
#[test]
fn tel_said_matches_keripy_134_ed25519() {
    let meta = read_meta("tel.ed25519.meta.json");
    let vcp = rebuild_vcp(&meta);
    let iss = rebuild_iss(&meta);
    let rev = rebuild_rev(&meta);

    assert_eq!(vcp.d.as_str(), meta["vcp_said"].as_str().unwrap());
    assert_eq!(iss.d.as_str(), meta["iss_said"].as_str().unwrap());
    assert_eq!(rev.d.as_str(), meta["rev_said"].as_str().unwrap());

    assert_eq!(
        auths_keri::tel_to_wire_bytes(&vcp).unwrap(),
        read_fixture("tel.ed25519.vcp.json")
    );
    assert_eq!(
        auths_keri::tel_to_wire_bytes(&iss).unwrap(),
        read_fixture("tel.ed25519.iss.json")
    );
    assert_eq!(
        auths_keri::tel_to_wire_bytes(&rev).unwrap(),
        read_fixture("tel.ed25519.rev.json")
    );

    // The issuing key is curve-tagged in-band and parseable — never length-dispatched.
    let verkey = meta["issuer_verkey"].as_str().unwrap();
    assert!(
        verkey.starts_with('D'),
        "ed25519 issuer verkey must carry the D curve tag: {verkey}"
    );
    KeriPublicKey::parse(verkey).expect("curve-tagged Ed25519 verkey must parse");
}

/// The P-256 issuer key carries the `1AAJ` curve tag in-band (never length-dispatched).
#[test]
fn tel_issuer_key_is_curve_tagged_p256() {
    let meta = read_meta("tel.p256.meta.json");
    let verkey = meta["issuer_verkey"].as_str().unwrap();
    assert!(
        verkey.starts_with("1AAJ"),
        "p256 issuer verkey must carry the 1AAJ curve tag: {verkey}"
    );
    KeriPublicKey::parse(verkey).expect("curve-tagged P-256 verkey must parse");
}

/// All three TEL events ride the KERI protocol family (`KERI10JSON`), not ACDC.
#[test]
fn tel_version_string_is_keri10json() {
    let meta = read_meta("tel.p256.meta.json");
    let vcp = rebuild_vcp(&meta);
    let iss = rebuild_iss(&meta);
    let rev = rebuild_rev(&meta);

    for v in [&vcp.v, &iss.v, &rev.v] {
        assert!(
            v.starts_with("KERI10JSON"),
            "TEL version must be KERI10JSON: {v}"
        );
        assert!(v.ends_with('_'));
        assert_eq!(v.len(), 17);
    }

    let declared = usize::from_str_radix(&iss.v[10..16], 16).unwrap();
    assert_eq!(
        declared,
        auths_keri::tel_to_wire_bytes(&iss).unwrap().len(),
        "declared size must equal serialized byte count"
    );
}

/// The TEL→KEL anchor seal is the `{i, s, d}` source-seal shape keripy carries in
/// the issuer KEL `ixn`'s `a[]` — NOT the bare `{s, d}` form.
#[test]
fn tel_anchor_seal_shape_matches_keripy() {
    let meta = read_meta("tel.p256.meta.json");
    let iss = rebuild_iss(&meta);

    let seal = TelAnchorSeal::for_event(
        Prefix::new_unchecked(meta["registry_said"].as_str().unwrap().to_string()),
        iss.s,
        iss.d.clone(),
    );

    let value = serde_json::to_value(&seal).unwrap();
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["d", "i", "s"],
        "anchor seal must be the {{i,s,d}} key-event seal, not {{s,d}}"
    );

    let expected = &meta["anchor_seal"];
    assert_eq!(
        value["i"].as_str().unwrap(),
        expected["i"].as_str().unwrap()
    );
    assert_eq!(
        value["d"].as_str().unwrap(),
        expected["d"].as_str().unwrap()
    );
    // keripy serializes the seal `s` as a hex string; the meta records the raw int 0.
    assert_eq!(value["s"].as_str().unwrap(), "0");
    assert_eq!(expected["s"].as_u64().unwrap(), 0);
}

/// A well-formed `vcp → iss → rev` log validates and resolves issued/revoked state.
#[test]
fn tel_chain_validates() {
    let meta = read_meta("tel.p256.meta.json");
    let vcp = rebuild_vcp(&meta);
    let iss = rebuild_iss(&meta);
    let rev = rebuild_rev(&meta);
    let credential = iss.i.clone();

    // vcp + iss: credential is currently valid.
    let state = validate_tel(&[TelEvent::Vcp(vcp.clone()), TelEvent::Iss(iss.clone())]).unwrap();
    assert!(state.is_valid(&credential));
    assert_eq!(state.issued, vec![credential.clone()]);
    assert!(state.revoked.is_empty());

    // vcp + iss + rev: credential is revoked.
    let state =
        validate_tel(&[TelEvent::Vcp(vcp), TelEvent::Iss(iss), TelEvent::Rev(rev)]).unwrap();
    assert!(!state.is_valid(&credential));
    assert_eq!(state.revoked, vec![credential]);
}

/// A `rev` for a credential that was never issued is rejected as `RevWithoutIss`.
#[test]
fn rev_without_iss_rejected() {
    let meta = read_meta("tel.p256.meta.json");
    let vcp = rebuild_vcp(&meta);
    let rev = rebuild_rev(&meta);

    let err = validate_tel(&[TelEvent::Vcp(vcp), TelEvent::Rev(rev)]).unwrap_err();
    assert!(
        matches!(err, TelError::RevWithoutIss { .. }),
        "expected RevWithoutIss, got {err:?}"
    );
}

/// An `iss` with no leading `vcp` registry inception is rejected as `MissingInception`.
#[test]
fn iss_without_registry_rejected() {
    let iss = rebuild_iss(&read_meta("tel.p256.meta.json"));

    // No leading vcp at all: the TEL has no inception.
    let err = validate_tel(&[TelEvent::Iss(iss.clone())]).unwrap_err();
    assert!(
        matches!(err, TelError::MissingInception),
        "expected MissingInception, got {err:?}"
    );

    // An iss naming a registry other than the inceptioned one is IssWithoutRegistry.
    let meta = read_meta("tel.p256.meta.json");
    let vcp = rebuild_vcp(&meta);
    let other_registry =
        Said::new_unchecked("EwrongRegistrySaid0000000000000000000000000".to_string());
    let foreign_iss = Iss::new(iss.i.clone(), other_registry, FIXED_DT.to_string())
        .saidify()
        .unwrap();
    let err = validate_tel(&[TelEvent::Vcp(vcp), TelEvent::Iss(foreign_iss)]).unwrap_err();
    assert!(
        matches!(err, TelError::IssWithoutRegistry { .. }),
        "expected IssWithoutRegistry, got {err:?}"
    );
}

/// A double `iss` of the same credential is rejected as `DoubleIss`.
#[test]
fn double_iss_rejected() {
    let meta = read_meta("tel.p256.meta.json");
    let vcp = rebuild_vcp(&meta);
    let iss = rebuild_iss(&meta);

    let err = validate_tel(&[
        TelEvent::Vcp(vcp),
        TelEvent::Iss(iss.clone()),
        TelEvent::Iss(iss),
    ])
    .unwrap_err();
    assert!(
        matches!(err, TelError::DoubleIss { .. }),
        "expected DoubleIss, got {err:?}"
    );
}

/// A double `rev` of the same credential is rejected as `DoubleRev`.
#[test]
fn double_rev_rejected() {
    let meta = read_meta("tel.p256.meta.json");
    let vcp = rebuild_vcp(&meta);
    let iss = rebuild_iss(&meta);
    let rev = rebuild_rev(&meta);

    let err = validate_tel(&[
        TelEvent::Vcp(vcp),
        TelEvent::Iss(iss),
        TelEvent::Rev(rev.clone()),
        TelEvent::Rev(rev),
    ])
    .unwrap_err();
    assert!(
        matches!(err, TelError::DoubleRev { .. }),
        "expected DoubleRev, got {err:?}"
    );
}

/// A `rev` whose `p` back-link does not match the prior `iss` SAID is a broken chain.
#[test]
fn rev_with_bad_prior_link_rejected() {
    let meta = read_meta("tel.p256.meta.json");
    let vcp = rebuild_vcp(&meta);
    let iss = rebuild_iss(&meta);

    let bad_rev = Rev::new(
        iss.i.clone(),
        iss.ri.clone(),
        Said::new_unchecked("EbogusPriorSaid000000000000000000000000000".to_string()),
        FIXED_DT.to_string(),
    )
    .saidify()
    .unwrap();

    let err = validate_tel(&[
        TelEvent::Vcp(vcp),
        TelEvent::Iss(iss),
        TelEvent::Rev(bad_rev),
    ])
    .unwrap_err();
    assert!(
        matches!(err, TelError::BrokenChain { .. }),
        "expected BrokenChain on a bad p back-link, got {err:?}"
    );
}

/// A tampered TEL event SAID is rejected as `SaidMismatch`.
#[test]
fn tampered_said_rejected() {
    let meta = read_meta("tel.p256.meta.json");
    let mut iss = rebuild_iss(&meta);
    iss.d = Said::new_unchecked("EtamperedSaid00000000000000000000000000000".to_string());

    let err = iss.verify_said().unwrap_err();
    assert!(
        matches!(
            err,
            TelError::SaidMismatch {
                event_type: "iss",
                ..
            }
        ),
        "expected iss SaidMismatch, got {err:?}"
    );
}

/// `TelEvent::from_wire_bytes` dispatches on the `t` field (never on byte length).
#[test]
fn tel_event_dispatches_on_type_field() {
    let vcp = TelEvent::from_wire_bytes(&read_fixture("tel.p256.vcp.json")).unwrap();
    let iss = TelEvent::from_wire_bytes(&read_fixture("tel.p256.iss.json")).unwrap();
    let rev = TelEvent::from_wire_bytes(&read_fixture("tel.p256.rev.json")).unwrap();
    assert!(matches!(vcp, TelEvent::Vcp(_)));
    assert!(matches!(iss, TelEvent::Iss(_)));
    assert!(matches!(rev, TelEvent::Rev(_)));

    // A whole fixture chain parsed from wire bytes validates end-to-end.
    let state = validate_tel(&[vcp, iss, rev]).unwrap();
    let credential = Said::new_unchecked(
        read_meta("tel.p256.meta.json")["credential_said"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    assert!(state.issued.contains(&credential));
    assert!(state.revoked.contains(&credential));
}
