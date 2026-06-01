//! SPEC.md §1.1 conformance vectors: emitted field set + order per event type.
//!
//! Executes the normative field-set table in `SPEC.md` for all five event
//! types (`icp`/`rot`/`ixn`/`dip`/`drt`): each representative event must
//! serialize in the exact documented field order, expose exactly that field
//! set (no missing, no unknown), and carry no legacy `dt`/`x` field. The
//! three finalizable types additionally round-trip through the strict
//! deserializer unchanged.
//!
//! This is the structural, cross-type half of conformance; `keripy_interop`
//! is the byte-level/keripy half (icp). Epic H.3 layers cross-implementation
//! KERIox `.cesr` vectors on top, using `SPEC.md` as the oracle.

use auths_keri::{
    CesrKey, DipEvent, DrtEvent, Event, IcpEvent, IxnEvent, KeriSequence, Prefix, RotEvent, Said,
    Threshold, VersionString, finalize_icp_event, finalize_ixn_event, finalize_rot_event,
};
use std::collections::BTreeSet;

fn verkey() -> CesrKey {
    CesrKey::new_unchecked("DAbcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".to_string())
}

fn commitment() -> Said {
    Said::new_unchecked("EFakeNextCommitment000000000000000000000000".to_string())
}

fn prior() -> Said {
    Said::new_unchecked("EFakePriorEventSaid00000000000000000000000".to_string())
}

fn delegator() -> Prefix {
    Prefix::new_unchecked("EFakeDelegatorAid0000000000000000000000000".to_string())
}

/// Assert a serialized event matches its `SPEC.md` §1.1 row: exact field set,
/// documented order, and no legacy fields.
fn assert_spec_shape(json: &str, ordered: &[&str]) {
    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    let obj = value
        .as_object()
        .expect("an event must serialize as a JSON object");

    let got: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let want: BTreeSet<&str> = ordered.iter().copied().collect();
    assert_eq!(got, want, "field set mismatch for {json}");

    let position = |key: &str| -> usize {
        json.find(&format!("\"{key}\":"))
            .unwrap_or_else(|| panic!("field {key} missing from {json}"))
    };
    for pair in ordered.windows(2) {
        assert!(
            position(pair[0]) < position(pair[1]),
            "field order violated: {} must precede {} in {json}",
            pair[0],
            pair[1]
        );
    }

    assert!(!json.contains("\"dt\":"), "no in-body dt is permitted: {json}");
    assert!(
        !json.contains("\"x\":"),
        "no legacy in-body signature x is permitted: {json}"
    );
}

/// Serialize, then parse and re-serialize; the bytes must be identical.
fn assert_round_trips(event: &Event) {
    let json = serde_json::to_string(event).unwrap();
    let parsed: Event = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("event must round-trip through the strict deserializer: {e}"));
    let again = serde_json::to_string(&parsed).unwrap();
    assert_eq!(json, again, "round-trip changed the wire bytes");
}

fn sample_icp() -> IcpEvent {
    finalize_icp_event(IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![verkey()],
        nt: Threshold::Simple(1),
        n: vec![commitment()],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
    })
    .unwrap()
}

fn sample_rot() -> RotEvent {
    finalize_rot_event(RotEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::new_unchecked("EFakeControllerAid000000000000000000000000".to_string()),
        s: KeriSequence::new(1),
        p: prior(),
        kt: Threshold::Simple(1),
        k: vec![verkey()],
        nt: Threshold::Simple(1),
        n: vec![commitment()],
        bt: Threshold::Simple(0),
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
    })
    .unwrap()
}

fn sample_ixn() -> IxnEvent {
    finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::new_unchecked("EFakeControllerAid000000000000000000000000".to_string()),
        s: KeriSequence::new(2),
        p: prior(),
        a: vec![],
    })
    .unwrap()
}

fn sample_dip() -> DipEvent {
    DipEvent {
        v: VersionString::placeholder(),
        d: commitment(),
        i: Prefix::new_unchecked("EFakeDelegateAid00000000000000000000000000".to_string()),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![verkey()],
        nt: Threshold::Simple(1),
        n: vec![commitment()],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
        di: delegator(),
    }
}

fn sample_drt() -> DrtEvent {
    DrtEvent {
        v: VersionString::placeholder(),
        d: commitment(),
        i: Prefix::new_unchecked("EFakeDelegateAid00000000000000000000000000".to_string()),
        s: KeriSequence::new(1),
        p: prior(),
        kt: Threshold::Simple(1),
        k: vec![verkey()],
        nt: Threshold::Simple(1),
        n: vec![commitment()],
        bt: Threshold::Simple(0),
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
        di: delegator(),
    }
}

#[test]
fn icp_matches_spec_field_set() {
    let json = serde_json::to_string(&Event::Icp(sample_icp())).unwrap();
    assert_spec_shape(
        &json,
        &["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
    );
}

#[test]
fn rot_matches_spec_field_set() {
    let json = serde_json::to_string(&Event::Rot(sample_rot())).unwrap();
    assert_spec_shape(
        &json,
        &[
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a",
        ],
    );
}

#[test]
fn ixn_matches_spec_field_set() {
    let json = serde_json::to_string(&Event::Ixn(sample_ixn())).unwrap();
    assert_spec_shape(&json, &["v", "t", "d", "i", "s", "p", "a"]);
}

#[test]
fn dip_matches_spec_field_set() {
    let json = serde_json::to_string(&Event::Dip(sample_dip())).unwrap();
    assert_spec_shape(
        &json,
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di",
        ],
    );
}

#[test]
fn drt_matches_spec_field_set() {
    let json = serde_json::to_string(&Event::Drt(sample_drt())).unwrap();
    assert_spec_shape(
        &json,
        &[
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a", "di",
        ],
    );
}

#[test]
fn finalizable_events_round_trip_unchanged() {
    assert_round_trips(&Event::Icp(sample_icp()));
    assert_round_trips(&Event::Rot(sample_rot()));
    assert_round_trips(&Event::Ixn(sample_ixn()));
}
