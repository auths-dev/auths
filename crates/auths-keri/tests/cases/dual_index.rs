//! Epic B — dual-index CESR signature attachment parsing & emission.
//!
//! Oracle: `tests/fixtures/keripy/rot_remove.rot.att` — keripy 1.3.4's `-AAC`
//! group of two `2A` (Ed25519_Big) sigers for a 3→2 key removal: new `k[0]`
//! reveals prior `n[1]`, new `k[1]` reveals prior `n[2]`.

use auths_keri::{IndexedSignature, parse_attachment, serialize_attachment};
use std::path::Path;

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/keripy")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|_| panic!("fixture missing: {}", p.display()))
}

/// Our code-directed parser must read keripy's dual-index attachment with the
/// correct `(index, prior_index)` pairs.
#[test]
fn parses_keripy_rot_remove_attachment() {
    let att = fixture("rot_remove.rot.att");
    let sigs = parse_attachment(&att).expect("keripy dual-index attachment must parse");
    assert_eq!(sigs.len(), 2, "expected two sigers");
    assert_eq!((sigs[0].index, sigs[0].prior_index), (0, Some(1)));
    assert_eq!((sigs[1].index, sigs[1].prior_index), (1, Some(2)));
}

/// A heterogeneous group — single-index `A` (88 ch) followed by dual-index `2A`
/// (92 ch) — must parse at code-directed boundaries; `prior_index` is `Some`
/// only for the dual-index siger.
#[test]
fn mixed_curve_attachment_parses() {
    // One single-index `A` siger via our emitter (88 chars after the -AAB header).
    let a = serialize_attachment(&[IndexedSignature {
        index: 5,
        prior_index: None,
        sig: vec![7u8; 64],
    }])
    .unwrap();
    let a_siger = &a[4..];
    assert_eq!(a_siger.len(), 88, "single-index Ed25519 siger is 88 chars");

    // One dual-index `2A` siger from the keripy fixture (92 chars after -AAC).
    let rot = fixture("rot_remove.rot.att");
    let twoa_siger = &rot[4..4 + 92];

    // Hand-assemble a count-2 group: -AAC + A(88) + 2A(92).
    let mut group = b"-AAC".to_vec();
    group.extend_from_slice(a_siger);
    group.extend_from_slice(twoa_siger);

    let sigs = parse_attachment(&group).expect("mixed-width group must parse");
    assert_eq!(sigs.len(), 2);
    assert_eq!((sigs[0].index, sigs[0].prior_index), (5, None));
    assert_eq!((sigs[1].index, sigs[1].prior_index), (0, Some(1)));
}
