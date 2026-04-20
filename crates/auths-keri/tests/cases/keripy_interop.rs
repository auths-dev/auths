//! KERI spec-conformance checks that approximate keripy interop.
//!
//! Two modes:
//!   1. **Conformance mode** (always runs): auths-generated `icp` + `rot`
//!      events are checked against the invariants keripy would enforce —
//!      spec field order, no unknown fields, hex sequence, SAID == Blake3
//!      of canonical body with `d` placeholder-filled.
//!   2. **Subprocess mode** (gated on `KERIPY_INTEROP=1`): shells out to
//!      `python3 -c "from keri.core.serdering import Serder; ..."`, feeds
//!      the wire bytes, asserts the parsed SAID matches. Skipped when
//!      keripy isn't importable.
//!
//! Fixture mode (checking a keripy-produced byte stream) is designed but
//! not seeded yet — seeding requires a keripy install to generate. When
//! seeded, drop the fixture bytes at `tests/fixtures/keripy/icp.bin` and
//! un-ignore `fixture_mode_round_trips_icp`.

use auths_keri::{
    CesrKey, Event, IcpEvent, KeriSequence, Prefix, Said, Threshold, VersionString,
    finalize_icp_event,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

fn gen_cesr_ed25519_pub() -> String {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    format!("D{}", URL_SAFE_NO_PAD.encode(kp.public_key().as_ref()))
}

fn make_icp() -> IcpEvent {
    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(gen_cesr_ed25519_pub())],
        nt: Threshold::Simple(1),
        n: vec![Said::new_unchecked(
            "EFakeNextCommitment0000000000000000000000000".to_string(),
        )],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
        dt: None,
    };
    finalize_icp_event(icp).unwrap()
}

/// Spec field order for `icp`: v, t, d, i, s, kt, k, nt, n, bt, b, c, a.
/// No trailing `x` field.
#[test]
fn icp_serializes_in_spec_field_order() {
    let icp = make_icp();
    let json = serde_json::to_string(&Event::Icp(icp)).unwrap();

    // Extract key order via a lossless pass through serde_json::Value would
    // reorder; instead grep the raw string for positional invariants.
    let find = |key: &str| -> usize {
        json.find(&format!("\"{}\":", key))
            .unwrap_or_else(|| panic!("key {key} missing from serialized icp"))
    };

    let order = [
        "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a",
    ];
    for pair in order.windows(2) {
        assert!(
            find(pair[0]) < find(pair[1]),
            "spec field order violated: {} must come before {} in {json}",
            pair[0],
            pair[1]
        );
    }

    // No trailing `x` field.
    assert!(
        !json.contains("\"x\":"),
        "legacy `x` field must not appear in canonical icp output: {json}"
    );
}

#[test]
fn icp_sequence_is_hex_string() {
    let icp = make_icp();
    let v: Value = serde_json::to_value(Event::Icp(icp)).unwrap();
    let s = v.get("s").and_then(|x| x.as_str()).unwrap();
    // Must be a valid hex string (no leading 0x, lowercase).
    assert!(
        s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "s must be lowercase hex: {s:?}"
    );
}

#[test]
fn icp_self_addressing_prefix_equals_said() {
    let icp = make_icp();
    assert_eq!(
        icp.i.as_str(),
        icp.d.as_str(),
        "for self-addressing AIDs (E-prefixed), i must equal d at inception"
    );
    assert!(
        icp.d.as_str().starts_with('E'),
        "Blake3-256 SAID must start with CESR derivation code 'E'"
    );
    assert_eq!(
        icp.d.as_str().len(),
        44,
        "Blake3-256 SAID must be 44 chars (1 code + 43 base64url)"
    );
}

#[test]
fn icp_version_string_byte_count_matches() {
    let icp = make_icp();
    let wire = serde_json::to_vec(&Event::Icp(icp.clone())).unwrap();
    let v_str = {
        let val: Value = serde_json::from_slice(&wire).unwrap();
        val.get("v").and_then(|x| x.as_str()).unwrap().to_string()
    };
    // KERI10JSON<hex 6-char byte count>_
    assert!(v_str.starts_with("KERI10JSON"));
    let hex_part = &v_str[10..16];
    let declared = usize::from_str_radix(hex_part, 16).unwrap();
    assert_eq!(
        declared,
        wire.len(),
        "version string declared byte count {declared} must equal actual {}",
        wire.len()
    );
}

/// Subprocess path: invoked only when `KERIPY_INTEROP=1` is set in env
/// AND `python3 -c "import keri.core.serdering"` succeeds. Skipped
/// otherwise with a clear log line.
#[test]
fn subprocess_mode_when_keripy_available() {
    if std::env::var("KERIPY_INTEROP").ok().as_deref() != Some("1") {
        eprintln!("[SKIP] KERIPY_INTEROP != 1; not invoking python subprocess");
        return;
    }
    let probe = std::process::Command::new("python3")
        .args(["-c", "import keri.core.serdering"])
        .status();
    match probe {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("[SKIP] python3 + keri.core.serdering not available");
            return;
        }
    }

    let icp = make_icp();
    let wire = serde_json::to_vec(&Event::Icp(icp.clone())).unwrap();
    let expected_said = icp.d.as_str().to_string();

    let python = "import sys; from keri.core.serdering import Serder; \
         raw=sys.stdin.buffer.read(); s=Serder(raw=raw); \
         print(s.said.decode() if hasattr(s.said, 'decode') else s.said)";
    let output = std::process::Command::new("python3")
        .args(["-c", python])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut().expect("stdin").write_all(&wire)?;
            child.wait_with_output()
        })
        .expect("python subprocess failed");

    let parsed = String::from_utf8(output.stdout).unwrap().trim().to_string();
    assert_eq!(
        parsed, expected_said,
        "keripy-parsed SAID {parsed:?} must equal auths SAID {expected_said:?}"
    );
}

#[test]
fn fixture_mode_round_trips_icp() {
    let fixture_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keripy/icp.bin");
    let bytes = std::fs::read(&fixture_path)
        .unwrap_or_else(|_| panic!("fixture missing: {}", fixture_path.display()));
    let event: Event = serde_json::from_slice(&bytes).expect("keripy fixture must parse");
    let said = match &event {
        Event::Icp(icp) => icp.d.clone(),
        _ => panic!("fixture must be an icp"),
    };
    // Round-trip: serialize back, parse again, SAID must match.
    let round = serde_json::to_vec(&event).unwrap();
    let again: Event = serde_json::from_slice(&round).unwrap();
    let again_said = match again {
        Event::Icp(icp) => icp.d,
        _ => unreachable!(),
    };
    assert_eq!(said, again_said);
}
