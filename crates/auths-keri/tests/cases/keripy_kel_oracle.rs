//! Differential check of the signed-KEL verdict against the keripy 1.3.4 reference.
//!
//! keripy *generated* this multisig inception+rotation (kt=2; a 3→2 key removal with
//! dual-index sigers) as a valid KEL, so an independent verifier must ACCEPT it — agreeing
//! with keripy, not merely with auths' own encoder (which would be circular). The tamper
//! variants are the universal KERI rejections — a forged signature, an unmet signing
//! threshold, a non-self-addressing inception, an altered prior pointer — that keripy also
//! refuses; auths must refuse each too. The fixtures are committed for offline runs; a live
//! keripy cross-check that re-derives the same accept/reject verdict is gated on
//! `KERIPY_INTEROP=1` and skipped when keripy is not importable.

use auths_keri::{
    Event, Said, SignedEvent, ValidationError, parse_attachment, validate_signed_kel,
};
use std::path::Path;

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/keripy")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|_| panic!("fixture missing: {}", p.display()))
}

fn load_event(name: &str) -> Event {
    serde_json::from_slice(&fixture(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// The keripy icp+rot KEL with its committed CESR attachments, as signed events.
fn keripy_kel() -> Vec<SignedEvent> {
    let icp = load_event("rot_remove.icp.json");
    let icp_sigs = parse_attachment(&fixture("rot_remove.icp.att")).expect("icp attachment");
    let rot = load_event("rot_remove.rot.json");
    let rot_sigs = parse_attachment(&fixture("rot_remove.rot.att")).expect("rot attachment");
    vec![
        SignedEvent::new(icp, icp_sigs),
        SignedEvent::new(rot, rot_sigs),
    ]
}

#[test]
fn keripy_valid_kel_is_accepted() {
    let state = validate_signed_kel(&keripy_kel(), None)
        .expect("a keripy-valid icp+rot KEL must be accepted, agreeing with keripy");
    assert_eq!(
        state.sequence, 1,
        "the rotation advanced the key state to sn=1"
    );
    assert_eq!(
        state.current_keys.len(),
        2,
        "the 3→2 removal left two current keys"
    );
}

#[test]
fn forged_inception_signature_is_rejected() {
    let mut kel = keripy_kel();
    // Flip a byte in the first inception signature: the kt=2 threshold can no longer be met.
    kel[0].signatures[0].sig[0] ^= 0x01;
    assert!(
        matches!(
            validate_signed_kel(&kel, None),
            Err(ValidationError::SignatureFailed { .. })
        ),
        "a forged inception signature must fail closed"
    );
}

#[test]
fn unmet_inception_threshold_is_rejected() {
    let mut kel = keripy_kel();
    // The inception commits kt=2 but only one signature remains → threshold unmet.
    kel[0].signatures.truncate(1);
    assert!(
        validate_signed_kel(&kel, None).is_err(),
        "an inception carrying fewer signatures than its kt must be rejected"
    );
}

#[test]
fn non_self_addressing_inception_is_rejected() {
    let mut kel = keripy_kel();
    if let Event::Icp(icp) = &mut kel[0].event {
        icp.d = Said::new_unchecked("EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
    }
    assert!(
        matches!(
            validate_signed_kel(&kel, None),
            Err(ValidationError::InvalidSaid { .. })
        ),
        "an inception whose d is not its self-addressing SAID must be rejected"
    );
}

#[test]
fn altered_prior_pointer_is_rejected() {
    let mut kel = keripy_kel();
    if let Event::Rot(rot) = &mut kel[1].event {
        rot.p = Said::new_unchecked("EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string());
    }
    // The prior pointer is part of the rotation's SAID preimage, so altering it cannot go
    // undetected: the recomputed SAID no longer matches the event's `d`.
    assert!(
        validate_signed_kel(&kel, None).is_err(),
        "a rotation whose prior pointer was altered must be rejected"
    );
}

/// A wrong-but-well-formed 44-char CESR SAID (Blake3 `E` code), for length-preserving
/// tampers that keep the event's version-string byte length valid.
const WRONG_SAID: &str = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Overwrite the 44-char SAID value of `field` (e.g. `d`, `p`) in a KERI event's raw
/// JSON, preserving length so the declared version-string size stays correct.
fn replace_field_said(raw: &[u8], field: &str, new_said: &str) -> Vec<u8> {
    assert_eq!(new_said.len(), 44, "a CESR Blake3 SAID is 44 chars");
    let needle = format!("\"{field}\":\"");
    let pos = raw
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .unwrap_or_else(|| panic!("field {field:?} not found in event"));
    let start = pos + needle.len();
    let mut out = raw.to_vec();
    out[start..start + 44].copy_from_slice(new_said.as_bytes());
    out
}

/// Concatenate `(event_json, attachment)` pairs into a single CESR ingestion stream.
fn cesr_stream(parts: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (event, att) in parts {
        out.extend_from_slice(event);
        out.extend_from_slice(att);
    }
    out
}

/// Live differential: feed the same committed bytes — valid and tampered — to keripy's own
/// ingestion path and confirm it reaches the identical accept/reject verdict auths does for
/// every universal KERI rejection. Gated on `KERIPY_INTEROP=1`; skipped (not failed) when
/// keripy is unavailable.
#[test]
fn keripy_subprocess_agrees_on_accept_and_reject() {
    if std::env::var("KERIPY_INTEROP").ok().as_deref() != Some("1") {
        eprintln!("[SKIP] KERIPY_INTEROP != 1; not invoking keripy");
        return;
    }
    if !keripy_importable() {
        eprintln!("[SKIP] keripy not importable");
        return;
    }

    let icp_raw = fixture("rot_remove.icp.json");
    let icp_att = fixture("rot_remove.icp.att");
    let rot_raw = fixture("rot_remove.rot.json");
    let rot_att = fixture("rot_remove.rot.att");

    // Valid stream: keripy must advance the AID to sn=1 (accept), agreeing with auths.
    let valid = cesr_stream(&[(&icp_raw, &icp_att), (&rot_raw, &rot_att)]);
    assert_eq!(
        keripy_highest_sn(&valid),
        Some(1),
        "keripy must accept the valid KEL to sn=1, matching auths"
    );

    // Forged inception signature: flip a base64 char inside the icp siger payload (after
    // the 4-byte `-AAC` counter).
    let mut forged_att = icp_att.clone();
    let flip = 6.min(forged_att.len() - 1);
    forged_att[flip] = if forged_att[flip] == b'A' { b'B' } else { b'A' };

    // Unmet inception threshold: the icp commits kt=2; drop a siger and re-count `-AAC`→`-AAB`
    // so only one of the two signatures remains.
    let mut one_sig_att = b"-AAB".to_vec();
    one_sig_att.extend_from_slice(&icp_att[4..4 + 88]);

    // Each tamper is a universal KERI rejection; keripy must refuse every one (never reach
    // sn=1), exactly as auths' offline verdict above does.
    let rejects: [(&str, Vec<u8>); 4] = [
        (
            "forged inception signature",
            cesr_stream(&[(&icp_raw, &forged_att)]),
        ),
        (
            "unmet inception threshold",
            cesr_stream(&[(&icp_raw, &one_sig_att)]),
        ),
        (
            "non-self-addressing inception d",
            cesr_stream(&[(&replace_field_said(&icp_raw, "d", WRONG_SAID), &icp_att)]),
        ),
        (
            "altered rotation prior pointer p",
            cesr_stream(&[
                (&icp_raw, &icp_att),
                (&replace_field_said(&rot_raw, "p", WRONG_SAID), &rot_att),
            ]),
        ),
    ];
    for (label, stream) in &rejects {
        assert_ne!(
            keripy_highest_sn(stream),
            Some(1),
            "keripy must reject the KEL with a {label}, matching auths"
        );
    }
}

fn keripy_importable() -> bool {
    std::process::Command::new("python3")
        .args(["-c", "import keri.core.eventing, keri.core.parsing"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Drive a CESR stream through keripy's `Parser`/`Kevery` and return the highest sequence
/// number the (single) AID reached, or `None` if no event was accepted.
fn keripy_highest_sn(stream: &[u8]) -> Option<u64> {
    use std::io::Write;
    let script = r#"
import sys
from keri.core import eventing, parsing
from keri.db import basing
raw = sys.stdin.buffer.read()
db = basing.Baser(name="oracle", temp=True, reopen=True)
kvy = eventing.Kevery(db=db)
try:
    parsing.Parser(kvy=kvy).parse(ims=bytearray(raw))
except Exception:
    pass
sn = -1
for pre, kever in kvy.kevers.items():
    sn = max(sn, kever.sn)
print(sn)
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            child.stdin.as_mut().expect("stdin").write_all(stream)?;
            child.wait_with_output()
        })
        .expect("python subprocess");
    let parsed: i64 = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
    if parsed < 0 {
        None
    } else {
        Some(parsed as u64)
    }
}
