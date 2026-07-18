//! KEL event round-trips, attachments, monotonic key-state, and append guards.

use std::ops::ControlFlow;

use auths_id::ports::RegistryBackend;
use auths_id::ports::registry::RegistryError;

use super::support;

#[test]
fn append_get_visit_round_trip() {
    let Some(backend) = support::setup() else {
        return;
    };

    let (icp, prefix, keypair) = support::make_signed_icp();
    let _ = &keypair;
    let icp_said = icp.said().as_str().to_string();
    backend.append_event(&prefix, &icp).unwrap();

    // Inception readable by seq.
    assert_eq!(backend.get_event(&prefix, 0).unwrap().said(), icp.said());

    let tip = backend.get_tip(&prefix).unwrap();
    assert_eq!(tip.sequence, 0);
    assert_eq!(tip.said.as_str(), icp_said.as_str());

    let state = backend.get_key_state(&prefix).unwrap();
    assert_eq!(state.sequence, 0);

    // Append an interaction, then confirm the full stream visits in order.
    let ixn = support::make_signed_ixn(&prefix, 1, &icp_said);
    backend.append_event(&prefix, &ixn).unwrap();

    let mut seen = Vec::new();
    backend
        .visit_events(&prefix, 0, &mut |e| {
            seen.push(e.sequence().value());
            ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(seen, vec![0, 1]);

    assert_eq!(backend.get_tip(&prefix).unwrap().sequence, 1);
}

#[test]
fn signed_event_attachment_round_trips() {
    let Some(backend) = support::setup() else {
        return;
    };

    let (icp, prefix, _kp) = support::make_signed_icp();
    let attachment = b"-AABAA_fake_cesr_indexed_signature_group".to_vec();
    backend
        .append_signed_event(&prefix, &icp, &attachment)
        .unwrap();

    assert_eq!(
        backend.get_attachment(&prefix, 0).unwrap(),
        Some(attachment)
    );

    // An event appended without an attachment reads back as None.
    let (icp2, prefix2, _kp2) = support::make_signed_icp();
    backend.append_event(&prefix2, &icp2).unwrap();
    assert_eq!(backend.get_attachment(&prefix2, 0).unwrap(), None);
}

#[test]
fn duplicate_and_gap_are_rejected() {
    let Some(backend) = support::setup() else {
        return;
    };

    let (icp, prefix, _kp) = support::make_signed_icp();
    let icp_said = icp.said().as_str().to_string();
    backend.append_event(&prefix, &icp).unwrap();

    // Re-appending the same inception is refused (append-only).
    let dup = backend.append_event(&prefix, &icp).unwrap_err();
    assert!(
        matches!(dup, RegistryError::EventExists { .. }),
        "expected EventExists, got {dup:?}"
    );

    // Skipping seq 1 and appending seq 2 is a sequence gap.
    let ixn2 = support::make_signed_ixn(&prefix, 2, &icp_said);
    let gap = backend.append_event(&prefix, &ixn2).unwrap_err();
    assert!(
        matches!(
            gap,
            RegistryError::SequenceGap {
                expected: 1,
                got: 2,
                ..
            }
        ),
        "expected SequenceGap, got {gap:?}"
    );
}

#[test]
fn key_state_is_monotonic_and_rejects_rollback() {
    let Some(backend) = support::setup() else {
        return;
    };

    let (icp, prefix, _kp) = support::make_signed_icp();
    let icp_said = icp.said().as_str().to_string();
    backend.append_event(&prefix, &icp).unwrap();
    let state0 = backend.get_key_state(&prefix).unwrap();
    assert_eq!(state0.sequence, 0);

    let ixn = support::make_signed_ixn(&prefix, 1, &icp_said);
    backend.append_event(&prefix, &ixn).unwrap();
    let state1 = backend.get_key_state(&prefix).unwrap();
    assert_eq!(state1.sequence, 1);

    // Writing the stale seq-0 state must be rejected (never roll backwards).
    let err = backend.write_key_state(&prefix, &state0).unwrap_err();
    assert!(
        matches!(err, RegistryError::ConcurrentModification(_)),
        "expected rollback rejection, got {err:?}"
    );

    // Re-writing the current state is allowed (idempotent, not a rollback).
    backend.write_key_state(&prefix, &state1).unwrap();
    assert_eq!(backend.get_key_state(&prefix).unwrap().sequence, 1);
}

#[test]
fn write_key_state_on_unknown_identity_is_not_found() {
    let Some(backend) = support::setup() else {
        return;
    };
    // Incept one identity and read its (valid) state.
    let (icp, prefix, _kp) = support::make_signed_icp();
    backend.append_event(&prefix, &icp).unwrap();
    let state = backend.get_key_state(&prefix).unwrap();

    // Writing that state under a prefix the backend never incepted is NotFound.
    let (_icp2, unknown_prefix, _kp2) = support::make_signed_icp();
    let err = backend
        .write_key_state(&unknown_prefix, &state)
        .unwrap_err();
    assert!(
        matches!(err, RegistryError::NotFound { .. }),
        "expected NotFound for unknown identity, got {err:?}"
    );
}
