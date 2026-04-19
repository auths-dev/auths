//! fn-129.T9: replay rejection tests.
//!
//! Pins the existing signature-over-`session_id` defense across several
//! reframings of the same attack.

use auths_crypto::{TypedSeed, parse_key_material};
use auths_pairing_protocol::{
    CompletedPairing, PairingProtocol, PairingResponse, ProtocolError, respond_to_pairing,
};
use chrono::Duration;

fn gen_p256_test_pair() -> (TypedSeed, Vec<u8>) {
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey;
    let sk = SigningKey::random(&mut OsRng);
    let pkcs8 = sk.to_pkcs8_der().unwrap();
    let parsed = parse_key_material(pkcs8.as_bytes()).unwrap();
    (parsed.seed, parsed.public_key)
}

fn build_initiator_and_response(
    now: chrono::DateTime<chrono::Utc>,
) -> (PairingProtocol, PairingResponse) {
    let (protocol, token) = PairingProtocol::initiate(
        now,
        "did:keri:test".to_string(),
        "http://localhost:3000".to_string(),
        vec!["sign_commit".to_string()],
    )
    .unwrap();
    let (seed, pubkey) = gen_p256_test_pair();
    let token_bytes = serde_json::to_vec(&token).unwrap();
    let resp = respond_to_pairing(
        now,
        &token_bytes,
        &seed,
        &pubkey,
        "did:key:zDnaTest".to_string(),
        None,
    )
    .unwrap();
    (protocol, resp.response)
}

/// Replay a response produced against initiator A to initiator B. B's
/// session_id differs from A's — the signature was computed over A's
/// session_id, so verification against B's token fails.
#[test]
fn response_for_wrong_session_is_rejected() {
    let now = chrono::Utc::now();
    let (_protocol_a, response_a) = build_initiator_and_response(now);
    let (protocol_b, _response_b) = build_initiator_and_response(now);

    let response_bytes = serde_json::to_vec(&response_a).unwrap();
    let result = protocol_b.complete(now, &response_bytes);
    assert!(
        matches!(result, Err(ProtocolError::InvalidSignature)),
        "replayed response should fail with InvalidSignature, got {result:?}"
    );
}

/// Expired initiator token: a stale response replayed against a fresh
/// protocol should be rejected.
#[test]
fn stale_response_from_expired_token_is_rejected() {
    let now = chrono::Utc::now();
    // Build initiator+response using a stale `now` (1h ago).
    let (_protocol_expired, response) = build_initiator_and_response(now - Duration::hours(1));
    // Fresh initiator at `now`; replay the old response.
    let (protocol_now, _) = build_initiator_and_response(now);
    let response_bytes = serde_json::to_vec(&response).unwrap();
    let result = protocol_now.complete(now, &response_bytes);
    assert!(
        matches!(
            result,
            Err(ProtocolError::InvalidSignature | ProtocolError::Expired)
        ),
        "stale response should be rejected, got {result:?}"
    );
}

/// Happy path — proves the negatives aren't false positives.
#[test]
fn valid_pairing_completes() {
    let now = chrono::Utc::now();
    let (protocol, response) = build_initiator_and_response(now);
    let response_bytes = serde_json::to_vec(&response).unwrap();
    let completed: CompletedPairing = protocol.complete(now, &response_bytes).unwrap();
    assert_eq!(completed.peer_did, "did:key:zDnaTest");
    assert_eq!(completed.sas.len(), 10);
}

/// Same-session replay by direct call: completing a protocol consumes it
/// (`fn complete(mut self, ...)`), so calling `complete` twice on the
/// same value is a move-after-move borrow error — caught at compile
/// time. This test documents the invariant.
#[test]
#[allow(clippy::no_effect_underscore_binding)]
fn double_complete_is_a_compile_time_error() {
    // The invariant is enforced by `PairingProtocol::complete` taking
    // `mut self` by value. A second call on the same variable produces:
    //   error[E0382]: use of moved value: `protocol`
    // at compile time. trybuild-based assertion is a follow-up.
    let _note = "complete() consumes self; double-complete is a compile error";
}
