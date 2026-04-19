//! fn-129.T6: the typestate chain refuses to hand back [`CompletedPairing`]
//! without a [`SasMatch`] proof token.
//!
//! These tests exercise the runtime-observable behaviour; a compile-fail
//! test (attempting to call `finalize()` on `PairingFlow<Init>`) would be
//! more rigorous but requires `trybuild`, which isn't a workspace dep. The
//! type system already guarantees the states cannot be skipped; these
//! tests confirm the transitions carry the right material through.

use auths_crypto::{TypedSeed, parse_key_material};
use auths_pairing_protocol::{PairingFlow, PairingResponse, SasMatch, respond_to_pairing};

fn gen_p256_test_pair() -> (TypedSeed, Vec<u8>) {
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey;
    let sk = SigningKey::random(&mut OsRng);
    let pkcs8 = sk.to_pkcs8_der().unwrap();
    let parsed = parse_key_material(pkcs8.as_bytes()).unwrap();
    (parsed.seed, parsed.public_key)
}

#[test]
fn typestate_chain_completes_with_explicit_sas_confirmation() {
    let now = chrono::Utc::now();
    let (flow, token) = PairingFlow::initiate(
        now,
        "did:keri:test".to_string(),
        "http://localhost:3000".to_string(),
        vec!["sign_commit".to_string()],
    )
    .unwrap();

    // Responder side (simulating the mobile device).
    let (seed, pubkey) = gen_p256_test_pair();
    let token_bytes = serde_json::to_vec(&token).unwrap();
    let resp_result = respond_to_pairing(
        now,
        &token_bytes,
        &seed,
        &pubkey,
        "did:key:zDnaTest".to_string(),
        None,
    )
    .unwrap();

    // Round-trip the response through bytes (the wire would).
    let response_bytes = serde_json::to_vec(&resp_result.response).unwrap();
    let response: PairingResponse = serde_json::from_slice(&response_bytes).unwrap();

    // Transition: Init → Responded.
    let responded = flow.accept_response(now, response).unwrap();

    // The initiator's SAS matches the responder's — property of the
    // shared HKDF inputs.
    let initiator_sas = *responded.sas().unwrap();
    assert_eq!(initiator_sas, resp_result.sas);

    // User confirms visually. Produce the SasMatch token.
    let proof = SasMatch::user_confirmed_visual_match(&initiator_sas, &resp_result.sas);

    // Transition: Responded → Confirmed → Paired.
    let confirmed = responded.confirm(proof);
    let (_paired_handle, completed) = confirmed.finalize().unwrap();

    assert_eq!(completed.peer_did, "did:key:zDnaTest");
    assert_eq!(completed.sas, initiator_sas);
}

#[test]
fn sas_match_token_is_only_constructable_with_both_byte_arrays() {
    // Compile-check: the `SasMatch::user_confirmed_visual_match` signature
    // takes both SAS arrays. If someone tries to construct a SasMatch by
    // literal (`SasMatch {}`) the `#[non_exhaustive]` attribute prevents it.
    // This is a runtime test of the happy path.
    let sas_a = [0u8; 10];
    let sas_b = [0u8; 10];
    let _proof = SasMatch::user_confirmed_visual_match(&sas_a, &sas_b);
    // The token is zero-sized; we can only prove it was produced, not
    // introspect it. Construction above is the assertion.
}
