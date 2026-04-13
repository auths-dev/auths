//! PKCS8 round-trip invariant harness (fn-114.11).
//!
//! Purpose: catch silent S3/S4 corruption before call-site sweeps land.
//! Invariant: for every seed the codebase produces or stores, a PKCS8 encode
//! followed by `parse_key_material` yields the same `TypedSeed` curve AND the
//! same derived public key.
//!
//! Silent-corruption hazards currently in the tree:
//! - S3: `build_ed25519_pkcs8_v2(&p256_seed, &fake_pubkey)` wraps a P-256 seed in
//!   an Ed25519 PKCS8 OID (1.3.101.112). The resulting bytes parse cleanly as
//!   Ed25519 but the derived public key does NOT match the original P-256
//!   verifying key — signatures produced under this "key" will never verify.
//! - S4: `encode_seed_as_pkcs8` (in auths-id) carries the same hazard.
//!
//! Strategy for this harness (fn-114.11 → fn-114.18):
//! - Positive cases run in the default test suite (`cargo test`). They pass
//!   today and must keep passing after fn-114.18 migrates the encoders.
//! - Negative cases carry `#[ignore]` with an `UNGATE IN fn-114.18` marker.
//!   Running `cargo test -- --include-ignored` today shows them failing by
//!   design — they document the hazard. fn-114.18 removes each `#[ignore]`
//!   incrementally as it migrates the matching encoder call site, at which
//!   point the negative tests flip to passing (because the hazardous encoder
//!   is no longer reachable from the code path the test exercises).
//!
//! Main stays green throughout the refactor.

use auths_crypto::{
    CurveType, TypedSeed, build_ed25519_pkcs8_v2, parse_ed25519_key_material, parse_key_material,
};

/// Produce a deterministic Ed25519 keypair via ring, returning (seed_bytes, pubkey_bytes, pkcs8_v2_der).
fn ed25519_keypair(seed_byte: u8) -> ([u8; 32], [u8; 32], Vec<u8>) {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let seed = [seed_byte; 32];
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).expect("ring accepts any 32-byte seed");
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(kp.public_key().as_ref());
    let pkcs8 = build_ed25519_pkcs8_v2(&seed, &pubkey);
    (seed, pubkey, pkcs8)
}

/// Produce a deterministic P-256 keypair via the p256 crate.
/// Returns (scalar_bytes, compressed_pubkey_33_bytes, pkcs8_der).
fn p256_keypair(scalar_byte: u8) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::pkcs8::EncodePrivateKey;

    let mut scalar = [scalar_byte; 32];
    scalar[0] |= 1;
    let sk = SigningKey::from_slice(&scalar).expect("non-zero scalar is valid");
    let vk = VerifyingKey::from(&sk);
    let compressed = vk.to_encoded_point(true).as_bytes().to_vec();

    let secret_doc = sk.to_pkcs8_der().expect("p256 pkcs8 encode");
    let pkcs8 = secret_doc.as_bytes().to_vec();

    let mut scalar_out = [0u8; 32];
    scalar_out.copy_from_slice(&sk.to_bytes());
    (scalar_out, compressed, pkcs8)
}

// --- Positive cases (green on main today; must stay green across fn-114.18) ---

#[test]
fn ed25519_pkcs8_roundtrip_preserves_curve_and_pubkey() {
    let (seed_in, pubkey_in, pkcs8) = ed25519_keypair(0x11);

    let parsed = parse_key_material(&pkcs8).expect("ed25519 pkcs8 parses");
    assert_eq!(parsed.seed.curve(), CurveType::Ed25519);
    assert!(matches!(parsed.seed, TypedSeed::Ed25519(_)));
    assert_eq!(parsed.seed.as_bytes(), &seed_in);
    assert_eq!(parsed.public_key.as_slice(), &pubkey_in[..]);
}

#[test]
fn ed25519_pkcs8_legacy_key_material_matches_typed_parse() {
    let (seed_in, pubkey_in, pkcs8) = ed25519_keypair(0x22);

    let (legacy_seed, legacy_pk) =
        parse_ed25519_key_material(&pkcs8).expect("legacy parser still works");
    assert_eq!(legacy_seed.as_bytes(), &seed_in);
    assert_eq!(legacy_pk.expect("pkcs8 v2 embeds pubkey"), pubkey_in);

    let parsed = parse_key_material(&pkcs8).expect("typed parse");
    assert_eq!(parsed.seed.as_bytes(), &seed_in);
    assert_eq!(parsed.public_key, pubkey_in);
}

#[test]
fn p256_pkcs8_roundtrip_preserves_curve_and_pubkey() {
    let (scalar_in, pubkey_in, pkcs8) = p256_keypair(0x33);

    let parsed = parse_key_material(&pkcs8).expect("p256 pkcs8 parses");
    assert_eq!(parsed.seed.curve(), CurveType::P256);
    assert!(matches!(parsed.seed, TypedSeed::P256(_)));
    assert_eq!(parsed.seed.as_bytes(), &scalar_in);
    assert_eq!(parsed.public_key.len(), 33, "compressed SEC1");
    assert_eq!(parsed.public_key, pubkey_in);
}

#[test]
fn parse_key_material_rejects_garbage() {
    let err = parse_key_material(&[0u8; 50]).expect_err("length 50 is not any known format");
    let msg = format!("{err}");
    assert!(
        msg.contains("Unrecognized") || msg.contains("Invalid"),
        "expected unrecognized-format error, got: {msg}"
    );
}

// --- Negative cases (hazard demonstrations) ---
//
// Every #[ignore] below carries `UNGATE IN fn-114.18`. fn-114.18 removes the
// #[ignore] attribute for each call site it migrates to a curve-aware encoder.
// Once the hazardous encoder has no in-tree callers, the negative test flips
// to passing because `parse_key_material` on the re-encoded bytes now returns
// the correct curve and pubkey.

#[test]
#[ignore = "UNGATE IN fn-114.18 — documents S3 silent hazard: \
    build_ed25519_pkcs8_v2 accepts a P-256 scalar and emits an Ed25519 PKCS8 blob. \
    The derived Ed25519 pubkey does NOT match the original P-256 verifying key, \
    but nothing errors. fn-114.18 migrates callers to TypedSignerKey::to_pkcs8, \
    after which this call path is unreachable and this test is removable."]
fn p256_seed_through_ed25519_pkcs8_encoder_silently_corrupts() {
    let (p256_scalar, p256_pubkey, _p256_pkcs8) = p256_keypair(0x44);

    let fake_ed_pubkey = [0x55u8; 32];
    let misencoded = build_ed25519_pkcs8_v2(&p256_scalar, &fake_ed_pubkey);

    let parsed = parse_key_material(&misencoded).expect("bytes parse as Ed25519 PKCS8");
    assert_eq!(
        parsed.seed.curve(),
        CurveType::Ed25519,
        "parser dispatches on OID, not original scalar's true curve"
    );

    let derived_pk = &parsed.public_key[..];
    assert_ne!(
        derived_pk,
        &p256_pubkey[..],
        "if this assertion FAILS, the hazard has already been fixed — delete this test"
    );
}

#[test]
#[ignore = "UNGATE IN fn-114.18 — the Ed25519 PKCS8 derived from a P-256 scalar will NOT \
    round-trip to the original P-256 compressed pubkey. Proves the encoder cannot be \
    retrofitted to handle P-256; callers must use the curve-aware encoder."]
fn p256_cannot_roundtrip_through_ed25519_encoder() {
    let (p256_scalar, p256_pubkey, _) = p256_keypair(0x66);

    let placeholder_pk = [0u8; 32];
    let misencoded = build_ed25519_pkcs8_v2(&p256_scalar, &placeholder_pk);

    let parsed = parse_key_material(&misencoded).expect("bytes parse as Ed25519 PKCS8");
    let roundtrip_equal = parsed.public_key == p256_pubkey;
    assert!(
        !roundtrip_equal,
        "Ed25519 PKCS8 wrapper cannot round-trip a P-256 pubkey — this test documents that invariant"
    );
}
