//! KEL-native commit verdict (Epic B core) — verifies the delegation + revocation +
//! binding logic against constructed KELs and the real signed-commit fixture.

use auths_crypto::RingCryptoProvider;
use auths_keri::{
    CesrKey, DipEvent, DipEventInit, Event, IcpEvent, IcpEventInit, IxnEvent, KeriPublicKey,
    KeriSequence, Prefix, Said, Seal, Threshold, VersionString, compute_next_commitment,
    finalize_dip_event, finalize_icp_event, finalize_ixn_event,
};
use auths_verifier::{CommitVerdict, verify_commit_against_kel};

const FIXTURE_COMMIT: &str = include_str!("../fixtures/signed_commit.txt");
const FIXTURE_PUBKEY_HEX: &str = include_str!("../fixtures/pubkey.hex");

fn cesr(pk: &KeriPublicKey) -> CesrKey {
    CesrKey::new_unchecked(pk.to_qb64().expect("qb64"))
}

/// A length-valid (not point-validated) Ed25519 key for non-signing roles (root/next).
fn dummy_key(seed: u8) -> KeriPublicKey {
    KeriPublicKey::ed25519(&[seed; 32]).expect("ed25519")
}

/// The Ed25519 key that actually signed `FIXTURE_COMMIT`.
fn fixture_device_key() -> KeriPublicKey {
    let bytes = hex::decode(FIXTURE_PUBKEY_HEX.trim()).expect("hex");
    KeriPublicKey::ed25519(&bytes).expect("fixture key")
}

struct Fixture {
    root_kel: Vec<Event>,
    device_kel: Vec<Event>,
    root_did: String,
}

/// Build a delegated-device fixture: a root `icp` (+ optionally an `ixn` anchoring
/// the device dip, + optionally a revocation), and the device `dip` whose current
/// key is `device_key`. `delegator` overrides the dip's `di` (to test wrong-root).
fn build(
    device_key: &KeriPublicKey,
    anchor: bool,
    revoked: bool,
    delegator: Option<Prefix>,
) -> Fixture {
    let root_icp = finalize_icp_event(IcpEvent::new(IcpEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![cesr(&dummy_key(1))],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&dummy_key(2))],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
    }))
    .expect("root icp");
    let root_prefix = root_icp.i.clone();

    let dip = finalize_dip_event(DipEvent::new(DipEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![cesr(device_key)],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&dummy_key(3))],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
        di: delegator.unwrap_or_else(|| root_prefix.clone()),
    }))
    .expect("device dip");
    let device_prefix = dip.i.clone();
    let dip_said = dip.d.clone();

    let mut root_kel = vec![Event::Icp(root_icp.clone())];
    let mut last_said = root_icp.d.clone();
    let mut seq = 1u128;
    if anchor {
        let ixn = finalize_ixn_event(IxnEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: root_prefix.clone(),
            s: KeriSequence::new(seq),
            p: last_said.clone(),
            a: vec![Seal::KeyEvent {
                i: device_prefix.clone(),
                s: KeriSequence::new(0),
                d: dip_said.clone(),
            }],
        })
        .expect("anchor ixn");
        last_said = ixn.d.clone();
        seq += 1;
        root_kel.push(Event::Ixn(ixn));
    }
    if revoked {
        let rev = finalize_ixn_event(IxnEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: root_prefix.clone(),
            s: KeriSequence::new(seq),
            p: last_said,
            a: vec![Seal::Digest {
                d: Said::new_unchecked(device_prefix.as_str().to_string()),
            }],
        })
        .expect("revocation ixn");
        root_kel.push(Event::Ixn(rev));
    }

    Fixture {
        root_kel,
        device_kel: vec![Event::Dip(dip)],
        root_did: format!("did:keri:{root_prefix}"),
    }
}

#[tokio::test]
async fn delegated_device_current_key_is_valid() {
    let f = build(&fixture_device_key(), true, false, None);
    let verdict = verify_commit_against_kel(
        FIXTURE_COMMIT.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
    )
    .await;
    match verdict {
        CommitVerdict::Valid {
            root_did,
            duplicitous_root,
            ..
        } => {
            assert_eq!(root_did, f.root_did);
            assert!(!duplicitous_root, "a linear root KEL is not duplicitous");
        }
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[tokio::test]
async fn revoked_device_fails() {
    let f = build(&fixture_device_key(), true, true, None);
    let verdict = verify_commit_against_kel(
        FIXTURE_COMMIT.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        &[f.root_did],
        &RingCryptoProvider,
    )
    .await;
    assert_eq!(verdict, CommitVerdict::DeviceRevoked);
}

#[tokio::test]
async fn unanchored_dip_fails() {
    let f = build(&fixture_device_key(), false, false, None);
    let verdict = verify_commit_against_kel(
        FIXTURE_COMMIT.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        &[f.root_did],
        &RingCryptoProvider,
    )
    .await;
    assert_eq!(verdict, CommitVerdict::DelegationSealNotFound);
}

#[tokio::test]
async fn unpinned_root_fails() {
    let f = build(&fixture_device_key(), true, false, None);
    let verdict = verify_commit_against_kel(
        FIXTURE_COMMIT.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        &[], // nothing pinned
        &RingCryptoProvider,
    )
    .await;
    assert!(matches!(verdict, CommitVerdict::RootNotPinned(_)));
}

#[tokio::test]
async fn wrong_signer_key_fails() {
    // The device's current key is NOT the key that signed the fixture commit.
    let f = build(&dummy_key(9), true, false, None);
    let verdict = verify_commit_against_kel(
        FIXTURE_COMMIT.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        &[f.root_did],
        &RingCryptoProvider,
    )
    .await;
    assert_eq!(verdict, CommitVerdict::SignerKeyMismatch);
}

#[tokio::test]
async fn delegated_by_a_different_root_fails() {
    let other_root =
        Prefix::new_unchecked("ENotTheRealRootPrefixAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
    let f = build(&fixture_device_key(), true, false, Some(other_root));
    let verdict = verify_commit_against_kel(
        FIXTURE_COMMIT.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        &[f.root_did],
        &RingCryptoProvider,
    )
    .await;
    assert!(matches!(
        verdict,
        CommitVerdict::NotDelegatedByClaimedRoot { .. }
    ));
}
