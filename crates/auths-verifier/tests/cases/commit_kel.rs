//! KEL-native commit verdict (Epic B core) — verifies the delegation + revocation +
//! binding logic against constructed KELs and the real signed-commit fixture.

use auths_crypto::RingCryptoProvider;
use auths_keri::witness::{WitnessReceipt, WitnessReceiptLookup};
use auths_keri::{
    CesrKey, DipEvent, DipEventInit, Event, IcpEvent, IcpEventInit, IxnEvent, KeriPublicKey,
    KeriSequence, Prefix, Said, Seal, Threshold, VersionString, compute_next_commitment,
    finalize_dip_event, finalize_icp_event, finalize_ixn_event,
};
use auths_verifier::{
    CommitVerdict, VerifierWitnessPolicy, WitnessGateStatus, verify_commit_against_kel,
    verify_commit_against_kel_witnessed,
};

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

// ── D.7: verifier-side witness gate ──────────────────────────────────────────

/// Said-keyed receipt source for verify-gate tests.
struct MapReceipts {
    by_said: std::collections::HashMap<String, Vec<WitnessReceipt>>,
}

impl WitnessReceiptLookup for MapReceipts {
    fn receipts_for(
        &self,
        _controller: &Prefix,
        _sn: KeriSequence,
        said: &Said,
    ) -> Vec<WitnessReceipt> {
        self.by_said.get(said.as_str()).cloned().unwrap_or_default()
    }
}

fn wreceipt(aid: &str) -> WitnessReceipt {
    WitnessReceipt {
        witness: Prefix::new_unchecked(aid.to_string()),
        signature: vec![],
    }
}

/// Like `build`, but the root `icp` designates `backers` with threshold `bt`.
/// Returns the fixture and the root inception SAID (the gated establishment event).
fn build_witnessed(device_key: &KeriPublicKey, bt: u64, backers: &[&str]) -> (Fixture, Said) {
    let b: Vec<Prefix> = backers
        .iter()
        .map(|a| Prefix::new_unchecked(a.to_string()))
        .collect();
    let root_icp = finalize_icp_event(IcpEvent::new(IcpEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![cesr(&dummy_key(1))],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&dummy_key(2))],
        bt: Threshold::Simple(bt),
        b,
        c: vec![],
        a: vec![],
    }))
    .expect("root icp");
    let root_prefix = root_icp.i.clone();
    let root_said = root_icp.d.clone();

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
        di: root_prefix.clone(),
    }))
    .expect("device dip");
    let device_prefix = dip.i.clone();
    let dip_said = dip.d.clone();

    let ixn = finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: root_prefix.clone(),
        s: KeriSequence::new(1),
        p: root_icp.d.clone(),
        a: vec![Seal::KeyEvent {
            i: device_prefix.clone(),
            s: KeriSequence::new(0),
            d: dip_said.clone(),
        }],
    })
    .expect("anchor ixn");

    let fixture = Fixture {
        root_kel: vec![Event::Icp(root_icp), Event::Ixn(ixn)],
        device_kel: vec![Event::Dip(dip)],
        root_did: format!("did:keri:{root_prefix}"),
    };
    (fixture, root_said)
}

fn receipts_under(said: &Said, aids: &[&str]) -> MapReceipts {
    let mut by_said = std::collections::HashMap::new();
    by_said.insert(
        said.as_str().to_string(),
        aids.iter().map(|a| wreceipt(a)).collect(),
    );
    MapReceipts { by_said }
}

#[tokio::test]
async fn verify_passes_with_quorum() {
    let (f, root_said) = build_witnessed(&fixture_device_key(), 2, &["BWit1", "BWit2"]);
    let lookup = receipts_under(&root_said, &["BWit1", "BWit2"]);
    let wv = verify_commit_against_kel_witnessed(
        FIXTURE_COMMIT.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
        &lookup,
        VerifierWitnessPolicy::Warn,
    )
    .await;
    assert!(wv.verdict.is_valid(), "verdict: {:?}", wv.verdict);
    assert_eq!(wv.witness, WitnessGateStatus::Met);
}

#[tokio::test]
async fn verify_warns_under_quorum_by_default() {
    let (f, root_said) = build_witnessed(&fixture_device_key(), 2, &["BWit1", "BWit2"]);
    let lookup = receipts_under(&root_said, &["BWit1"]); // 1 of 2
    let wv = verify_commit_against_kel_witnessed(
        FIXTURE_COMMIT.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
        &lookup,
        VerifierWitnessPolicy::Warn,
    )
    .await;
    // Warn: still authorized, but the under-quorum status is surfaced.
    assert!(wv.verdict.is_valid(), "verdict: {:?}", wv.verdict);
    assert_eq!(
        wv.witness,
        WitnessGateStatus::UnderQuorum {
            collected: 1,
            required: 2
        }
    );
}

#[tokio::test]
async fn verify_fails_under_quorum_when_required() {
    let (f, root_said) = build_witnessed(&fixture_device_key(), 2, &["BWit1", "BWit2"]);
    let lookup = receipts_under(&root_said, &["BWit1"]); // 1 of 2
    let wv = verify_commit_against_kel_witnessed(
        FIXTURE_COMMIT.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
        &lookup,
        VerifierWitnessPolicy::RequireWitnesses,
    )
    .await;
    assert!(!wv.verdict.is_valid());
    assert!(matches!(
        wv.verdict,
        CommitVerdict::WitnessQuorumNotMet {
            collected: 1,
            required: 2,
            ..
        }
    ));
}

#[tokio::test]
async fn verify_bt_zero_kel_unaffected() {
    // A bt=0 root verifies identically with or without the gate, even fail-closed.
    let f = build(&fixture_device_key(), true, false, None);
    let lookup = MapReceipts {
        by_said: std::collections::HashMap::new(),
    };
    let wv = verify_commit_against_kel_witnessed(
        FIXTURE_COMMIT.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
        &lookup,
        VerifierWitnessPolicy::RequireWitnesses,
    )
    .await;
    assert!(wv.verdict.is_valid(), "verdict: {:?}", wv.verdict);
    assert_eq!(wv.witness, WitnessGateStatus::NotRequired);
}
