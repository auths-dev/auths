//! KEL-native commit verdict (Epic B core) — verifies the delegation + revocation +
//! binding logic against constructed KELs and the real signed-commit fixture.

use auths_crypto::RingCryptoProvider;
use auths_keri::witness::{WitnessReceipt, WitnessReceiptLookup};
use auths_keri::{
    AgentScope, CesrKey, DipEvent, DipEventInit, Event, IcpEvent, IcpEventInit, IxnEvent,
    KeriPublicKey, KeriSequence, Prefix, Said, Seal, SourceSeal, Threshold, VersionString,
    compute_next_commitment, encode_agent_scope, finalize_dip_event, finalize_icp_event,
    finalize_ixn_event,
};
use auths_verifier::{
    CommitVerdict, VerifierWitnessPolicy, WitnessGateStatus, verify_commit_against_kel,
    verify_commit_against_kel_scoped, verify_commit_against_kel_witnessed,
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

    let mut dip = finalize_dip_event(DipEvent::new(DipEventInit {
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
        // Delegate-side -G back-reference to the anchoring ixn (bilateral binding).
        dip.source_seal = Some(SourceSeal {
            s: KeriSequence::new(seq),
            d: ixn.d.clone(),
        });
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

    let mut dip = finalize_dip_event(DipEvent::new(DipEventInit {
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
    // Delegate-side -G back-reference to the anchoring ixn (bilateral binding).
    dip.source_seal = Some(SourceSeal {
        s: KeriSequence::new(1),
        d: ixn.d.clone(),
    });

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

#[tokio::test]
async fn commit_after_revocation_rejected() {
    // Revoked delegate (revocation anchored at root seq 2). A commit whose in-band
    // signing position is 3 (>= 2) is rejected by KEL position — distinctly from a
    // plain DeviceRevoked.
    let f = build(&fixture_device_key(), true, true, None);
    let commit = format!(
        "chore: late commit\n\nAuths-Id: {}\n{}\n",
        f.root_did,
        auths_verifier::anchor_seq_trailer(3)
    );
    let verdict = verify_commit_against_kel(
        commit.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
    )
    .await;
    assert!(
        matches!(
            verdict,
            CommitVerdict::SignedAfterRevocation {
                signed_at: 3,
                revoked_at: 2,
                ..
            }
        ),
        "expected SignedAfterRevocation{{3,2}}, got {verdict:?}"
    );
}

#[tokio::test]
async fn commit_before_revocation_passes_revocation_check() {
    // Same revoked delegate, but the commit's in-band position (1) precedes the
    // revocation (2): the revocation gate does NOT reject it — it proceeds to the
    // signature check (this hand-built commit is unsigned, so `Unsigned`), proving
    // legitimate prior history is not retroactively invalidated.
    let f = build(&fixture_device_key(), true, true, None);
    let commit = format!(
        "feat: earlier commit\n\nAuths-Id: {}\n{}\n",
        f.root_did,
        auths_verifier::anchor_seq_trailer(1)
    );
    let verdict = verify_commit_against_kel(
        commit.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
    )
    .await;
    assert!(
        !matches!(
            verdict,
            CommitVerdict::SignedAfterRevocation { .. } | CommitVerdict::DeviceRevoked
        ),
        "a before-revocation commit must pass the revocation gate, got {verdict:?}"
    );
    assert_eq!(verdict, CommitVerdict::Unsigned);
}

/// Build a delegated-agent fixture whose delegator anchors a scope/expiry seal for
/// the agent (root icp → anchor ixn → scope ixn).
fn build_scoped(device_key: &KeriPublicKey, scope: AgentScope) -> Fixture {
    let mut f = build(device_key, true, false, None);
    let root_prefix =
        Prefix::new_unchecked(f.root_did.strip_prefix("did:keri:").unwrap().to_string());
    let device_prefix = match &f.device_kel[0] {
        Event::Dip(d) => d.i.clone(),
        _ => unreachable!(),
    };
    let last = f.root_kel.last().unwrap().said().clone();
    let scope_ixn = finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: root_prefix,
        s: KeriSequence::new(f.root_kel.len() as u128),
        p: last,
        a: vec![Seal::Digest {
            d: Said::new_unchecked(encode_agent_scope(device_prefix.as_str(), &scope)),
        }],
    })
    .expect("scope ixn");
    f.root_kel.push(Event::Ixn(scope_ixn));
    f
}

#[tokio::test]
async fn agent_out_of_scope_signing_rejected() {
    let f = build_scoped(
        &fixture_device_key(),
        AgentScope {
            capabilities: vec!["sign_commit".to_string()],
            expires_at: None,
        },
    );
    // The commit claims a capability the delegator never granted.
    let commit = format!("feat: x\n\nAuths-Id: {}\nAuths-Scope: admin\n", f.root_did);
    let verdict = verify_commit_against_kel_scoped(
        commit.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
        0,
    )
    .await;
    assert!(
        matches!(verdict, CommitVerdict::OutsideAgentScope { ref capability, .. } if capability == "admin"),
        "got {verdict:?}"
    );
}

#[tokio::test]
async fn expired_agent_rejected_with_injected_now() {
    let f = build_scoped(
        &fixture_device_key(),
        AgentScope {
            capabilities: vec![],
            expires_at: Some(100),
        },
    );
    let commit = format!("feat: x\n\nAuths-Id: {}\n", f.root_did);
    // now (200) is past the anchored expiry (100).
    let verdict = verify_commit_against_kel_scoped(
        commit.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
        200,
    )
    .await;
    assert!(
        matches!(
            verdict,
            CommitVerdict::AgentExpired {
                expired_at: 100,
                signed_at: 200,
                ..
            }
        ),
        "got {verdict:?}"
    );
}

#[tokio::test]
async fn in_scope_unexpired_agent_verifies() {
    let f = build_scoped(
        &fixture_device_key(),
        AgentScope {
            capabilities: vec!["sign_commit".to_string()],
            expires_at: Some(10_000),
        },
    );
    let commit = format!(
        "feat: x\n\nAuths-Id: {}\nAuths-Scope: sign_commit\n",
        f.root_did
    );
    // In-scope capability, well before expiry → the scope/expiry gate passes (the
    // hand-built commit is unsigned, so the verdict is Unsigned, not a scope rejection).
    let verdict = verify_commit_against_kel_scoped(
        commit.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
        5,
    )
    .await;
    assert!(
        !matches!(
            verdict,
            CommitVerdict::OutsideAgentScope { .. } | CommitVerdict::AgentExpired { .. }
        ),
        "an in-scope unexpired agent must pass the scope/expiry gate, got {verdict:?}"
    );
    assert_eq!(verdict, CommitVerdict::Unsigned);
}

#[tokio::test]
async fn scope_is_delegator_anchored_not_self() {
    // The delegator grants only [sign_commit]. The agent CANNOT self-assert a wider
    // scope: the verifier reads the scope from the DELEGATOR's KEL, so a commit
    // claiming [admin] is rejected even though the agent signs it with its own key.
    let f = build_scoped(
        &fixture_device_key(),
        AgentScope {
            capabilities: vec!["sign_commit".to_string()],
            expires_at: None,
        },
    );
    let commit = format!("feat: x\n\nAuths-Id: {}\nAuths-Scope: admin\n", f.root_did);
    let verdict = verify_commit_against_kel_scoped(
        commit.as_bytes(),
        &f.device_kel,
        &f.root_kel,
        std::slice::from_ref(&f.root_did),
        &RingCryptoProvider,
        0,
    )
    .await;
    assert!(
        matches!(verdict, CommitVerdict::OutsideAgentScope { .. }),
        "a self-claimed capability outside the delegator scope must be rejected, got {verdict:?}"
    );
}
