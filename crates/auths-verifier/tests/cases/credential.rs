//! Epic F.5 — pure ACDC credential verification (`verify_credential`).
//!
//! Builds an issuer KEL that anchors a backerless TEL (`vcp`/`iss`/optional `rev`),
//! signs the ACDC with the issuer's signing-time key, and exercises the twelve
//! lifecycle/quorum cases on BOTH curves. Everything is constructed in-memory: no
//! git, no network, matching the WASM-safe verifier contract.

use auths_crypto::{CurveType, RingCryptoProvider};
use auths_keri::witness::{Receipt, ReceiptTag, SignedReceipt, StoredReceipt};
use auths_keri::{
    Acdc, CesrKey, Event, IcpEvent, IcpEventInit, Iss, IxnEvent, KeriPublicKey, KeriSequence,
    Prefix, Rev, Said, Seal, TelAnchorSeal, TelEvent, Threshold, Vcp, VersionString,
    compute_capability_schema_said, compute_next_commitment, encode_tel_nonce, finalize_icp_event,
    finalize_ixn_event,
};
use auths_verifier::{CredentialVerdict, LifecycleEvent, SignedAcdc, VerifierWitnessPolicy};
use chrono::{TimeZone, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Map, Value};

const DT: &str = "2025-01-01T00:00:00.000000+00:00";

fn provider() -> RingCryptoProvider {
    RingCryptoProvider
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()
}

/// Synchronously sign with Ed25519 (ring) — matches what `RingCryptoProvider` does.
fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 keypair");
    kp.sign(message).as_ref().to_vec()
}

/// The 32-byte Ed25519 public key for a seed.
fn ed25519_pubkey(seed: &[u8; 32]) -> [u8; 32] {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 keypair");
    kp.public_key().as_ref().try_into().expect("32-byte pubkey")
}

/// Synchronously sign with P-256 (deterministic ECDSA, 64-byte r||s).
fn p256_sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    let sk = SigningKey::from_slice(seed).expect("p256 key");
    let sig: Signature = sk.sign(message);
    sig.to_bytes().to_vec()
}

/// The 33-byte compressed SEC1 P-256 public key for a seed.
fn p256_pubkey(seed: &[u8; 32]) -> Vec<u8> {
    use p256::ecdsa::{SigningKey, VerifyingKey};
    let sk = SigningKey::from_slice(seed).expect("p256 key");
    let vk = VerifyingKey::from(&sk);
    vk.to_encoded_point(true).as_bytes().to_vec()
}

/// A signing key on the requested curve, derived from a 32-byte seed.
struct Signer {
    curve: CurveType,
    seed: [u8; 32],
    verkey: KeriPublicKey,
}

impl Signer {
    fn new(curve: CurveType, seed_byte: u8) -> Self {
        let seed = [seed_byte; 32];
        let verkey = match curve {
            CurveType::Ed25519 => KeriPublicKey::ed25519(&ed25519_pubkey(&seed)).expect("ed25519"),
            CurveType::P256 => {
                KeriPublicKey::from_verkey_bytes(&p256_pubkey(&seed), CurveType::P256)
                    .expect("p256")
            }
        };
        Self {
            curve,
            seed,
            verkey,
        }
    }

    fn cesr(&self) -> CesrKey {
        CesrKey::new_unchecked(self.verkey.to_qb64().expect("qb64"))
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self.curve {
            CurveType::Ed25519 => ed25519_sign(&self.seed, message),
            CurveType::P256 => p256_sign(&self.seed, message),
        }
    }
}

/// One designated witness: an Ed25519 key whose AID is its own CESR verkey.
struct Witness {
    seed: [u8; 32],
    aid: Prefix,
}

impl Witness {
    fn new(seed_byte: u8) -> Self {
        let seed = [seed_byte; 32];
        let verkey = KeriPublicKey::ed25519(&ed25519_pubkey(&seed)).expect("witness verkey");
        Self {
            seed,
            aid: Prefix::new_unchecked(verkey.to_qb64().expect("qb64")),
        }
    }

    /// A signed receipt for a TEL event (`said`/`seq`), attributed to this witness.
    fn receipt_for(&self, controller: &Prefix, said: &Said, seq: u128) -> StoredReceipt {
        let receipt = Receipt {
            v: VersionString::placeholder(),
            t: ReceiptTag,
            d: said.clone(),
            i: controller.clone(),
            s: KeriSequence::new(seq),
        };
        let payload = serde_json::to_vec(&receipt).expect("receipt json");
        let signature = ed25519_sign(&self.seed, &payload);
        StoredReceipt {
            signed: SignedReceipt { receipt, signature },
            witness: self.aid.clone(),
        }
    }
}

/// A length-valid Ed25519 key for non-signing roles (next-key commitments).
fn dummy_key(seed: u8) -> KeriPublicKey {
    KeriPublicKey::ed25519(&[seed; 32]).expect("ed25519")
}

/// The pinned capability schema SAID embedded by the verifier.
fn schema_said() -> Said {
    compute_capability_schema_said().expect("schema said")
}

/// Build a capability ACDC and the issuer's detached signature over its wire bytes.
fn build_credential(
    issuer: &Signer,
    issuer_aid: &Prefix,
    registry: &Said,
    subject: &str,
    capability: &str,
    expiry: Option<&str>,
) -> (Acdc, SignedAcdc) {
    let mut data = Map::new();
    data.insert(
        "capability".to_string(),
        Value::String(capability.to_string()),
    );
    if let Some(exp) = expiry {
        data.insert("expiry".to_string(), Value::String(exp.to_string()));
    }
    let acdc = Acdc::new(
        issuer_aid.clone(),
        registry.clone(),
        schema_said(),
        Prefix::new_unchecked(subject.to_string()),
        DT.to_string(),
        data,
    )
    .saidify()
    .expect("saidify");

    let wire = acdc.to_wire_bytes().expect("wire");
    let signature = issuer.sign(&wire);
    (acdc.clone(), SignedAcdc { acdc, signature })
}

/// A complete issuer KEL + TEL fixture for one credential lifecycle.
struct Fixture {
    issuer: Signer,
    issuer_aid: Prefix,
    issuer_kel: Vec<Event>,
    tel: Vec<TelEvent>,
    registry: Said,
    iss_said: Said,
    /// The signed credential whose SAID equals the TEL `iss` target.
    signed: SignedAcdc,
}

struct FixtureSpec {
    curve: CurveType,
    witnesses: Vec<Prefix>,
    witness_threshold: u64,
    revoke: bool,
    capability: String,
    expiry: Option<String>,
}

impl FixtureSpec {
    fn basic(curve: CurveType, revoke: bool) -> Self {
        Self {
            curve,
            witnesses: vec![],
            witness_threshold: 0,
            revoke,
            capability: "sign".to_string(),
            expiry: None,
        }
    }

    fn witnessed(curve: CurveType, witnesses: Vec<Prefix>, threshold: u64, revoke: bool) -> Self {
        Self {
            curve,
            witnesses,
            witness_threshold: threshold,
            revoke,
            capability: "sign".to_string(),
            expiry: None,
        }
    }
}

/// Build an issuer KEL that anchors `vcp` then `iss` (and optionally `rev`), with
/// optional designated witnesses (`b[]`/`bt`) on every event.
fn build_fixture(spec: &FixtureSpec) -> Fixture {
    let issuer = Signer::new(spec.curve, 1);

    let bt = Threshold::Simple(spec.witness_threshold);
    let icp = finalize_icp_event(IcpEvent::new(IcpEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![issuer.cesr()],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&dummy_key(2))],
        bt: bt.clone(),
        b: spec.witnesses.clone(),
        c: vec![],
        a: vec![],
    }))
    .expect("issuer icp");
    let issuer_aid = icp.i.clone();

    let nonce = encode_tel_nonce(&[7u8; 16]).expect("nonce");
    let vcp = Vcp::new(issuer_aid.clone(), nonce).saidify().expect("vcp");
    let registry = vcp.registry().clone();

    // The TEL `iss` `i` is the credential SAID, so build the credential first.
    let (acdc, signed) = build_credential(
        &issuer,
        &issuer_aid,
        &registry,
        &self_addressing_subject(),
        &spec.capability,
        spec.expiry.as_deref(),
    );
    let iss = Iss::new(acdc.d.clone(), registry.clone(), DT.to_string())
        .saidify()
        .expect("iss");

    let mut kel = vec![Event::Icp(icp.clone())];
    let mut last_said = icp.d.clone();
    let mut seq = 1u128;

    // ixn anchoring the vcp (registry inception).
    let vcp_ixn = anchor_ixn(&issuer_aid, seq, &last_said, &registry, vcp.s, &vcp.d);
    last_said = vcp_ixn.d.clone();
    kel.push(Event::Ixn(vcp_ixn));
    seq += 1;

    // ixn anchoring the iss (credential issuance).
    let iss_ixn = anchor_ixn(&issuer_aid, seq, &last_said, &registry, iss.s, &iss.d);
    last_said = iss_ixn.d.clone();
    kel.push(Event::Ixn(iss_ixn));
    seq += 1;

    let mut tel = vec![TelEvent::Vcp(vcp.clone()), TelEvent::Iss(iss.clone())];

    if spec.revoke {
        let rev = Rev::new(
            acdc.d.clone(),
            registry.clone(),
            iss.d.clone(),
            DT.to_string(),
        )
        .saidify()
        .expect("rev");
        let rev_ixn = anchor_ixn(&issuer_aid, seq, &last_said, &registry, rev.s, &rev.d);
        kel.push(Event::Ixn(rev_ixn));
        tel.push(TelEvent::Rev(rev));
    }

    Fixture {
        issuer,
        issuer_aid,
        issuer_kel: kel,
        tel,
        registry,
        iss_said: iss.d.clone(),
        signed,
    }
}

/// A deterministic self-addressing-shaped subject AID (E-prefixed) for the holder.
fn self_addressing_subject() -> String {
    "EHolder000000000000000000000000000000000000".to_string()
}

/// An `ixn` carrying the `{i,s,d}` TEL anchor seal for a TEL event.
fn anchor_ixn(
    issuer_aid: &Prefix,
    seq: u128,
    prior: &Said,
    registry: &Said,
    tel_seq: KeriSequence,
    tel_said: &Said,
) -> IxnEvent {
    let seal = TelAnchorSeal::for_event(
        Prefix::new_unchecked(registry.as_str().to_string()),
        tel_seq,
        tel_said.clone(),
    );
    finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: issuer_aid.clone(),
        s: KeriSequence::new(seq),
        p: prior.clone(),
        a: vec![Seal::KeyEvent {
            i: seal.i,
            s: seal.s,
            d: seal.d,
        }],
    })
    .expect("anchor ixn")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn valid_credential_verifies() {
    for curve in [CurveType::P256, CurveType::Ed25519] {
        let f = build_fixture(&FixtureSpec::basic(curve, false));

        let verdict = auths_verifier::verify_credential(
            &f.signed,
            &f.issuer_kel,
            &f.tel,
            &[],
            VerifierWitnessPolicy::Warn,
            now(),
            &provider(),
        )
        .await;

        match verdict {
            CredentialVerdict::Valid {
                issuer,
                subject,
                caps,
                as_of,
            } => {
                assert_eq!(issuer.as_str(), format!("did:keri:{}", f.issuer_aid));
                assert_eq!(
                    subject.as_str(),
                    format!("did:keri:{}", self_addressing_subject())
                );
                assert_eq!(
                    caps.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    ["sign"]
                );
                assert_eq!(as_of, 2, "as_of is the tip of the given KEL ({curve:?})");
            }
            other => panic!("expected Valid on {curve:?}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn schema_mismatch_rejected() {
    let f = build_fixture(&FixtureSpec::basic(CurveType::P256, false));
    // A credential pinning an unknown schema SAID is rejected (offline pin check).
    let mut data = Map::new();
    data.insert("capability".to_string(), Value::String("sign".into()));
    let acdc = Acdc::new(
        f.issuer_aid.clone(),
        f.registry.clone(),
        Said::new_unchecked("EUnknownSchemaSaid00000000000000000000000000".into()),
        Prefix::new_unchecked(self_addressing_subject()),
        DT.to_string(),
        data,
    )
    .saidify()
    .expect("saidify");
    let wire = acdc.to_wire_bytes().unwrap();
    let signature = f.issuer.sign(&wire);
    let signed = SignedAcdc { acdc, signature };

    let verdict = auths_verifier::verify_credential(
        &signed,
        &f.issuer_kel,
        &f.tel,
        &[],
        VerifierWitnessPolicy::Warn,
        now(),
        &provider(),
    )
    .await;
    assert_eq!(verdict, CredentialVerdict::SchemaInvalid);
}

#[tokio::test]
async fn revoked_credential_rejected_by_kel_position() {
    let f = build_fixture(&FixtureSpec::basic(CurveType::P256, true));

    let verdict = auths_verifier::verify_credential(
        &f.signed,
        &f.issuer_kel,
        &f.tel,
        &[],
        VerifierWitnessPolicy::Warn,
        now(),
        &provider(),
    )
    .await;
    // rev anchored at KEL seq 3, presentation tip is 3 -> revoked.
    assert_eq!(
        verdict,
        CredentialVerdict::CredentialRevoked { revoked_at: 3 }
    );
}

#[tokio::test]
async fn credential_presented_before_rev_valid() {
    let f = build_fixture(&FixtureSpec::basic(CurveType::P256, true));

    // Present the KEL truncated to BEFORE the revocation ixn (seq 0..=2): the
    // revocation is not yet anchored at this position, so the credential is valid.
    let pre_rev_kel: Vec<Event> = f
        .issuer_kel
        .iter()
        .filter(|e| e.sequence().value() <= 2)
        .cloned()
        .collect();
    let tel_no_rev: Vec<TelEvent> = f
        .tel
        .iter()
        .filter(|e| !matches!(e, TelEvent::Rev(_)))
        .cloned()
        .collect();

    let verdict = auths_verifier::verify_credential(
        &f.signed,
        &pre_rev_kel,
        &tel_no_rev,
        &[],
        VerifierWitnessPolicy::Warn,
        now(),
        &provider(),
    )
    .await;
    assert!(
        verdict.is_valid(),
        "credential presented before the rev is valid, got {verdict:?}"
    );
}

#[tokio::test]
async fn unanchored_registry_rejected() {
    let f = build_fixture(&FixtureSpec::basic(CurveType::P256, false));

    // Drop the vcp-anchoring ixn (KEL seq 1) so the registry is never established.
    let kel_without_vcp_anchor: Vec<Event> = f
        .issuer_kel
        .iter()
        .filter(|e| e.sequence().value() != 1)
        .cloned()
        .collect();

    let verdict = auths_verifier::verify_credential(
        &f.signed,
        &kel_without_vcp_anchor,
        &f.tel,
        &[],
        VerifierWitnessPolicy::Warn,
        now(),
        &provider(),
    )
    .await;
    assert_eq!(verdict, CredentialVerdict::RegistryNotEstablished);
}

#[tokio::test]
async fn issuer_rotated_after_issue_still_valid() {
    // The issuer rotates AFTER anchoring the iss; the credential signed with the
    // pre-rotation key stays valid (signing-time key recovery, take-while <= iss seq).
    let f = build_fixture(&FixtureSpec::basic(CurveType::Ed25519, false));

    let mut rotated_kel = f.issuer_kel.clone();
    let tip = rotated_kel.last().expect("tip");
    let rot = auths_keri::finalize_rot_event(auths_keri::RotEvent::new(auths_keri::RotEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: f.issuer_aid.clone(),
        s: KeriSequence::new(3),
        p: tip.said().clone(),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(dummy_key(2).to_qb64().unwrap())],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&dummy_key(9))],
        bt: Threshold::Simple(0),
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
    }))
    .expect("rot");
    rotated_kel.push(Event::Rot(rot));

    let verdict = auths_verifier::verify_credential(
        &f.signed,
        &rotated_kel,
        &f.tel,
        &[],
        VerifierWitnessPolicy::Warn,
        now(),
        &provider(),
    )
    .await;
    assert!(
        verdict.is_valid(),
        "rotation after issue must not invalidate, got {verdict:?}"
    );
}

#[tokio::test]
async fn under_quorum_iss_fails_closed_require_witnesses() {
    let w1 = Witness::new(50);
    let w2 = Witness::new(51);
    let f = build_fixture(&FixtureSpec::witnessed(
        CurveType::P256,
        vec![w1.aid.clone(), w2.aid.clone()],
        2,
        false,
    ));

    // Quorum on vcp; only ONE receipt on the iss anchor -> 1-of-2 -> under quorum.
    let receipts = vec![
        w1.receipt_for(&f.issuer_aid, &f.registry, 0),
        w2.receipt_for(&f.issuer_aid, &f.registry, 0),
        w1.receipt_for(&f.issuer_aid, &f.iss_said, 0),
    ];

    let verdict = auths_verifier::verify_credential(
        &f.signed,
        &f.issuer_kel,
        &f.tel,
        &receipts,
        VerifierWitnessPolicy::RequireWitnesses,
        now(),
        &provider(),
    )
    .await;
    match verdict {
        CredentialVerdict::WitnessQuorumNotMet {
            event,
            collected,
            required,
        } => {
            assert_eq!(event, LifecycleEvent::Iss);
            assert_eq!(collected, 1);
            assert_eq!(required, 2);
        }
        other => panic!("expected WitnessQuorumNotMet(iss), got {other:?}"),
    }
}

#[tokio::test]
async fn under_quorum_iss_warns_by_default() {
    let w1 = Witness::new(60);
    let w2 = Witness::new(61);
    let f = build_fixture(&FixtureSpec::witnessed(
        CurveType::P256,
        vec![w1.aid.clone(), w2.aid.clone()],
        2,
        false,
    ));

    // No receipts at all, default Warn policy -> accepted (TOFS).
    let verdict = auths_verifier::verify_credential(
        &f.signed,
        &f.issuer_kel,
        &f.tel,
        &[],
        VerifierWitnessPolicy::Warn,
        now(),
        &provider(),
    )
    .await;
    assert!(
        verdict.is_valid(),
        "under-quorum is a non-fatal warning under Warn, got {verdict:?}"
    );
}

#[tokio::test]
async fn under_quorum_rev_does_not_revoke_require_witnesses() {
    let w1 = Witness::new(70);
    let w2 = Witness::new(71);
    let f = build_fixture(&FixtureSpec::witnessed(
        CurveType::P256,
        vec![w1.aid.clone(), w2.aid.clone()],
        2,
        true,
    ));

    // Full quorum on vcp + iss; only ONE receipt on the rev -> rev under quorum.
    let receipts = vec![
        w1.receipt_for(&f.issuer_aid, &f.registry, 0),
        w2.receipt_for(&f.issuer_aid, &f.registry, 0),
        w1.receipt_for(&f.issuer_aid, &f.iss_said, 0),
        w2.receipt_for(&f.issuer_aid, &f.iss_said, 0),
        w1.receipt_for(&f.issuer_aid, rev_said(&f), 1),
    ];

    let verdict = auths_verifier::verify_credential(
        &f.signed,
        &f.issuer_kel,
        &f.tel,
        &receipts,
        VerifierWitnessPolicy::RequireWitnesses,
        now(),
        &provider(),
    )
    .await;
    assert!(
        verdict.is_valid(),
        "a sub-quorum rev must NOT revoke under RequireWitnesses, got {verdict:?}"
    );
}

#[tokio::test]
async fn under_quorum_rev_revokes_under_warn() {
    let w1 = Witness::new(80);
    let w2 = Witness::new(81);
    let f = build_fixture(&FixtureSpec::witnessed(
        CurveType::P256,
        vec![w1.aid.clone(), w2.aid.clone()],
        2,
        true,
    ));

    // Even with NO receipts on the rev, under Warn a seen rev revokes (conservative).
    let verdict = auths_verifier::verify_credential(
        &f.signed,
        &f.issuer_kel,
        &f.tel,
        &[],
        VerifierWitnessPolicy::Warn,
        now(),
        &provider(),
    )
    .await;
    assert_eq!(
        verdict,
        CredentialVerdict::CredentialRevoked { revoked_at: 3 },
        "a seen rev revokes under Warn"
    );
}

/// The rev TEL SAID for a revoking fixture.
fn rev_said(f: &Fixture) -> &Said {
    f.tel
        .iter()
        .find_map(|e| match e {
            TelEvent::Rev(rev) => Some(&rev.d),
            _ => None,
        })
        .expect("fixture has a rev")
}

#[tokio::test]
async fn issuer_kel_fork_detected() {
    let f = build_fixture(&FixtureSpec::basic(CurveType::P256, false));

    // Fork the KEL: append a second, different event at the tip's sequence.
    let mut forked = f.issuer_kel.clone();
    let tip = forked.last().expect("tip");
    let fork = finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: f.issuer_aid.clone(),
        s: tip.sequence(),
        p: tip.previous().cloned().unwrap_or_default(),
        a: vec![Seal::Digest {
            d: Said::new_unchecked("EForkedDifferentSeal0000000000000000000000".into()),
        }],
    })
    .expect("fork ixn");
    forked.push(Event::Ixn(fork));

    for policy in [
        VerifierWitnessPolicy::Warn,
        VerifierWitnessPolicy::RequireWitnesses,
    ] {
        let verdict = auths_verifier::verify_credential(
            &f.signed,
            &forked,
            &f.tel,
            &[],
            policy,
            now(),
            &provider(),
        )
        .await;
        assert_eq!(
            verdict,
            CredentialVerdict::IssuerKelDuplicitous,
            "fork detected in {policy:?}"
        );
    }
}

#[tokio::test]
async fn valid_reports_as_of_position() {
    let f = build_fixture(&FixtureSpec::basic(CurveType::Ed25519, false));

    // Extend the KEL with a benign ixn so the tip advances; as_of must follow it.
    let mut extended = f.issuer_kel.clone();
    let tip = extended.last().expect("tip");
    let benign = finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: f.issuer_aid.clone(),
        s: KeriSequence::new(3),
        p: tip.said().clone(),
        a: vec![],
    })
    .expect("benign ixn");
    extended.push(Event::Ixn(benign));

    let verdict = auths_verifier::verify_credential(
        &f.signed,
        &extended,
        &f.tel,
        &[],
        VerifierWitnessPolicy::Warn,
        now(),
        &provider(),
    )
    .await;
    match verdict {
        CredentialVerdict::Valid { as_of, .. } => {
            assert_eq!(as_of, 3, "as_of follows the tip of the given KEL");
        }
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[tokio::test]
async fn expired_credential_rejected() {
    // Sanity: the injected `now` drives expiry (no wall clock in the verifier).
    let mut spec = FixtureSpec::basic(CurveType::P256, false);
    spec.expiry = Some("2025-03-01T00:00:00+00:00".to_string());
    let f = build_fixture(&spec);

    let verdict = auths_verifier::verify_credential(
        &f.signed,
        &f.issuer_kel,
        &f.tel,
        &[],
        VerifierWitnessPolicy::Warn,
        now(), // 2025-06-01, after the 2025-03-01 expiry
        &provider(),
    )
    .await;
    assert!(matches!(verdict, CredentialVerdict::Expired { .. }));
}
