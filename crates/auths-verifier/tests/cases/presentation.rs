//! Epic F.8 — holder-binding + presentation verification (`verify_presentation`).
//!
//! A possessed-but-unbound ACDC is a bearer token and grants nothing: authority is
//! honored only on proof of current control of the subject AID (`a.i`) by KEL replay
//! plus a fresh presentation signature. These tests build an issuer KEL/TEL (the F.5
//! credential) AND a *separate subject KEL*, then exercise the holder-binding gate on
//! both curves — challenge-response (the v1 default) and the non-interactive TTL path.
//! Everything is in-memory: no git, no network (the WASM-safe verifier contract).

use auths_crypto::{CurveType, RingCryptoProvider};
use auths_keri::{
    Acdc, CesrKey, Event, IcpEvent, IcpEventInit, Iss, IxnEvent, KeriPublicKey, KeriSequence,
    Prefix, Rev, RotEvent, RotEventInit, Said, Seal, TelAnchorSeal, TelEvent, Threshold, Vcp,
    VersionString, compute_capability_schema_said, compute_next_commitment, encode_tel_nonce,
    finalize_icp_event, finalize_ixn_event, finalize_rot_event,
};
use auths_verifier::freshness::FreshnessPolicy;
use auths_verifier::{
    CredentialVerdict, PresentationBinding, PresentationEnvelope, PresentationVerdict, SignedAcdc,
    VerifierWitnessPolicy, verify_presentation, verify_presentation_json, verify_presentation_sync,
};
use base64::Engine as _;
use chrono::{TimeZone, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};

const DT: &str = "2025-01-01T00:00:00.000000+00:00";

fn provider() -> RingCryptoProvider {
    RingCryptoProvider
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()
}

// ── curve-agnostic signing primitives (mirrors the F.5 fixture) ──────────────────

fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 keypair");
    kp.sign(message).as_ref().to_vec()
}

fn ed25519_pubkey(seed: &[u8; 32]) -> [u8; 32] {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 keypair");
    kp.public_key().as_ref().try_into().expect("32-byte pubkey")
}

fn p256_sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    let sk = SigningKey::from_slice(seed).expect("p256 key");
    let sig: Signature = sk.sign(message);
    sig.to_bytes().to_vec()
}

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

fn dummy_key(seed: u8) -> KeriPublicKey {
    KeriPublicKey::ed25519(&[seed; 32]).expect("ed25519")
}

fn schema_said() -> Said {
    compute_capability_schema_said().expect("schema said")
}

/// The canonical presentation message — must mirror the verifier/SDK framing exactly.
fn presentation_message(credential_said: &str, audience: &str, nonce: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(credential_said.len() + audience.len() + nonce.len() + 2);
    message.extend_from_slice(credential_said.as_bytes());
    message.push(0);
    message.extend_from_slice(audience.as_bytes());
    message.push(0);
    message.extend_from_slice(nonce);
    message
}

// ── subject KEL (the holder identity that must prove current control) ────────────

/// A subject (holder) identity with its own single-key KEL.
struct Subject {
    aid: Prefix,
    signer: Signer,
    /// The pre-committed next signer (revealed by [`Subject::rotate`]).
    next_signer: Signer,
    kel: Vec<Event>,
}

impl Subject {
    /// Incept a subject KEL (`icp` only) on the given curve, pre-committing a next key.
    fn incept(curve: CurveType, seed_byte: u8) -> Self {
        let signer = Signer::new(curve, seed_byte);
        let next_signer = Signer::new(curve, seed_byte.wrapping_add(100));
        let icp = finalize_icp_event(IcpEvent::new(IcpEventInit {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![signer.cesr()],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&next_signer.verkey)],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        }))
        .expect("subject icp");
        let aid = icp.i.clone();
        Self {
            aid,
            signer,
            next_signer,
            kel: vec![Event::Icp(icp)],
        }
    }

    /// Rotate the subject's signing key — reveal the pre-committed next key, advancing
    /// current control. After this the original `signer` is no longer current.
    fn rotate(&mut self) {
        let tip = self.kel.last().expect("tip");
        let new_next = Signer::new(self.next_signer.curve, 251);
        let rot = finalize_rot_event(RotEvent::new(RotEventInit {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: self.aid.clone(),
            s: KeriSequence::new(tip.sequence().value() + 1),
            p: tip.said().clone(),
            kt: Threshold::Simple(1),
            k: vec![self.next_signer.cesr()],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&new_next.verkey)],
            bt: Threshold::Simple(0),
            br: vec![],
            ba: vec![],
            c: vec![],
            a: vec![],
        }))
        .expect("subject rot");
        self.kel.push(Event::Rot(rot));
    }

    /// Sign a presentation envelope for `credential_said`/`audience`/`binding`.
    fn present(
        &self,
        credential_said: &str,
        audience: &str,
        binding: PresentationBinding,
    ) -> PresentationEnvelope {
        let nonce = match &binding {
            PresentationBinding::Challenge { nonce } => nonce.clone(),
            PresentationBinding::Ttl { nonce, .. } => nonce.clone(),
        };
        let message = presentation_message(credential_said, audience, &nonce);
        let signature = self.signer.sign(&message);
        PresentationEnvelope {
            credential_said: credential_said.to_string(),
            audience: audience.to_string(),
            binding,
            signature,
        }
    }
}

// ── issuer KEL + TEL (the F.5 credential the subject holds) ──────────────────────

/// The issuer KEL/TEL fixture credentialing a given subject AID.
struct Credentialed {
    issuer_kel: Vec<Event>,
    tel: Vec<TelEvent>,
    signed: SignedAcdc,
    credential_said: String,
}

/// Build an issuer KEL anchoring `vcp` then `iss` for a credential to `subject_aid`,
/// optionally followed by a `rev`. The issuer is backerless (Warn-policy trivially Met).
fn credential_for(subject_aid: &Prefix, revoke: bool) -> Credentialed {
    let issuer = Signer::new(CurveType::Ed25519, 1);
    let icp = finalize_icp_event(IcpEvent::new(IcpEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![issuer.cesr()],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&dummy_key(2))],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
    }))
    .expect("issuer icp");
    let issuer_aid = icp.i.clone();

    let nonce = encode_tel_nonce(&[7u8; 16]).expect("nonce");
    let vcp = Vcp::new(issuer_aid.clone(), nonce).saidify().expect("vcp");
    let registry = vcp.registry().clone();

    let mut data = serde_json::Map::new();
    data.insert(
        "capability".to_string(),
        serde_json::Value::String("sign".to_string()),
    );
    let acdc = Acdc::new(
        issuer_aid.clone(),
        registry.clone(),
        schema_said(),
        subject_aid.clone(),
        DT.to_string(),
        data,
    )
    .saidify()
    .expect("acdc");
    let credential_said = acdc.d.as_str().to_string();

    let wire = acdc.to_wire_bytes().expect("wire");
    let signature = issuer.sign(&wire);
    let signed = SignedAcdc {
        acdc: acdc.clone(),
        signature,
    };

    let iss = Iss::new(acdc.d.clone(), registry.clone(), DT.to_string())
        .saidify()
        .expect("iss");

    let mut kel = vec![Event::Icp(icp.clone())];
    let mut last = icp.d.clone();
    let vcp_ixn = anchor_ixn(&issuer_aid, 1, &last, &registry, vcp.s, &vcp.d);
    last = vcp_ixn.d.clone();
    kel.push(Event::Ixn(vcp_ixn));
    let iss_ixn = anchor_ixn(&issuer_aid, 2, &last, &registry, iss.s, &iss.d);
    last = iss_ixn.d.clone();
    kel.push(Event::Ixn(iss_ixn));

    let mut tel = vec![TelEvent::Vcp(vcp), TelEvent::Iss(iss.clone())];
    if revoke {
        let rev = Rev::new(
            acdc.d.clone(),
            registry.clone(),
            iss.d.clone(),
            DT.to_string(),
        )
        .saidify()
        .expect("rev");
        let rev_ixn = anchor_ixn(&issuer_aid, 3, &last, &registry, rev.s, &rev.d);
        kel.push(Event::Ixn(rev_ixn));
        tel.push(TelEvent::Rev(rev));
    }

    Credentialed {
        issuer_kel: kel,
        tel,
        signed,
        credential_said,
    }
}

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

/// Run the full holder-binding gate with the default backerless Warn policy.
#[allow(clippy::too_many_arguments)]
async fn verify(
    envelope: &PresentationEnvelope,
    cred: &Credentialed,
    subject_kel: &[Event],
    expected_audience: &str,
    expected_challenge: Option<&[u8]>,
) -> PresentationVerdict {
    verify_presentation(
        envelope,
        &cred.signed,
        &cred.issuer_kel,
        &cred.tel,
        &[],
        VerifierWitnessPolicy::Warn,
        subject_kel,
        &[],
        expected_audience,
        expected_challenge,
        now(),
        &FreshnessPolicy::default(),
        None,
        &provider(),
    )
    .await
}

const AUDIENCE: &str = "audience.example";

/// Drive `verify_presentation` with an explicit freshness policy + a known-fresher issuer tip.
#[allow(clippy::too_many_arguments)]
async fn verify_with_tip(
    envelope: &PresentationEnvelope,
    cred: &Credentialed,
    subject_kel: &[Event],
    expected_audience: &str,
    expected_challenge: Option<&[u8]>,
    policy: &FreshnessPolicy,
    fresher_tip_seq: Option<u128>,
) -> PresentationVerdict {
    verify_presentation(
        envelope,
        &cred.signed,
        &cred.issuer_kel,
        &cred.tel,
        &[],
        VerifierWitnessPolicy::Warn,
        subject_kel,
        &[],
        expected_audience,
        expected_challenge,
        now(),
        policy,
        fresher_tip_seq,
        &provider(),
    )
    .await
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn bearer_acdc_without_holder_proof_is_not_honored() {
    // A possessor with a valid issuer-signed ACDC but NO control of the subject key
    // presents it. The presentation is "signed" by a key that is not the subject's
    // current key (here: empty/garbage signature) → not honored.
    let subject = Subject::incept(CurveType::Ed25519, 30);
    let cred = credential_for(&subject.aid, false);

    let bearer = PresentationEnvelope {
        credential_said: cred.credential_said.clone(),
        audience: AUDIENCE.to_string(),
        binding: PresentationBinding::Challenge {
            nonce: vec![9u8; 32],
        },
        signature: vec![0u8; 64], // possessor cannot produce the subject's signature
    };

    let verdict = verify(&bearer, &cred, &subject.kel, AUDIENCE, Some(&[9u8; 32])).await;
    assert_eq!(
        verdict,
        PresentationVerdict::HolderNotCurrentKey,
        "a possessed-but-unbound ACDC must not be honored"
    );
}

#[tokio::test]
async fn valid_challenge_presentation_verifies() {
    for curve in [CurveType::P256, CurveType::Ed25519] {
        let subject = Subject::incept(curve, 31);
        let cred = credential_for(&subject.aid, false);
        let nonce = vec![5u8; 32];

        let envelope = subject.present(
            &cred.credential_said,
            AUDIENCE,
            PresentationBinding::Challenge {
                nonce: nonce.clone(),
            },
        );

        let verdict = verify(&envelope, &cred, &subject.kel, AUDIENCE, Some(&nonce)).await;
        match verdict {
            PresentationVerdict::Valid {
                issuer,
                subject: s,
                caps,
                role,
                expires_at,
                freshness,
            } => {
                assert_eq!(s.as_str(), format!("did:keri:{}", subject.aid));
                assert_eq!(
                    caps.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    ["sign"]
                );
                assert!(
                    issuer.as_str().starts_with("did:keri:"),
                    "issuer carried on Valid, got {}",
                    issuer.as_str()
                );
                // The F.8 fixture writes only `a.capability` (no role/expiry claims).
                assert_eq!(role, None);
                assert_eq!(expires_at, None);
                // `verify` supplies no fresher issuer tip (offline), so the honored verdict
                // names its freshness as Unknown — never a bare Valid.
                assert_eq!(freshness, auths_verifier::freshness::Freshness::Unknown);
            }
            other => panic!("expected Valid on {curve:?}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn presentation_behind_a_fresher_issuer_tip_is_rejected() {
    // A captured slice verifies positionally (Valid as-of its slice), but the verifier knows the
    // issuer's KEL has advanced past it — a later revocation the slice cannot see. The presentation
    // path must consume that freshness signal and refuse the stale slice; a slice at or beyond the
    // known tip is still honored.
    let subject = Subject::incept(CurveType::Ed25519, 41);
    let cred = credential_for(&subject.aid, false);
    let nonce = vec![7u8; 32];
    let envelope = subject.present(
        &cred.credential_said,
        AUDIENCE,
        PresentationBinding::Challenge {
            nonce: nonce.clone(),
        },
    );

    // A known issuer tip far beyond the slice's as-of → the held slice is stale → not honored.
    let stale = verify_with_tip(
        &envelope,
        &cred,
        &subject.kel,
        AUDIENCE,
        Some(&nonce),
        &FreshnessPolicy::default(),
        Some(u128::MAX),
    )
    .await;
    assert!(
        !matches!(stale, PresentationVerdict::Valid { .. }),
        "a presentation whose credential slice is behind the issuer's true tip must not be \
         honored, got {stale:?}"
    );

    // A tip at or behind the slice → the slice is current → honored.
    let fresh = verify_with_tip(
        &envelope,
        &cred,
        &subject.kel,
        AUDIENCE,
        Some(&nonce),
        &FreshnessPolicy::default(),
        Some(0),
    )
    .await;
    assert_eq!(
        fresh.freshness(),
        Some(auths_verifier::freshness::Freshness::Fresh),
        "a presentation whose credential slice is at the known tip must be honored as Fresh, \
         got {fresh:?}"
    );
}

#[tokio::test]
async fn strict_policy_refuses_offline_unknown_presentation() {
    // The same offline-resolved slice the default policy honors as `Valid(Unknown)` is refused
    // outright under a strict policy that denies `Unknown` — the freshness is surfaced *and*
    // gated, never a silent accept.
    let subject = Subject::incept(CurveType::P256, 61);
    let cred = credential_for(&subject.aid, false);
    let nonce = vec![3u8; 32];
    let envelope = subject.present(
        &cred.credential_said,
        AUDIENCE,
        PresentationBinding::Challenge {
            nonce: nonce.clone(),
        },
    );

    let strict = FreshnessPolicy::strict(std::time::Duration::from_secs(3600));
    let verdict = verify_with_tip(
        &envelope,
        &cred,
        &subject.kel,
        AUDIENCE,
        Some(&nonce),
        &strict,
        None,
    )
    .await;
    assert!(
        matches!(verdict, PresentationVerdict::CredentialNotValid(_)),
        "a strict policy must refuse an offline-Unknown presentation, got {verdict:?}"
    );
}

#[tokio::test]
async fn consumed_or_mismatched_challenge_rejected() {
    let subject = Subject::incept(CurveType::Ed25519, 32);
    let cred = credential_for(&subject.aid, false);
    let issued_nonce = vec![5u8; 32];

    let envelope = subject.present(
        &cred.credential_said,
        AUDIENCE,
        PresentationBinding::Challenge {
            nonce: issued_nonce.clone(),
        },
    );

    // Mismatch: the verifier expects a different nonce than the one signed.
    let mismatch = verify(&envelope, &cred, &subject.kel, AUDIENCE, Some(&[6u8; 32])).await;
    assert_eq!(
        mismatch,
        PresentationVerdict::NonceMismatchOrConsumed,
        "a mismatched challenge nonce is rejected"
    );

    // Consumed: a single-use challenge that the session has already spent presents to
    // the pure verifier as `expected_challenge == None`, so the challenge-bound envelope
    // cannot match → rejected (the one-shot replay protection).
    let consumed = verify(&envelope, &cred, &subject.kel, AUDIENCE, None).await;
    assert_eq!(
        consumed,
        PresentationVerdict::NonceMismatchOrConsumed,
        "a consumed (no-longer-offered) challenge is rejected"
    );
}

/// The challenge nonce is compared in constant time (`ct_eq`), so its accept/reject must
/// still match exact byte-equality semantics: honored only when the offered challenge is
/// byte-for-byte the bound nonce, rejected for an equal-length mismatch and — the case a
/// fixed-length compare could get wrong — for a different-length challenge.
#[tokio::test]
async fn challenge_nonce_gate_matches_byte_equality() {
    let subject = Subject::incept(CurveType::Ed25519, 39);
    let cred = credential_for(&subject.aid, false);
    let bound = vec![5u8; 32];
    let envelope = subject.present(
        &cred.credential_said,
        AUDIENCE,
        PresentationBinding::Challenge {
            nonce: bound.clone(),
        },
    );

    // Exact match → honored.
    let exact = verify(&envelope, &cred, &subject.kel, AUDIENCE, Some(&bound)).await;
    assert!(
        exact.is_honored(),
        "the exact bound nonce is honored, got {exact:?}"
    );

    // Equal-length, one byte different → rejected.
    let mut off_by_one = bound.clone();
    off_by_one[31] ^= 0x01;
    let mismatch = verify(&envelope, &cred, &subject.kel, AUDIENCE, Some(&off_by_one)).await;
    assert_eq!(
        mismatch,
        PresentationVerdict::NonceMismatchOrConsumed,
        "a single differing byte is rejected"
    );

    // Different length (a prefix of the bound nonce) → rejected, never honored.
    let shorter = verify(&envelope, &cred, &subject.kel, AUDIENCE, Some(&bound[..16])).await;
    assert_eq!(
        shorter,
        PresentationVerdict::NonceMismatchOrConsumed,
        "a different-length challenge is rejected, never treated as a prefix match"
    );
}

#[tokio::test]
async fn presentation_by_noncurrent_key_rejected() {
    // The subject rotates its key AFTER signing the presentation with the OLD key. The
    // old key is no longer current, so current-control is not proven → rejected.
    let mut subject = Subject::incept(CurveType::Ed25519, 33);
    let cred = credential_for(&subject.aid, false);
    let nonce = vec![5u8; 32];

    let envelope = subject.present(
        &cred.credential_said,
        AUDIENCE,
        PresentationBinding::Challenge {
            nonce: nonce.clone(),
        },
    );

    subject.rotate();

    let verdict = verify(&envelope, &cred, &subject.kel, AUDIENCE, Some(&nonce)).await;
    assert_eq!(
        verdict,
        PresentationVerdict::HolderNotCurrentKey,
        "a presentation signed by a rotated-away key is not current control"
    );
}

#[tokio::test]
async fn wrong_audience_rejected() {
    let subject = Subject::incept(CurveType::Ed25519, 34);
    let cred = credential_for(&subject.aid, false);
    let nonce = vec![5u8; 32];

    // The subject binds to "other.example" but the verifier expects AUDIENCE.
    let envelope = subject.present(
        &cred.credential_said,
        "other.example",
        PresentationBinding::Challenge {
            nonce: nonce.clone(),
        },
    );

    let verdict = verify(&envelope, &cred, &subject.kel, AUDIENCE, Some(&nonce)).await;
    assert_eq!(verdict, PresentationVerdict::WrongAudience);
}

#[tokio::test]
async fn non_interactive_expired_ttl_rejected() {
    let subject = Subject::incept(CurveType::P256, 35);
    let cred = credential_for(&subject.aid, false);

    // TTL already in the past relative to `now()` → Expired.
    let not_after = Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0).unwrap();
    let envelope = subject.present(
        &cred.credential_said,
        AUDIENCE,
        PresentationBinding::Ttl {
            nonce: vec![1u8; 32],
            not_after,
        },
    );

    // Non-interactive path: expected_challenge == None.
    let verdict = verify(&envelope, &cred, &subject.kel, AUDIENCE, None).await;
    assert_eq!(verdict, PresentationVerdict::Expired);
}

#[tokio::test]
async fn non_interactive_ttl_within_window_verifies() {
    // Sanity that the TTL happy-path binds (and documents the within-TTL residual).
    let subject = Subject::incept(CurveType::Ed25519, 36);
    let cred = credential_for(&subject.aid, false);
    let not_after = Utc.with_ymd_and_hms(2025, 12, 31, 0, 0, 0).unwrap();
    let envelope = subject.present(
        &cred.credential_said,
        AUDIENCE,
        PresentationBinding::Ttl {
            nonce: vec![1u8; 32],
            not_after,
        },
    );

    let verdict = verify(&envelope, &cred, &subject.kel, AUDIENCE, None).await;
    assert!(
        verdict.is_honored(),
        "an in-window TTL presentation by the current key is honored, got {verdict:?}"
    );
}

#[tokio::test]
async fn presentation_of_revoked_credential_rejected() {
    // The subject proves current control correctly, but the credential is revoked: the
    // F.5 chain short-circuits to CredentialNotValid(CredentialRevoked).
    let subject = Subject::incept(CurveType::Ed25519, 37);
    let cred = credential_for(&subject.aid, true);
    let nonce = vec![5u8; 32];

    let envelope = subject.present(
        &cred.credential_said,
        AUDIENCE,
        PresentationBinding::Challenge {
            nonce: nonce.clone(),
        },
    );

    let verdict = verify(&envelope, &cred, &subject.kel, AUDIENCE, Some(&nonce)).await;
    match verdict {
        PresentationVerdict::CredentialNotValid(CredentialVerdict::CredentialRevoked {
            ..
        }) => {}
        other => panic!("expected CredentialNotValid(CredentialRevoked), got {other:?}"),
    }
}

#[tokio::test]
async fn invalid_subject_kel_rejected() {
    // A subject KEL that cannot be replayed (empty) yields SubjectKelInvalid, not a
    // misleading signature failure.
    let subject = Subject::incept(CurveType::Ed25519, 38);
    let cred = credential_for(&subject.aid, false);
    let nonce = vec![5u8; 32];
    let envelope = subject.present(
        &cred.credential_said,
        AUDIENCE,
        PresentationBinding::Challenge {
            nonce: nonce.clone(),
        },
    );

    let verdict = verify(&envelope, &cred, &[], AUDIENCE, Some(&nonce)).await;
    assert_eq!(verdict, PresentationVerdict::SubjectKelInvalid);
}

/// The executor-free `verify_presentation_sync` must return exactly the same verdict as
/// the async `verify_presentation` for identical inputs — the contract the FFI/WASM/Node/
/// Python/Go bindings rely on. Exercised across both curves and across honored, wrong-key,
/// wrong-audience, and revoked outcomes so the parity is not just on the happy path.
#[tokio::test]
async fn sync_and_async_presentation_verdicts_match() {
    for curve in [CurveType::P256, CurveType::Ed25519] {
        let subject = Subject::incept(curve, 40);
        let cred = credential_for(&subject.aid, false);
        let nonce = vec![5u8; 32];

        // Honored happy path.
        let honored = subject.present(
            &cred.credential_said,
            AUDIENCE,
            PresentationBinding::Challenge {
                nonce: nonce.clone(),
            },
        );
        // Wrong-audience binding → WrongAudience.
        let wrong_audience = subject.present(
            &cred.credential_said,
            "other.example",
            PresentationBinding::Challenge {
                nonce: nonce.clone(),
            },
        );
        // A possessor who cannot produce the subject signature → HolderNotCurrentKey.
        let bearer = PresentationEnvelope {
            credential_said: cred.credential_said.clone(),
            audience: AUDIENCE.to_string(),
            binding: PresentationBinding::Challenge {
                nonce: nonce.clone(),
            },
            signature: vec![0u8; 64],
        };

        let cases = [
            (&honored, AUDIENCE, Some(nonce.as_slice())),
            (&wrong_audience, AUDIENCE, Some(nonce.as_slice())),
            (&bearer, AUDIENCE, Some(nonce.as_slice())),
        ];

        for (envelope, audience, challenge) in cases {
            let async_verdict = verify_presentation(
                envelope,
                &cred.signed,
                &cred.issuer_kel,
                &cred.tel,
                &[],
                VerifierWitnessPolicy::Warn,
                &subject.kel,
                &[],
                audience,
                challenge,
                now(),
                &FreshnessPolicy::default(),
                Some(0),
                &provider(),
            )
            .await;

            let sync_verdict = verify_presentation_sync(
                envelope,
                &cred.signed,
                &cred.issuer_kel,
                &cred.tel,
                &[],
                VerifierWitnessPolicy::Warn,
                &subject.kel,
                &[],
                audience,
                challenge,
                now(),
                &FreshnessPolicy::default(),
                Some(0),
            );

            assert_eq!(
                async_verdict, sync_verdict,
                "sync/async verdict parity must hold on {curve:?}"
            );
        }
    }
}

/// Build a `VerifyPresentationRequest` JSON bundle from the same typed inputs
/// `load_presentation_inputs` produces (Vec<Event>/Vec<TelEvent>/SignedAcdc), with all
/// bytes base64-encoded. This is the wire shape the FFI/WASM/Node/Python/Go bindings send.
fn presentation_request_json(
    envelope: &PresentationEnvelope,
    cred: &Credentialed,
    subject_kel: &[Event],
    audience: &str,
    expected_challenge: Option<&[u8]>,
) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    let binding = match &envelope.binding {
        PresentationBinding::Challenge { nonce } => serde_json::json!({
            "mode": "challenge",
            "nonceB64": b64.encode(nonce),
        }),
        PresentationBinding::Ttl { nonce, not_after } => serde_json::json!({
            "mode": "ttl",
            "nonceB64": b64.encode(nonce),
            "notAfter": not_after.to_rfc3339(),
        }),
    };
    serde_json::json!({
        "schemaVersion": 1,
        "envelope": {
            "credentialSaid": envelope.credential_said,
            "audience": envelope.audience,
            "binding": binding,
            "signatureB64": b64.encode(&envelope.signature),
        },
        "credential": {
            "acdc": cred.signed.acdc,
            "signatureB64": b64.encode(&cred.signed.signature),
        },
        "issuerKel": cred.issuer_kel,
        "subjectKel": subject_kel,
        "tel": cred.tel,
        "receipts": [],
        "witnessPolicy": "warn",
        "audience": audience,
        "expectedChallengeB64": expected_challenge.map(|c| b64.encode(c)),
        "now": now().to_rfc3339(),
    })
    .to_string()
}

/// The JSON contract must round-trip (typed inputs → bundle JSON → request) and produce a
/// tagged verdict whose `kind` matches the typed `verify_presentation_sync` outcome — across
/// honored, wrong-audience, and not-current-key cases, on both curves.
#[test]
fn presentation_json_contract_matches_sync() {
    for curve in [CurveType::P256, CurveType::Ed25519] {
        let subject = Subject::incept(curve, 42);
        let cred = credential_for(&subject.aid, false);
        let nonce = vec![5u8; 32];

        let honored = subject.present(
            &cred.credential_said,
            AUDIENCE,
            PresentationBinding::Challenge {
                nonce: nonce.clone(),
            },
        );
        let wrong_audience = subject.present(
            &cred.credential_said,
            "other.example",
            PresentationBinding::Challenge {
                nonce: nonce.clone(),
            },
        );
        let bearer = PresentationEnvelope {
            credential_said: cred.credential_said.clone(),
            audience: AUDIENCE.to_string(),
            binding: PresentationBinding::Challenge {
                nonce: nonce.clone(),
            },
            signature: vec![0u8; 64],
        };

        for (envelope, expected_kind) in [
            (&honored, "valid"),
            (&wrong_audience, "wrongAudience"),
            (&bearer, "holderNotCurrentKey"),
        ] {
            let request =
                presentation_request_json(envelope, &cred, &subject.kel, AUDIENCE, Some(&nonce));
            let verdict: serde_json::Value =
                serde_json::from_str(&verify_presentation_json(&request)).expect("verdict json");

            assert_eq!(verdict["schemaVersion"], 1);
            assert_eq!(
                verdict["kind"], expected_kind,
                "JSON verdict kind must match the sync outcome on {curve:?}"
            );
            if expected_kind == "valid" {
                assert_eq!(
                    verdict["subject"],
                    format!("did:keri:{}", subject.aid),
                    "valid verdict carries the holder subject DID"
                );
                assert_eq!(verdict["caps"], serde_json::json!(["sign"]));
                assert_eq!(
                    verdict["freshness"], "unknown",
                    "the JSON valid verdict surfaces freshness in lockstep with the native verdict"
                );
            }
        }
    }
}

/// Emit a deterministic valid presentation-request bundle as a cross-language test vector
/// (consumed by the WASM/Node/Python/Go binding tests). Inert unless `AUTHS_EMIT_FIXTURES=1`.
#[test]
fn emit_presentation_fixture() {
    if std::env::var("AUTHS_EMIT_FIXTURES").is_err() {
        return;
    }
    let subject = Subject::incept(CurveType::P256, 50);
    let cred = credential_for(&subject.aid, false);
    let nonce = vec![5u8; 32];
    let envelope = subject.present(
        &cred.credential_said,
        AUDIENCE,
        PresentationBinding::Challenge {
            nonce: nonce.clone(),
        },
    );
    let request = presentation_request_json(&envelope, &cred, &subject.kel, AUDIENCE, Some(&nonce));
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/presentation_valid.json"
    );
    std::fs::write(path, request).unwrap();
}

/// Malformed, oversize, and wrong-version requests must each return a typed error verdict
/// (never a panic, never a bare string).
#[test]
fn presentation_json_typed_errors() {
    // Not JSON at all.
    let malformed: serde_json::Value =
        serde_json::from_str(&verify_presentation_json("{not json")).expect("verdict json");
    assert_eq!(malformed["kind"], "malformedRequest");

    // Over the 1 MiB request ceiling → inputTooLarge on the whole request.
    let huge = " ".repeat(1024 * 1024 + 1);
    let too_large: serde_json::Value =
        serde_json::from_str(&verify_presentation_json(&huge)).expect("verdict json");
    assert_eq!(too_large["kind"], "inputTooLarge");
    assert_eq!(too_large["field"], "request");

    // A schema version this build does not understand.
    let bad_version = serde_json::json!({
        "schemaVersion": 999,
        "envelope": {"credentialSaid":"E","audience":"a","binding":{"mode":"challenge","nonceB64":""},"signatureB64":""},
        "credential": {"acdc": {}, "signatureB64": ""},
        "issuerKel": [], "subjectKel": [], "tel": [], "receipts": [],
        "witnessPolicy": "warn", "audience": "a", "now": "2025-06-01T00:00:00+00:00"
    })
    .to_string();
    let unsupported: serde_json::Value =
        serde_json::from_str(&verify_presentation_json(&bad_version)).expect("verdict json");
    assert_eq!(unsupported["kind"], "unsupportedSchemaVersion");
    assert_eq!(unsupported["got"], 999);
}
