//! SDK-level commit-trust e2e for `workflows::commit_trust::verify_commit_local`.
//!
//! `commit_kel.rs` in `auths-verifier` exercises the verdict primitive by passing the
//! device + root KELs inline. This test drives one layer up: it resolves those KELs
//! from an **in-memory `RegistryBackend`** (the mock backend) the way a real relying
//! party does — parse the commit's `Auths-Id`/`Auths-Device` trailers, replay the
//! device + delegating-root KELs from the registry, and decide the verdict.
//!
//! It mirrors the delegated-device KEL fixture from `commit_kel.rs`, but mints a fresh
//! commit that actually carries the trailers and is validly signed: the device's
//! signing seed derives both the SSH commit signature and the device AID's current
//! key, so the signer key matches the KEL by construction. A pinned root yields
//! `CommitVerdict::Valid`; the same commit with nothing pinned yields
//! `CommitVerdict::RootNotPinned`.

use auths_core::crypto::ssh::SecureSeed;
use auths_crypto::{CurveType, RingCryptoProvider};
use auths_id::keri::{Event, Prefix};
use auths_id::ports::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use auths_keri::{
    CesrKey, DipEvent, DipEventInit, IcpEvent, IcpEventInit, IxnEvent, KeriPublicKey, KeriSequence,
    Said, Seal, SourceSeal, Threshold, VersionString, compute_next_commitment, finalize_dip_event,
    finalize_icp_event, finalize_ixn_event,
};
use auths_sdk::domains::signing::service as signing;
use auths_sdk::workflows::commit_trust::{CommitDecision, PolicyOutcome, verify_commit_local};
use auths_verifier::CommitVerdict;
use auths_verifier::freshness::{Freshness, FreshnessEvidence, FreshnessPolicy};
use ssh_key::private::Ed25519Keypair;

/// The git empty-tree hash — a placeholder tree the verdict path never dereferences.
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf899d69f628aca02";
/// Fixed device signing seed — derives both the commit signature and the device key.
const DEVICE_SEED: [u8; 32] = [7u8; 32];

/// CESR-encode a KERI public key for an event's key list.
fn cesr(pk: &KeriPublicKey) -> CesrKey {
    CesrKey::new_unchecked(pk.to_qb64().expect("qb64"))
}

/// A length-valid Ed25519 key for the non-signing roles (root current/next, device next).
fn dummy_key(seed: u8) -> KeriPublicKey {
    KeriPublicKey::ed25519(&[seed; 32]).expect("ed25519")
}

/// The device seed plus the KERI key its SSH signature will carry — derived via the
/// same `Ed25519Keypair::from_seed` the signer uses, so the keys match by construction.
fn device_keypair() -> (SecureSeed, KeriPublicKey) {
    let seed = SecureSeed::new(DEVICE_SEED);
    let kp = Ed25519Keypair::from_seed(seed.as_bytes());
    let device_key = KeriPublicKey::ed25519(&kp.public.0).expect("device ed25519 key");
    (seed, device_key)
}

/// A delegated-device KEL fixture: a root `icp`, the root `ixn` anchoring the device
/// `dip`, and the device `dip` whose current key is `device_key`.
struct Fixture {
    root_kel: Vec<Event>,
    device_kel: Vec<Event>,
    root_prefix: Prefix,
    device_prefix: Prefix,
    root_did: String,
    device_did: String,
}

/// Build the delegated-device fixture (mirrors `commit_kel.rs::build` with anchoring on).
fn build_delegated(device_key: &KeriPublicKey) -> Fixture {
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
    dip.source_seal = Some(SourceSeal {
        s: KeriSequence::new(1),
        d: ixn.d.clone(),
    });

    Fixture {
        root_did: format!("did:keri:{root_prefix}"),
        device_did: format!("did:keri:{device_prefix}"),
        root_kel: vec![Event::Icp(root_icp), Event::Ixn(ixn)],
        device_kel: vec![Event::Dip(dip)],
        root_prefix,
        device_prefix,
    }
}

/// Mint a raw git commit object that carries the `Auths-Id`/`Auths-Device` trailers and
/// is SSH-signed (namespace `git`) over the gpgsig-stripped payload, exactly as the
/// verifier reconstructs it.
fn signed_commit(seed: &SecureSeed, root_did: &str, device_did: &str) -> Vec<u8> {
    let headers = format!(
        "tree {EMPTY_TREE}\n\
         author Test User <test@auths.local> 1700000000 +0000\n\
         committer Test User <test@auths.local> 1700000000 +0000"
    );
    let message = format!("test commit\n\nAuths-Id: {root_did}\nAuths-Device: {device_did}\n");
    // What git signs: the commit object with the gpgsig header removed.
    let payload = format!("{headers}\n\n{message}");
    let pem = signing::sign_with_seed(seed, payload.as_bytes(), "git", CurveType::Ed25519)
        .expect("sign commit payload");

    // Fold the PEM into a `gpgsig` header: first line inline, the rest space-indented.
    let mut lines = pem.lines();
    let first = lines.next().expect("pem first line");
    let mut gpgsig = format!("gpgsig {first}\n");
    for line in lines {
        gpgsig.push(' ');
        gpgsig.push_str(line);
        gpgsig.push('\n');
    }
    format!("{headers}\n{gpgsig}\n{message}").into_bytes()
}

/// Build the fixture, populate an in-memory registry with both KELs, and mint the commit.
fn setup() -> (Fixture, FakeRegistryBackend, Vec<u8>) {
    let (seed, device_key) = device_keypair();
    let f = build_delegated(&device_key);

    let registry = FakeRegistryBackend::new();
    for event in &f.root_kel {
        registry
            .append_event(&f.root_prefix, event)
            .expect("append root event");
    }
    for event in &f.device_kel {
        registry
            .append_event(&f.device_prefix, event)
            .expect("append device event");
    }

    let commit = signed_commit(&seed, &f.root_did, &f.device_did);
    (f, registry, commit)
}

#[tokio::test]
async fn pinned_root_yields_valid() {
    let (f, registry, commit) = setup();

    let verdict = verify_commit_local(
        &registry,
        std::slice::from_ref(&f.root_did),
        &commit,
        &RingCryptoProvider,
    )
    .await
    .expect("trust resolution succeeds");

    match verdict {
        CommitVerdict::Valid { root_did, .. } => assert_eq!(root_did, f.root_did),
        other => panic!("expected Valid for a pinned delegating root, got {other:?}"),
    }
}

#[tokio::test]
async fn commit_verdict_names_freshness_and_authorization_consumes_it() {
    // The wired commit-trust path must surface the freshness it carries (never drop it) AND
    // the authorization decision must *consume* it: a verdict graded Stale is refused even when
    // the root anchored no org policy. This locks the freshness gate against a regression to a
    // bare `is_valid()` check.
    let (f, registry, commit) = setup();

    let verdict = verify_commit_local(
        &registry,
        std::slice::from_ref(&f.root_did),
        &commit,
        &RingCryptoProvider,
    )
    .await
    .expect("trust resolution succeeds");

    // Surfaced, not dropped: an offline commit verify names its freshness as Unknown.
    assert!(matches!(verdict, CommitVerdict::Valid { .. }));
    assert_eq!(
        verdict.freshness(),
        Freshness::Unknown,
        "an offline commit verdict must name Unknown, never a bare Valid"
    );

    // Consumed: re-grade the *same* valid verdict against a known-fresher signer tip → Stale,
    // and the authorization decision refuses it despite there being no org policy to fail.
    let stale = verdict.clone().with_freshness(
        &FreshnessPolicy::default(),
        FreshnessEvidence::FresherTip {
            latest_seq: u128::MAX,
            slice_as_of: 0,
        },
    );
    assert_eq!(stale.freshness(), Freshness::Stale);
    let denied = CommitDecision {
        verdict: stale,
        policy: PolicyOutcome::NoPolicy,
    };
    assert!(
        !denied.is_authorized(),
        "a Stale commit verdict must not authorize, even with no org policy"
    );

    // The offline-Unknown verdict clears the default policy (which tolerates Unknown).
    let allowed = CommitDecision {
        verdict,
        policy: PolicyOutcome::NoPolicy,
    };
    assert!(
        allowed.is_authorized(),
        "an offline-Unknown verdict is authorized under the default policy + no org policy"
    );
}

#[tokio::test]
async fn unpinned_root_yields_root_not_pinned() {
    let (_f, registry, commit) = setup();

    // Same commit + same resolvable KELs, but nothing is pinned in `.auths/roots`.
    let verdict = verify_commit_local(&registry, &[], &commit, &RingCryptoProvider)
        .await
        .expect("trust resolution succeeds");

    assert!(
        matches!(verdict, CommitVerdict::RootNotPinned(_)),
        "an unpinned root must not be trusted, got {verdict:?}"
    );
}
