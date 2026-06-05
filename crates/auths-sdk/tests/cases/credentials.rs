//! Epic F.4 — SDK credential issuance / revocation / listing / verification.
//!
//! Exercises the SDK-orchestrates `credentials::{issue,revoke,list,verify}` over a
//! real git-backed registry: issuing anchors an ACDC + `iss` TEL event to the issuer
//! KEL, revoking anchors a `rev`, and verify resolves the issuer KEL/TEL + the
//! lifecycle-anchor witness receipts to the witnessed tip before handing them to the
//! pure verifier and judging freshness.

use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::keri::credential_registry::find_registry;
use auths_id::keri::types::Prefix;
use auths_id::keri::{Event, Seal};
use auths_id::storage::receipts::{GitReceiptStorage, ReceiptStorage};
use auths_id::storage::registry::backend::RegistryBackend;
use auths_keri::witness::{Receipt, ReceiptTag, SignedReceipt, StoredReceipt};
use auths_keri::{
    KeriPublicKey, KeriSequence, Said, TelEvent, Threshold, VersionString,
    compute_capability_schema_said,
};
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::credentials::{
    CredentialError, CredentialVerdict, StoredCredential, VerifierWitnessPolicy, issue, list,
    revoke, verify,
};
use auths_sdk::domains::device::add_device;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::signing::types::GitSigningScope;
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::cases::helpers::build_test_context_with_provider;

const PASS: &str = "Test-passphrase1!";

fn setup_test_identity(registry_path: &Path) -> (KeyAlias, IsolatedKeychainHandle) {
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("issuer-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let ctx = build_test_context_with_provider(registry_path, Arc::new(keychain.clone()), None);
    let result = match initialize(
        IdentityConfig::Developer(config),
        &ctx,
        Arc::new(keychain.clone()),
        &signer,
        &provider,
        None,
    )
    .unwrap()
    {
        InitializeResult::Developer(r) => r,
        _ => unreachable!(),
    };
    (result.key_alias, keychain)
}

/// A git-backed issuer identity context for the issue/revoke/list/verify flows.
struct Harness {
    ctx: AuthsContext,
    issuer_alias: KeyAlias,
    issuer_prefix: Prefix,
    _tmp: tempfile::TempDir,
}

fn setup() -> Harness {
    let tmp = tempfile::tempdir().unwrap();
    let (issuer_alias, keychain) = setup_test_identity(tmp.path());
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx = build_test_context_with_provider(tmp.path(), Arc::new(keychain), Some(provider));
    let managed = ctx
        .identity_storage
        .load_identity()
        .expect("issuer identity");
    let issuer_prefix = Prefix::new_unchecked(
        managed
            .controller_did
            .as_str()
            .strip_prefix("did:keri:")
            .unwrap()
            .to_string(),
    );
    Harness {
        ctx,
        issuer_alias,
        issuer_prefix,
        _tmp: tmp,
    }
}

/// Delegate a device under the issuer so the issuee has a real KEL to credential.
fn make_issuee(h: &Harness, label: &str) -> String {
    add_device(
        &h.ctx,
        &h.issuer_alias,
        &KeyAlias::new_unchecked(label),
        CurveType::Ed25519,
    )
    .expect("delegate issuee device")
    .device_did
}

fn collect_kel(backend: &(dyn RegistryBackend + Send + Sync), prefix: &Prefix) -> Vec<Event> {
    let mut events = Vec::new();
    backend
        .visit_events(prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .expect("walk KEL");
    events
}

/// Load the stored credential envelope for a credential SAID.
fn load_stored(h: &Harness, credential_said: &str) -> StoredCredential {
    let blob = h
        .ctx
        .registry
        .load_credential(
            &h.issuer_prefix,
            &Said::new_unchecked(credential_said.to_string()),
        )
        .expect("load credential")
        .expect("credential blob present");
    StoredCredential::from_bytes(&blob).expect("parse stored credential")
}

// ── issue ─────────────────────────────────────────────────────────────────────

#[test]
fn issue_creates_anchored_acdc() {
    let h = setup();
    let issuee = make_issuee(&h, "deploy-bot");

    let issued = issue(
        &h.ctx,
        &h.issuer_alias,
        &issuee,
        &["sign".to_string()],
        Some("deployer"),
        None,
    )
    .expect("issue credential");

    assert!(issued.credential_said.starts_with('E'));
    assert_eq!(issued.issuee_did, issuee);

    // The credential SAID is anchored by an `iss`-bearing `ixn` seal in the issuer KEL
    // (the seal's `i` is the credential SAID — keripy's `SealEvent(i=tev.pre)`).
    let cred = issued.credential_said.clone();
    let kel = collect_kel(h.ctx.registry.as_ref(), &h.issuer_prefix);
    let anchored = kel.iter().any(|e| {
        e.is_interaction()
            && e.anchors().iter().any(|s| {
                matches!(
                    s,
                    Seal::KeyEvent { i, s: sn, .. }
                        if i.as_str() == cred && sn.value() == 0
                )
            })
    });
    assert!(
        anchored,
        "issuer KEL must anchor the iss for the credential"
    );

    // The stored envelope round-trips and its embedded ACDC verifies its own SAID.
    let stored = load_stored(&h, &issued.credential_said);
    assert!(stored.acdc.verify_said().is_ok());
    assert_eq!(stored.acdc.d.as_str(), issued.credential_said);
}

#[test]
fn issue_to_nonexistent_issuee_rejected() {
    let h = setup();
    let phantom = "did:keri:EPhantomIssueeAID00000000000000000000000000";

    let err = issue(
        &h.ctx,
        &h.issuer_alias,
        phantom,
        &["sign".to_string()],
        None,
        None,
    )
    .expect_err("issuing to an issuee with no KEL must hard-fail");
    assert!(
        matches!(err, CredentialError::IssueeNotFound { .. }),
        "expected IssueeNotFound, got {err:?}"
    );
}

// ── revoke ─────────────────────────────────────────────────────────────────────

#[test]
fn revoke_marks_credential_revoked_in_tel() {
    let h = setup();
    let issuee = make_issuee(&h, "rev-bot");
    let issued = issue(
        &h.ctx,
        &h.issuer_alias,
        &issuee,
        &["sign".to_string()],
        None,
        None,
    )
    .expect("issue");

    revoke(&h.ctx, &h.issuer_alias, &issued.credential_said).expect("revoke");

    // The credential drops out of the live set.
    let live = list(&h.ctx, &h.issuer_alias).expect("list");
    let entry = live
        .iter()
        .find(|c| c.credential_said == issued.credential_said)
        .expect("credential still present in the full set");
    assert!(entry.revoked, "revoked credential must be flagged revoked");
}

#[test]
fn revoke_already_revoked_idempotent() {
    let h = setup();
    let issuee = make_issuee(&h, "idem-bot");
    let issued = issue(
        &h.ctx,
        &h.issuer_alias,
        &issuee,
        &["sign".to_string()],
        None,
        None,
    )
    .expect("issue");

    revoke(&h.ctx, &h.issuer_alias, &issued.credential_said).expect("first revoke");
    revoke(&h.ctx, &h.issuer_alias, &issued.credential_said)
        .expect("re-revoking is idempotent (Ok)");

    // Exactly one rev anchored — the second revoke was a no-op.
    let registry = find_registry(h.ctx.registry.as_ref(), &h.issuer_prefix)
        .unwrap()
        .expect("registry exists");
    let cred = Said::new_unchecked(issued.credential_said.clone());
    let tel = auths_id::keri::credential_registry::read_credential_tel(
        h.ctx.registry.as_ref(),
        &h.issuer_prefix,
        &registry,
        &cred,
    )
    .unwrap();
    let rev_count = tel
        .iter()
        .filter(|e| matches!(e, TelEvent::Rev(rev) if rev.i == cred))
        .count();
    assert_eq!(
        rev_count, 1,
        "idempotent revoke must not author a second rev"
    );
}

// ── list ───────────────────────────────────────────────────────────────────────

#[test]
fn credential_list_shows_live() {
    let h = setup();
    let issuee_a = make_issuee(&h, "issuee-a");
    let issuee_b = make_issuee(&h, "issuee-b");

    let a = issue(
        &h.ctx,
        &h.issuer_alias,
        &issuee_a,
        &["sign".to_string()],
        None,
        None,
    )
    .expect("issue a");
    let b = issue(
        &h.ctx,
        &h.issuer_alias,
        &issuee_b,
        &["read".to_string()],
        None,
        None,
    )
    .expect("issue b");

    // Both live initially.
    let live: Vec<_> = list(&h.ctx, &h.issuer_alias)
        .expect("list")
        .into_iter()
        .filter(|c| !c.revoked)
        .collect();
    assert_eq!(live.len(), 2, "two live credentials");

    // Revoke one → only the other remains live.
    revoke(&h.ctx, &h.issuer_alias, &a.credential_said).expect("revoke a");
    let live: Vec<_> = list(&h.ctx, &h.issuer_alias)
        .expect("list")
        .into_iter()
        .filter(|c| !c.revoked)
        .collect();
    assert_eq!(live.len(), 1, "one live credential after revoke");
    assert_eq!(live[0].credential_said, b.credential_said);
}

// ── verify (resolution + freshness) ─────────────────────────────────────────────

#[tokio::test]
async fn verify_collects_lifecycle_anchor_receipts() {
    let h = setup();
    let issuee = make_issuee(&h, "verify-bot");
    let issued = issue(
        &h.ctx,
        &h.issuer_alias,
        &issuee,
        &["sign".to_string()],
        None,
        None,
    )
    .expect("issue");
    let stored = load_stored(&h, &issued.credential_said);

    // Default Warn policy: a backerless issuer needs no receipts, and the credential
    // verifies end-to-end through the resolution layer to the witnessed tip.
    let now = chrono::Utc::now();
    let verdict = verify(&h.ctx, &stored, VerifierWitnessPolicy::Warn, now)
        .await
        .expect("verify");
    assert!(
        verdict.is_valid(),
        "freshly issued credential must verify, got {verdict:?}"
    );

    // The verdict is reported as-of the resolved KEL tip (the iss anchor position).
    match verdict {
        CredentialVerdict::Resolved { as_of, .. } => {
            let kel = collect_kel(h.ctx.registry.as_ref(), &h.issuer_prefix);
            assert_eq!(as_of.seq, kel.last().unwrap().sequence().value());
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_stale_tip_is_unresolvable() {
    let h = setup();
    let issuee = make_issuee(&h, "stale-bot");
    let issued = issue(
        &h.ctx,
        &h.issuer_alias,
        &issuee,
        &["sign".to_string()],
        None,
        None,
    )
    .expect("issue");
    let mut stored = load_stored(&h, &issued.credential_said);

    // Forge the issuer's key-state to declare a witness backer it has no receipts for:
    // under RequireWitnesses the witnessed tip is unreachable → StaleOrUnresolvable.
    let witness = witness_aid(99);
    let mut state = h.ctx.registry.get_key_state(&h.issuer_prefix).unwrap();
    state.backers = vec![witness];
    state.backer_threshold = Threshold::Simple(1);
    h.ctx
        .registry
        .write_key_state(&h.issuer_prefix, &state)
        .unwrap();

    // (stored is unchanged; the issuer signature still matches its ACDC.)
    let _ = &mut stored;

    let now = chrono::Utc::now();
    let verdict = verify(
        &h.ctx,
        &stored,
        VerifierWitnessPolicy::RequireWitnesses,
        now,
    )
    .await
    .expect("verify");
    assert!(
        matches!(verdict, CredentialVerdict::StaleOrUnresolvable { .. }),
        "no reachable witnessed tip must fail closed, got {verdict:?}"
    );
}

#[tokio::test]
async fn verify_require_witnesses_fails_closed_on_under_quorum_iss() {
    // A backerless issuer's anchors are trivially Met, so to exercise the quorum gate
    // through the SDK resolution layer we persist a *witnessed* issuer KEL+TEL fixture
    // (bt=2) into a real git registry, seed full quorum on the vcp but only ONE receipt
    // on the iss, and confirm the SDK verify routes the receipts to F.5 and surfaces a
    // non-Valid WitnessQuorumNotMet end-to-end.
    let tmp = tempfile::tempdir().unwrap();
    let ctx =
        build_test_context_with_provider(tmp.path(), Arc::new(IsolatedKeychainHandle::new()), None);
    ctx.registry.init_if_needed().expect("init registry");

    let w1 = TestWitness::new(40);
    let w2 = TestWitness::new(41);
    let fixture = WitnessedFixture::build(&[w1.aid.clone(), w2.aid.clone()], 2);
    fixture.persist(&ctx);

    // vcp: full 2-of-2 quorum; iss: only one receipt → 1-of-2, under quorum.
    let storage = GitReceiptStorage::new(tmp.path());
    store_receipts(
        &storage,
        &fixture.issuer_prefix,
        &fixture.registry,
        &[
            w1.receipt(&fixture.issuer_prefix, &fixture.registry, 0),
            w2.receipt(&fixture.issuer_prefix, &fixture.registry, 0),
        ],
    );
    store_receipts(
        &storage,
        &fixture.issuer_prefix,
        &fixture.iss_said,
        &[w1.receipt(&fixture.issuer_prefix, &fixture.iss_said, 0)],
    );

    let now = chrono::Utc::now();
    let verdict = verify(
        &ctx,
        &fixture.stored,
        VerifierWitnessPolicy::RequireWitnesses,
        now,
    )
    .await
    .expect("verify");

    assert!(
        !verdict.is_valid(),
        "under-quorum iss must not be Valid under RequireWitnesses, got {verdict:?}"
    );
    match verdict {
        CredentialVerdict::Resolved { verdict, .. } => assert!(
            matches!(
                verdict,
                auths_verifier::CredentialVerdict::WitnessQuorumNotMet {
                    event: auths_verifier::LifecycleEvent::Iss,
                    ..
                }
            ),
            "expected WitnessQuorumNotMet(iss), got {verdict:?}"
        ),
        other => panic!("expected a Resolved WitnessQuorumNotMet, got {other:?}"),
    }
}

// ── witness receipt helpers ──────────────────────────────────────────────────────

fn ed25519_pubkey(seed: &[u8; 32]) -> [u8; 32] {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 keypair");
    kp.public_key().as_ref().try_into().expect("32-byte pubkey")
}

fn witness_aid(seed_byte: u8) -> Prefix {
    let verkey = KeriPublicKey::ed25519(&ed25519_pubkey(&[seed_byte; 32])).expect("verkey");
    Prefix::new_unchecked(verkey.to_qb64().expect("qb64"))
}

/// A designated witness whose AID is its own CESR verkey (matches the F.5 fixtures).
struct TestWitness {
    seed: [u8; 32],
    aid: Prefix,
}

impl TestWitness {
    fn new(seed_byte: u8) -> Self {
        let seed = [seed_byte; 32];
        Self {
            aid: witness_aid(seed_byte),
            seed,
        }
    }

    fn receipt(&self, controller: &Prefix, said: &Said, seq: u128) -> StoredReceipt {
        let receipt = Receipt {
            v: VersionString::placeholder(),
            t: ReceiptTag,
            d: said.clone(),
            i: controller.clone(),
            s: KeriSequence::new(seq),
        };
        let payload = serde_json::to_vec(&receipt).expect("receipt json");
        let kp = Ed25519KeyPair::from_seed_unchecked(&self.seed).expect("kp");
        let signature = kp.sign(&payload).as_ref().to_vec();
        StoredReceipt {
            signed: SignedReceipt { receipt, signature },
            witness: self.aid.clone(),
        }
    }
}

/// Persist receipts for a single event SAID under the issuer's receipt refs.
fn store_receipts(
    storage: &GitReceiptStorage,
    issuer: &Prefix,
    event_said: &Said,
    receipts: &[StoredReceipt],
) {
    use auths_id::keri::EventReceipts;
    let event_receipts = EventReceipts::new(event_said.as_str(), receipts.to_vec());
    storage
        .store_receipts(issuer, &event_receipts, chrono::Utc::now())
        .expect("store receipts");
}

// ── witnessed KEL+TEL fixture (for the quorum-gate integration test) ─────────────

/// A complete witnessed issuer KEL + TEL + signed credential, persistable into a
/// real git registry.
///
/// Mirrors the F.5 verifier fixture but lands the events in storage so the SDK
/// resolution layer reads them back. The issuer's `icp` declares the given witness
/// backers (`bt`); the `vcp`/`iss` anchors land at KEL seq 1/2 where that backer set
/// is in force. `validate_kel` (structural-only) and `verify_event_crypto` (icp/ixn
/// are structural-only) accept the hand-built KEL; only the ACDC issuer signature
/// (which we sign for real with the icp's signing key) needs to verify.
struct WitnessedFixture {
    issuer_prefix: Prefix,
    issuer_kel: Vec<Event>,
    vcp: TelEvent,
    iss: TelEvent,
    registry: Said,
    iss_said: Said,
    credential_said: Said,
    stored: StoredCredential,
}

impl WitnessedFixture {
    fn build(witnesses: &[Prefix], threshold: u64) -> Self {
        use auths_keri::{
            CesrKey, IcpEvent, IcpEventInit, Iss, IxnEvent, Seal as KeriSeal, TelAnchorSeal, Vcp,
            compute_next_commitment, encode_tel_nonce, finalize_icp_event, finalize_ixn_event,
        };

        let issuer_seed = [1u8; 32];
        let issuer_verkey =
            KeriPublicKey::ed25519(&ed25519_pubkey(&issuer_seed)).expect("issuer verkey");
        let issuer_cesr = CesrKey::new_unchecked(issuer_verkey.to_qb64().expect("qb64"));
        let next_key = KeriPublicKey::ed25519(&[2u8; 32]).expect("next key");

        let icp = finalize_icp_event(IcpEvent::new(IcpEventInit {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![issuer_cesr],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&next_key)],
            bt: Threshold::Simple(threshold),
            b: witnesses.to_vec(),
            c: vec![],
            a: vec![],
        }))
        .expect("issuer icp");
        let issuer_prefix = icp.i.clone();

        let nonce = encode_tel_nonce(&[7u8; 16]).expect("nonce");
        let vcp = Vcp::new(issuer_prefix.clone(), nonce)
            .saidify()
            .expect("vcp");
        let registry = vcp.registry().clone();

        let schema = compute_capability_schema_said().expect("schema");
        let mut data = serde_json::Map::new();
        data.insert(
            "capability".to_string(),
            serde_json::Value::String("sign".to_string()),
        );
        let acdc = auths_keri::Acdc::new(
            issuer_prefix.clone(),
            registry.clone(),
            schema,
            Prefix::new_unchecked("EHolder000000000000000000000000000000000000".to_string()),
            "2025-01-01T00:00:00.000000+00:00".to_string(),
            data,
        )
        .saidify()
        .expect("acdc");
        let credential_said = acdc.d.clone();

        let wire = acdc.to_wire_bytes().expect("wire");
        let kp = Ed25519KeyPair::from_seed_unchecked(&issuer_seed).expect("kp");
        let signature = kp.sign(&wire).as_ref().to_vec();

        let iss = Iss::new(
            credential_said.clone(),
            registry.clone(),
            "2025-01-01T00:00:00.000000+00:00".to_string(),
        )
        .saidify()
        .expect("iss");
        let iss_said = iss.d.clone();

        let anchor =
            |seq: u128, prior: &Said, tel_seq: KeriSequence, tel_said: &Said| -> IxnEvent {
                let seal = TelAnchorSeal::for_event(
                    Prefix::new_unchecked(registry.as_str().to_string()),
                    tel_seq,
                    tel_said.clone(),
                );
                finalize_ixn_event(IxnEvent {
                    v: VersionString::placeholder(),
                    d: Said::default(),
                    i: issuer_prefix.clone(),
                    s: KeriSequence::new(seq),
                    p: prior.clone(),
                    a: vec![KeriSeal::KeyEvent {
                        i: seal.i,
                        s: seal.s,
                        d: seal.d,
                    }],
                })
                .expect("anchor ixn")
            };

        let vcp_ixn = anchor(1, &icp.d, vcp.s, &vcp.d);
        let iss_ixn = anchor(2, &vcp_ixn.d, iss.s, &iss.d);

        let issuer_kel = vec![Event::Icp(icp), Event::Ixn(vcp_ixn), Event::Ixn(iss_ixn)];

        WitnessedFixture {
            issuer_prefix,
            issuer_kel,
            vcp: TelEvent::Vcp(vcp),
            iss: TelEvent::Iss(iss),
            registry,
            iss_said,
            credential_said,
            stored: StoredCredential { acdc, signature },
        }
    }

    /// Persist the KEL, TEL, and credential blob into the registry backend.
    fn persist(&self, ctx: &AuthsContext) {
        for event in &self.issuer_kel {
            ctx.registry
                .append_event(&self.issuer_prefix, event)
                .expect("append KEL event");
        }
        let vcp_bytes = auths_keri::tel_to_wire_bytes(match &self.vcp {
            TelEvent::Vcp(v) => v,
            _ => unreachable!(),
        })
        .expect("vcp bytes");
        ctx.registry
            .append_tel_event(
                &self.issuer_prefix,
                &self.registry,
                &self.registry,
                0,
                &vcp_bytes,
            )
            .expect("append vcp");
        let iss_bytes = auths_keri::tel_to_wire_bytes(match &self.iss {
            TelEvent::Iss(i) => i,
            _ => unreachable!(),
        })
        .expect("iss bytes");
        ctx.registry
            .append_tel_event(
                &self.issuer_prefix,
                &self.registry,
                &self.credential_said,
                0,
                &iss_bytes,
            )
            .expect("append iss");
        let blob = self.stored.to_bytes().expect("blob");
        ctx.registry
            .store_credential(&self.issuer_prefix, &self.credential_said, &blob)
            .expect("store credential");
    }
}
