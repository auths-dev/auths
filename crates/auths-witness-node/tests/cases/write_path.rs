//! The KEL write path, end to end: a member publishes signed key events to
//! the witness, the witness validates + receipts + stores them under a
//! per-prefix ref, and a stranger resolves the member offline from the served
//! registry — "serve what you witness" proven over the real wire shapes.

use std::path::Path;
use std::sync::Arc;

use auths_core::witness::wire::encode_submit_body;
use auths_core::witness::{
    WitnessServerConfig, WitnessServerState, witness_router, witness_signer_from_seed_hex,
};
use auths_keri::{
    CesrKey, Event, IcpEvent, IndexedSignature, KeriPublicKey, KeriSequence, Prefix, RotEvent,
    Said, Threshold, VersionString, compute_next_commitment, finalize_icp_event,
    finalize_rot_event, serialize_attachment, serialize_for_signing,
};
use auths_sdk::storage::{PerPrefixKelStore, kel_ref};
use auths_witness_node::kel_sink::KelStoreSink;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

/// A member controller with three generations of keys: current, next
/// (pre-committed), and the one after (committed by the rotation).
struct Controller {
    keys: [SigningKey; 3],
}

impl Controller {
    fn new(seed_base: u8) -> Self {
        let mk = |b: u8| SigningKey::from_bytes(&[b; 32]);
        Self {
            keys: [mk(seed_base), mk(seed_base + 1), mk(seed_base + 2)],
        }
    }

    fn verkey(&self, idx: usize) -> KeriPublicKey {
        KeriPublicKey::ed25519(self.keys[idx].verifying_key().as_bytes()).unwrap()
    }

    fn cesr_key(&self, idx: usize) -> CesrKey {
        CesrKey::new_unchecked(self.verkey(idx).to_qb64().unwrap())
    }

    /// A finalized, signed inception: `k=[K0]`, `n=[H(K1)]`.
    fn signed_icp(&self) -> (IcpEvent, Vec<u8>) {
        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![self.cesr_key(0)],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&self.verkey(1))],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };
        let finalized = finalize_icp_event(icp).unwrap();
        let attachment = self.sign_event(&Event::Icp(finalized.clone()), 0);
        (finalized, attachment)
    }

    /// A finalized, signed rotation at seq 1: reveals `K1`, commits `H(K2)`.
    /// The `next_commitment` override lets a test author a *conflicting*
    /// rotation at the same sequence (same chain, different content).
    fn signed_rot(&self, prior: &IcpEvent, next_idx: usize) -> (RotEvent, Vec<u8>) {
        let rot = RotEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: prior.i.clone(),
            s: KeriSequence::new(1),
            p: prior.d.clone(),
            kt: Threshold::Simple(1),
            k: vec![self.cesr_key(1)],
            nt: Threshold::Simple(1),
            n: vec![compute_next_commitment(&self.verkey(next_idx))],
            bt: Threshold::Simple(0),
            br: vec![],
            ba: vec![],
            c: vec![],
            a: vec![],
        };
        let finalized = finalize_rot_event(rot).unwrap();
        let attachment = self.sign_event(&Event::Rot(finalized.clone()), 1);
        (finalized, attachment)
    }

    fn sign_event(&self, event: &Event, key_idx: usize) -> Vec<u8> {
        let canonical = serialize_for_signing(event).unwrap();
        let sig = self.keys[key_idx].sign(&canonical);
        serialize_attachment(&[IndexedSignature {
            index: 0,
            prior_index: None,
            sig: sig.to_bytes().to_vec(),
        }])
        .unwrap()
    }
}

/// A witness app whose `kel` role bridges into the per-prefix store at
/// `registry` — the same wiring the binary's `build_kel_router` performs.
fn witness_app(registry: &Path, data_dir: &Path) -> Router {
    auths_witness_node::sync::ensure_registry(registry).unwrap();
    let signer =
        witness_signer_from_seed_hex(auths_crypto::CurveType::Ed25519, &"ab".repeat(32)).unwrap();
    let sink = KelStoreSink::new(PerPrefixKelStore::open(registry));
    let config = WitnessServerConfig::from_signer(data_dir.join("receipts.db"), signer)
        .unwrap()
        .with_kel_sink(Arc::new(sink));
    witness_router(WitnessServerState::new(config).unwrap())
}

async fn submit(app: &Router, prefix: &Prefix, event: &Event, attachment: &[u8]) -> StatusCode {
    let event_json = serialize_for_signing(event).unwrap();
    let body = encode_submit_body(&event_json, attachment).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/witness/{}/event", prefix.as_str()))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    response.status()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipted_events_are_stored_served_and_resolvable_offline() {
    let registry = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let app = witness_app(registry.path(), data.path());

    let member = Controller::new(10);
    let (icp, icp_att) = member.signed_icp();
    let prefix = icp.i.clone();

    assert_eq!(
        submit(&app, &prefix, &Event::Icp(icp.clone()), &icp_att).await,
        StatusCode::OK,
        "inception must be receipted"
    );
    let (rot, rot_att) = member.signed_rot(&icp, 2);
    assert_eq!(
        submit(&app, &prefix, &Event::Rot(rot.clone()), &rot_att).await,
        StatusCode::OK,
        "rotation must be receipted"
    );

    // The witness now SERVES the 2-event KEL it receipted: the per-prefix ref
    // resolves locally to the post-rotation key state.
    let store = PerPrefixKelStore::open(registry.path());
    let state = store.get_key_state(&prefix).unwrap();
    assert_eq!(state.sequence, 1);
    assert_eq!(state.current_keys, vec![member.cesr_key(1)]);

    // A stranger fetches exactly one member's ref over git smart-HTTP and
    // resolves the current keys offline — no trust in the transport.
    let serve = auths_witness_node::serve_registry::registry_router(registry.path());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, serve).await.unwrap();
    });

    let stranger = TempDir::new().unwrap();
    git(stranger.path(), &["init", "-q"]);
    let ref_name = kel_ref(&prefix).unwrap();
    git(
        stranger.path(),
        &[
            "fetch",
            "-q",
            &format!("http://{addr}"),
            &format!("+{ref_name}:{ref_name}"),
        ],
    );
    let offline = PerPrefixKelStore::open(stranger.path());
    let resolved = offline.get_key_state(&prefix).unwrap();
    assert_eq!(resolved.sequence, 1);
    assert_eq!(resolved.current_keys, vec![member.cesr_key(1)]);
    server.abort();

    // The roster lists the member without any KEL walk.
    let prefixes = store.list_prefixes().unwrap();
    assert_eq!(prefixes, vec![prefix.clone()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflicting_event_at_occupied_sequence_is_refused_not_forked() {
    let registry = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let app = witness_app(registry.path(), data.path());

    let member = Controller::new(20);
    let (icp, icp_att) = member.signed_icp();
    let prefix = icp.i.clone();
    assert_eq!(
        submit(&app, &prefix, &Event::Icp(icp.clone()), &icp_att).await,
        StatusCode::OK
    );
    let (rot, rot_att) = member.signed_rot(&icp, 2);
    assert_eq!(
        submit(&app, &prefix, &Event::Rot(rot.clone()), &rot_att).await,
        StatusCode::OK
    );

    // Re-submission of the identical event is idempotent — receipted again,
    // never a fork.
    assert_eq!(
        submit(&app, &prefix, &Event::Rot(rot.clone()), &rot_att).await,
        StatusCode::OK,
        "identical re-submission must be a receipted no-op"
    );

    // A validly-signed but CONFLICTING rotation at the occupied sequence
    // (same chain position, different committed next key) is refused as
    // duplicity by the first-seen ledger.
    let (conflicting_rot, conflicting_att) = member.signed_rot(&icp, 0);
    assert_ne!(conflicting_rot.d, rot.d, "test needs distinct events");
    assert_eq!(
        submit(
            &app,
            &prefix,
            &Event::Rot(conflicting_rot.clone()),
            &conflicting_att
        )
        .await,
        StatusCode::CONFLICT,
        "conflicting event must be refused, not forked"
    );

    // Even a witness whose SQLite first-seen ledger was wiped (fresh
    // receipts.db, same registry) refuses the fork: git is the source of
    // truth, and the store's append-only rule catches the conflict.
    let fresh_data = TempDir::new().unwrap();
    let amnesiac = witness_app(registry.path(), fresh_data.path());
    assert_eq!(
        submit(
            &amnesiac,
            &prefix,
            &Event::Rot(conflicting_rot),
            &conflicting_att
        )
        .await,
        StatusCode::CONFLICT,
        "git truth must refuse the fork even with a wiped SQLite ledger"
    );

    // The refused fork must NOT have poisoned the sequence slot: the honest
    // event still receipts on the same node (first-seen records only after
    // full validation).
    assert_eq!(
        submit(&amnesiac, &prefix, &Event::Rot(rot.clone()), &rot_att).await,
        StatusCode::OK,
        "a refused fork must not block the honest event's receipt"
    );

    // The stored KEL is still one unbroken chain.
    let store = PerPrefixKelStore::open(registry.path());
    let state = store.get_key_state(&prefix).unwrap();
    assert_eq!(state.sequence, 1);
    assert_eq!(state.last_event_said, rot.d);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_onboarding_of_distinct_members_does_not_serialize_or_fail() {
    let registry = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let app = witness_app(registry.path(), data.path());

    let mut handles = Vec::new();
    for i in 0..8u8 {
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            let member = Controller::new(50 + i * 3);
            let (icp, att) = member.signed_icp();
            let prefix = icp.i.clone();
            let status = submit(&app, &prefix, &Event::Icp(icp), &att).await;
            (prefix, status)
        }));
    }

    let mut prefixes = Vec::new();
    for handle in handles {
        let (prefix, status) = handle.await.unwrap();
        assert_eq!(status, StatusCode::OK, "concurrent inception must succeed");
        prefixes.push(prefix);
    }

    let store = PerPrefixKelStore::open(registry.path());
    let mut held = store.list_prefixes().unwrap();
    held.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    prefixes.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(held, prefixes, "every member's KEL must be held");
    for prefix in &prefixes {
        assert_eq!(store.get_key_state(prefix).unwrap().sequence, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_submission_is_refused_when_bridge_is_active() {
    let registry = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let app = witness_app(registry.path(), data.path());

    let member = Controller::new(80);
    let (icp, _att) = member.signed_icp();
    let prefix = icp.i.clone();

    // Bare event, no attachment: the bridge demands the envelope dialect so
    // every stored event carries verifiable signature evidence.
    let event_json = serialize_for_signing(&Event::Icp(icp)).unwrap();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/witness/{}/event", prefix.as_str()))
        .header("content-type", "application/json")
        .body(Body::from(event_json))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("attachment") || text.contains("envelope") || text.contains("'x'"),
        "refusal must name the missing signature evidence, got: {text}"
    );
}

/// Run a git command in `dir`, isolated from host/global config.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .unwrap_or_else(|e| panic!("spawn git {args:?}: {e}"));
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
