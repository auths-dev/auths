//! Remote pairing onto the KERI delegation model (Model D).
//!
//! A joining device generates its own key, ships a self-signed `dip`, the
//! initiator (root) anchors it, and the joiner confirms the anchor and persists.
//! The root never holds the device key. These tests drive the online path through
//! an in-memory fake relay (the relay is an untrusted byte courier), plus the
//! abort + tamper negatives.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use auths_core::PrefilledPassphraseProvider;
use auths_core::pairing::types::{
    CreateSessionRequest, CreateSessionResponse, GetConfirmationResponse, GetSessionResponse,
    SessionStatus, SubmitConfirmationRequest, SubmitResponseRequest,
};
use auths_core::ports::network::NetworkError;
use auths_core::ports::pairing::PairingRelayClient;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::keri::Event;
use auths_id::keri::types::Prefix;
use auths_id::storage::registry::backend::RegistryBackend;
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_sdk::pairing::{
    PairingCompletionResult, PairingError, PairingSessionParams, anchor_pairing_response,
    build_delegated_join_response, build_pairing_session_request, finalize_delegated_join,
    initiate_online_pairing, join_pairing_session, load_controller_did,
};
use chrono::Utc;

use crate::cases::helpers::{build_test_context, build_test_context_with_provider};

const PASS: &str = "Test-passphrase1!";

/// In-memory pairing relay shared by the initiator + joiner halves. It only stores
/// and serves the session/response/confirmation bytes — it neither builds nor
/// inspects the delegation events (mirrors a real untrusted relay).
#[derive(Default)]
struct RelayState {
    session: Option<CreateSessionRequest>,
    response: Option<SubmitResponseRequest>,
    confirmation: Option<SubmitConfirmationRequest>,
}

#[derive(Clone)]
struct FakeRelay {
    state: Arc<Mutex<RelayState>>,
}

impl FakeRelay {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RelayState::default())),
        }
    }

    /// Wait until the initiator has registered a session, then return its short code
    /// (simulates the joiner reading the QR / typing the code).
    async fn wait_for_short_code(&self) -> String {
        loop {
            if let Some(code) = self
                .state
                .lock()
                .expect("relay lock")
                .session
                .as_ref()
                .map(|s| s.short_code.clone())
            {
                return code;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn session_snapshot(state: &RelayState, session_id: &str) -> GetSessionResponse {
    let status = if state.response.is_some() {
        SessionStatus::Responded
    } else {
        SessionStatus::Pending
    };
    GetSessionResponse {
        session_id: session_id.to_string(),
        status,
        ttl_seconds: 60,
        token: state.session.clone(),
        response: state.response.clone(),
    }
}

fn confirmation_snapshot(state: &RelayState) -> GetConfirmationResponse {
    match state.confirmation.as_ref() {
        Some(c) => GetConfirmationResponse {
            encrypted_attestation: c.encrypted_attestation.clone(),
            aborted: c.aborted,
        },
        None => GetConfirmationResponse {
            encrypted_attestation: None,
            aborted: false,
        },
    }
}

impl PairingRelayClient for FakeRelay {
    fn create_session(
        &self,
        _url: &str,
        request: &CreateSessionRequest,
    ) -> impl Future<Output = Result<CreateSessionResponse, NetworkError>> + Send {
        let state = self.state.clone();
        let req = request.clone();
        async move {
            let session_id = req.session_id.clone();
            let short_code = req.short_code.clone();
            state.lock().expect("relay lock").session = Some(req);
            Ok(CreateSessionResponse {
                session_id,
                status: SessionStatus::Pending,
                short_code,
                uri: String::new(),
                ttl_seconds: 60,
            })
        }
    }

    fn get_session(
        &self,
        _url: &str,
        session_id: &str,
    ) -> impl Future<Output = Result<GetSessionResponse, NetworkError>> + Send {
        let state = self.state.clone();
        let sid = session_id.to_string();
        async move { Ok(session_snapshot(&state.lock().expect("relay lock"), &sid)) }
    }

    fn lookup_by_code(
        &self,
        _url: &str,
        _code: &str,
    ) -> impl Future<Output = Result<GetSessionResponse, NetworkError>> + Send {
        let state = self.state.clone();
        async move {
            let guard = state.lock().expect("relay lock");
            let sid = guard
                .session
                .as_ref()
                .map(|s| s.session_id.clone())
                .unwrap_or_default();
            Ok(session_snapshot(&guard, &sid))
        }
    }

    fn submit_response(
        &self,
        _url: &str,
        _session_id: &str,
        response: &SubmitResponseRequest,
    ) -> impl Future<Output = Result<(), NetworkError>> + Send {
        let state = self.state.clone();
        let resp = response.clone();
        async move {
            state.lock().expect("relay lock").response = Some(resp);
            Ok(())
        }
    }

    fn wait_for_update(
        &self,
        _url: &str,
        session_id: &str,
        timeout: Duration,
    ) -> impl Future<Output = Result<Option<GetSessionResponse>, NetworkError>> + Send {
        let state = self.state.clone();
        let sid = session_id.to_string();
        async move {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                {
                    let guard = state.lock().expect("relay lock");
                    if guard.response.is_some() {
                        return Ok(Some(session_snapshot(&guard, &sid)));
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    return Ok(None);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    fn submit_confirmation(
        &self,
        _url: &str,
        _session_id: &str,
        request: &SubmitConfirmationRequest,
    ) -> impl Future<Output = Result<(), NetworkError>> + Send {
        let state = self.state.clone();
        let req = request.clone();
        async move {
            state.lock().expect("relay lock").confirmation = Some(req);
            Ok(())
        }
    }

    fn get_confirmation(
        &self,
        _url: &str,
        _session_id: &str,
    ) -> impl Future<Output = Result<GetConfirmationResponse, NetworkError>> + Send {
        let state = self.state.clone();
        async move { Ok(confirmation_snapshot(&state.lock().expect("relay lock"))) }
    }

    fn wait_for_confirmation(
        &self,
        _url: &str,
        _session_id: &str,
        timeout: Duration,
    ) -> impl Future<Output = Result<Option<GetConfirmationResponse>, NetworkError>> + Send {
        let state = self.state.clone();
        async move {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                {
                    let guard = state.lock().expect("relay lock");
                    if guard.confirmation.is_some() {
                        return Ok(Some(confirmation_snapshot(&guard)));
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    return Ok(None);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

fn prefilled() -> Arc<dyn PassphraseProvider + Send + Sync> {
    Arc::new(PrefilledPassphraseProvider::new(PASS))
}

/// A root identity over real git storage. Returns the keychain handle so tests can
/// assert the device key is NEVER stored under the root.
fn setup_root_identity() -> (tempfile::TempDir, String, AuthsContext, IsolatedKeychainHandle) {
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let registry_path = tmp.path().join(".auths");
    let kc = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(kc.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let setup_ctx = build_test_context(&registry_path, Arc::new(kc.clone()));
    match initialize(
        IdentityConfig::Developer(config),
        &setup_ctx,
        Arc::new(kc.clone()),
        &signer,
        &provider,
        None,
    )
    .expect("root inception")
    {
        InitializeResult::Developer(r) => r,
        _ => unreachable!("developer identity"),
    };
    let ctx = build_test_context_with_provider(&registry_path, Arc::new(kc.clone()), Some(prefilled()));
    let did = load_controller_did(ctx.identity_storage.as_ref()).expect("root did");
    (tmp, did, ctx, kc)
}

/// A fresh device: an initialized but empty registry + empty keychain, no identity.
fn setup_fresh_joiner() -> (tempfile::TempDir, AuthsContext, IsolatedKeychainHandle) {
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let registry_path = tmp.path().join(".auths-joiner");
    let kc = IsolatedKeychainHandle::new();
    let ctx = build_test_context_with_provider(&registry_path, Arc::new(kc.clone()), Some(prefilled()));
    (tmp, ctx, kc)
}

fn root_params(controller_did: &str) -> PairingSessionParams {
    PairingSessionParams {
        controller_did: controller_did.to_string(),
        registry: "fake://relay".to_string(),
        capabilities: vec![],
        expiry_secs: 60,
    }
}

#[tokio::test]
async fn pair_delegates_a_fresh_device_end_to_end() {
    let relay = FakeRelay::new();
    let (_root_tmp, root_did, root_ctx, root_keychain) = setup_root_identity();
    let (_joiner_tmp, joiner_ctx, joiner_keychain) = setup_fresh_joiner();
    let now = Utc::now();
    let device_alias = KeyAlias::new_unchecked("laptop");

    let initiator = async {
        initiate_online_pairing(root_params(&root_did), &relay, &root_ctx, now, None).await
    };
    let joiner = async {
        let code = relay.wait_for_short_code().await;
        join_pairing_session(
            &joiner_ctx,
            &code,
            "fake://relay",
            &relay,
            now,
            CurveType::Ed25519,
            device_alias.clone(),
            Some("Laptop".to_string()),
            Duration::from_secs(10),
        )
        .await
    };

    let (init_res, join_res) = tokio::join!(initiator, joiner);

    let init_did = match init_res.expect("initiator pairing") {
        PairingCompletionResult::Success { device_did, .. } => device_did,
    };
    let join_did = match join_res.expect("joiner pairing") {
        PairingCompletionResult::Success { device_did, .. } => device_did,
    };

    // Both sides agree on the delegated device's identifier, and it is a did:keri.
    assert_eq!(init_did.as_str(), join_did.as_str());
    assert!(
        join_did.as_str().starts_with("did:keri:"),
        "the paired device is a KERI delegated identifier, got {join_did}"
    );

    // The device key lives in the JOINER's keychain — never the root's.
    assert!(
        joiner_keychain.load_key(&device_alias).is_ok(),
        "the device persisted its own key"
    );
    assert!(
        root_keychain.load_key(&device_alias).is_err(),
        "the root never holds the device key"
    );

    // The device persisted its own KEL (the dip) in its registry.
    let device_prefix = Prefix::new_unchecked(
        join_did
            .as_str()
            .strip_prefix("did:keri:")
            .expect("did:keri prefix")
            .to_string(),
    );
    let dip = joiner_ctx
        .registry
        .get_event(&device_prefix, 0)
        .expect("device dip persisted in the joiner's registry");
    assert!(matches!(dip, Event::Dip(_)), "the device's KEL is a dip");
}

#[test]
fn finalize_rejects_an_initiator_abort() {
    let (_tmp, root_did, _root_ctx, _kc) = setup_root_identity();
    let (_joiner_tmp, joiner_ctx, _joiner_kc) = setup_fresh_joiner();
    let now = Utc::now();

    let session = build_pairing_session_request(now, root_params(&root_did)).expect("session");
    let (_submit, pending, _secret) = build_delegated_join_response(
        now,
        &session.session.token,
        CurveType::Ed25519,
        KeyAlias::new_unchecked("laptop"),
        None,
    )
    .expect("join response");

    let aborted = GetConfirmationResponse {
        encrypted_attestation: None,
        aborted: true,
    };
    let result = finalize_delegated_join(&joiner_ctx, pending, &aborted);
    assert!(
        matches!(result, Err(PairingError::SessionNotAvailable(_))),
        "an aborted confirmation (SAS mismatch) must abort the join, got {result:?}"
    );
}

#[test]
fn anchor_rejects_a_tampered_device_dip() {
    let (_tmp, root_did, root_ctx, _kc) = setup_root_identity();
    let now = Utc::now();
    let session = build_pairing_session_request(now, root_params(&root_did)).expect("session");

    // A genuine device dip anchors cleanly.
    let (good, _pending, _s1) = build_delegated_join_response(
        now,
        &session.session.token,
        CurveType::Ed25519,
        KeyAlias::new_unchecked("laptop"),
        None,
    )
    .expect("join response");
    assert!(
        anchor_pairing_response(&root_ctx, &good.responder_inception_event, None).is_ok(),
        "a genuine device dip anchors"
    );

    // A tampered dip envelope must be rejected (fresh response so we don't reuse the anchored one).
    let (other, _p2, _s2) = build_delegated_join_response(
        now,
        &session.session.token,
        CurveType::Ed25519,
        KeyAlias::new_unchecked("laptop"),
        None,
    )
    .expect("join response");
    let mut bytes = other.responder_inception_event.into_bytes();
    let mid = bytes.len() / 2;
    bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).expect("ascii base64url");

    assert!(
        anchor_pairing_response(&root_ctx, &tampered, None).is_err(),
        "a tampered device dip must be rejected"
    );
}
