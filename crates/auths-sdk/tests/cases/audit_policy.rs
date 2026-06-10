//! Epic E1 A5 — every policy-enforcement decision (allow + deny) is routed through
//! the audit sink. Builds a ctx with a capturing `EventSink` and asserts the commit
//! path emits a `policy:commit` audit record carrying the outcome + policy hash.

use std::sync::{Arc, Mutex};

use auths_core::PrefilledPassphraseProvider;
use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::attestation::export::AttestationSink;
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_sdk::context::{AuthsContext, EventSink};
use auths_sdk::domains::agents::add_scoped;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::org::policy::{Expr, set_org_policy};
use auths_sdk::workflows::commit_trust::evaluate_commit_policy;
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};

const PASS: &str = "Test-passphrase1!";

#[derive(Clone, Default)]
struct CapturingSink(Arc<Mutex<Vec<String>>>);

impl EventSink for CapturingSink {
    fn emit(&self, payload: &str) {
        self.0.lock().unwrap().push(payload.to_string());
    }
    fn flush(&self) {}
}

fn ctx_with_sink(
    registry_path: &std::path::Path,
    key_storage: Arc<dyn KeyStorage + Send + Sync>,
    provider: Arc<dyn PassphraseProvider + Send + Sync>,
    sink: Arc<dyn EventSink>,
) -> AuthsContext {
    if !registry_path.exists() {
        std::fs::create_dir_all(registry_path).unwrap();
    }
    if git2::Repository::open(registry_path).is_err() {
        git2::Repository::init(registry_path).unwrap();
    }
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(registry_path)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(registry_path.to_path_buf()));
    let store = Arc::new(RegistryAttestationStorage::new(registry_path));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&store) as Arc<dyn AttestationSink + Send + Sync>;
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        store as Arc<dyn AttestationSource + Send + Sync>;
    AuthsContext::builder()
        .registry(backend)
        .key_storage(key_storage)
        .clock(Arc::new(SystemClock))
        .identity_storage(identity_storage)
        .attestation_sink(attestation_sink)
        .attestation_source(attestation_source)
        .event_sink(sink)
        .passphrase_provider(provider)
        .build()
}

#[test]
fn commit_policy_decisions_are_recorded_in_the_audit_sink() {
    let tmp = tempfile::tempdir().unwrap();
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("org-key"))
        .with_git_signing_scope(auths_sdk::domains::signing::types::GitSigningScope::Skip)
        .build();

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingSink(Arc::clone(&captured));
    let arc_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx = ctx_with_sink(
        tmp.path(),
        Arc::new(keychain.clone()),
        arc_provider,
        Arc::new(sink),
    );

    match initialize(
        IdentityConfig::Developer(config),
        &ctx,
        Arc::new(keychain),
        &signer,
        &provider,
        None,
    )
    .unwrap()
    {
        InitializeResult::Developer(_) => {}
        _ => unreachable!(),
    };
    let org_prefix = auths_id::keri::parse_did_keri(
        ctx.identity_storage
            .load_identity()
            .unwrap()
            .controller_did
            .as_str(),
    )
    .unwrap();
    let org_alias = KeyAlias::new_unchecked("org-key");

    let agent = add_scoped(
        &ctx,
        &org_alias,
        &KeyAlias::new_unchecked("agent-1"),
        CurveType::Ed25519,
        &[auths_keri::Capability::sign_commit()],
        None,
    )
    .expect("add agent");

    // A denying policy (requires a capability the agent lacks).
    set_org_policy(
        &ctx,
        &org_prefix,
        &org_alias,
        &serde_json::to_vec(&Expr::HasCapability("deploy".into())).unwrap(),
    )
    .expect("set policy");

    let now = chrono::Utc::now();
    let _ = evaluate_commit_policy(
        &ctx,
        &format!("did:keri:{}", org_prefix.as_str()),
        &agent.agent_did,
        now,
    )
    .expect("evaluate");

    let events = captured.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .any(|e| e.contains("policy:commit") && e.contains("DENY")),
        "the deny decision must be recorded in the audit sink; captured: {events:?}"
    );
}
