//! D1 regression guard — list endpoints must not replay the org KEL per member.
//!
//! The N+1 fix routes every per-member resolution through one shared
//! `OrgKelSnapshot`; this suite pins that invariant with a counting decorator
//! on `RegistryBackend::visit_events`. A *full replay* is a `visit_events`
//! call that walks more than one event (the chain walker's
//! `immediate_delegator` probe breaks at the inception event, so it never
//! counts as one).
//!
//! The invariant asserted is the one functional tests are structurally blind
//! to: replaying a KEL once or N times yields byte-identical responses, so
//! only counting can detect a regression. Each test measures the org-KEL
//! full-replay count at two member counts and requires it to be an identical
//! small constant — the pre-fix shape (one snapshot per member) grows with
//! the member count and fails loudly here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};

use auths_api::app::AppState;
use auths_api::control_plane::{list_agents, list_fleet, ListParams};
use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_core::testing::IsolatedKeychainHandle;
use auths_core::PrefilledPassphraseProvider;
use auths_crypto::CurveType;
use auths_id::attestation::export::AttestationSink;
use auths_id::keri::state::KeyState;
use auths_id::keri::types::{Prefix, Said};
use auths_id::keri::Event;
use auths_id::ports::registry::{
    AtomicWriteBatch, MemberFilter, MemberView, OrgMemberEntry, RegistryBackend, RegistryError,
    RegistryMetadata, TipInfo,
};
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_rp::{Audience, InMemoryChallengeStore};
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::agents::add_scoped;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_verifier::core::Attestation;
use auths_verifier::types::CanonicalDid;
use auths_verifier::Capability;
use axum::extract::{Path as AxPath, Query, State};

const PASS: &str = "Test-passphrase1!";

/// A delegating [`RegistryBackend`] decorator that records, per prefix, how
/// many events each `visit_events` call walked. Every other method forwards
/// to the wrapped backend unchanged (trait-default methods included, so
/// backend overrides like attachments and atomic batches are preserved).
struct CountingRegistry {
    inner: Arc<dyn RegistryBackend + Send + Sync>,
    visits: Mutex<HashMap<String, Vec<usize>>>,
}

impl CountingRegistry {
    fn new(inner: Arc<dyn RegistryBackend + Send + Sync>) -> Self {
        Self {
            inner,
            visits: Mutex::new(HashMap::new()),
        }
    }

    fn reset(&self) {
        self.visits.lock().expect("visit log poisoned").clear();
    }

    /// Calls on `prefix` that walked more than one event — i.e. full replays.
    /// Single-event calls are the chain walker's break-at-inception probes.
    fn full_replays(&self, prefix: &str) -> usize {
        self.visits
            .lock()
            .expect("visit log poisoned")
            .get(prefix)
            .map(|calls| calls.iter().filter(|&&events| events > 1).count())
            .unwrap_or(0)
    }
}

impl RegistryBackend for CountingRegistry {
    fn append_event(&self, prefix: &Prefix, event: &Event) -> Result<(), RegistryError> {
        self.inner.append_event(prefix, event)
    }

    fn append_signed_event(
        &self,
        prefix: &Prefix,
        event: &Event,
        attachment: &[u8],
    ) -> Result<(), RegistryError> {
        self.inner.append_signed_event(prefix, event, attachment)
    }

    fn get_attachment(&self, prefix: &Prefix, seq: u128) -> Result<Option<Vec<u8>>, RegistryError> {
        self.inner.get_attachment(prefix, seq)
    }

    fn get_event(&self, prefix: &Prefix, seq: u128) -> Result<Event, RegistryError> {
        self.inner.get_event(prefix, seq)
    }

    fn visit_events(
        &self,
        prefix: &Prefix,
        from_seq: u128,
        visitor: &mut dyn FnMut(&Event) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let mut events_walked = 0usize;
        let result = self.inner.visit_events(prefix, from_seq, &mut |event| {
            events_walked += 1;
            visitor(event)
        });
        self.visits
            .lock()
            .expect("visit log poisoned")
            .entry(prefix.as_str().to_string())
            .or_default()
            .push(events_walked);
        result
    }

    fn get_tip(&self, prefix: &Prefix) -> Result<TipInfo, RegistryError> {
        self.inner.get_tip(prefix)
    }

    fn get_key_state(&self, prefix: &Prefix) -> Result<KeyState, RegistryError> {
        self.inner.get_key_state(prefix)
    }

    fn write_key_state(&self, prefix: &Prefix, state: &KeyState) -> Result<(), RegistryError> {
        self.inner.write_key_state(prefix, state)
    }

    fn visit_identities(
        &self,
        visitor: &mut dyn FnMut(&str) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        self.inner.visit_identities(visitor)
    }

    fn store_attestation(&self, attestation: &Attestation) -> Result<(), RegistryError> {
        self.inner.store_attestation(attestation)
    }

    fn load_attestation(&self, did: &CanonicalDid) -> Result<Option<Attestation>, RegistryError> {
        self.inner.load_attestation(did)
    }

    fn visit_attestation_history(
        &self,
        did: &CanonicalDid,
        visitor: &mut dyn FnMut(&Attestation) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        self.inner.visit_attestation_history(did, visitor)
    }

    fn visit_devices(
        &self,
        visitor: &mut dyn FnMut(&CanonicalDid) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        self.inner.visit_devices(visitor)
    }

    fn store_org_member(&self, org: &str, member: &Attestation) -> Result<(), RegistryError> {
        self.inner.store_org_member(org, member)
    }

    fn visit_org_member_attestations(
        &self,
        org: &str,
        visitor: &mut dyn FnMut(&OrgMemberEntry) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        self.inner.visit_org_member_attestations(org, visitor)
    }

    fn list_org_members(
        &self,
        org: &str,
        filter: &MemberFilter,
    ) -> Result<Vec<MemberView>, RegistryError> {
        self.inner.list_org_members(org, filter)
    }

    fn list_org_members_fast(
        &self,
        org: &str,
        filter: &MemberFilter,
    ) -> Result<Vec<MemberView>, RegistryError> {
        self.inner.list_org_members_fast(org, filter)
    }

    fn init_if_needed(&self) -> Result<bool, RegistryError> {
        self.inner.init_if_needed()
    }

    fn metadata(&self) -> Result<RegistryMetadata, RegistryError> {
        self.inner.metadata()
    }

    fn append_tel_event(
        &self,
        issuer: &Prefix,
        registry_said: &Said,
        credential_said: &Said,
        sn: u128,
        event_bytes: &[u8],
    ) -> Result<(), RegistryError> {
        self.inner
            .append_tel_event(issuer, registry_said, credential_said, sn, event_bytes)
    }

    fn visit_tel_events(
        &self,
        issuer: &Prefix,
        registry_said: &Said,
        credential_said: &Said,
        visitor: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        self.inner
            .visit_tel_events(issuer, registry_said, credential_said, visitor)
    }

    fn store_credential(
        &self,
        issuer: &Prefix,
        credential_said: &Said,
        credential_bytes: &[u8],
    ) -> Result<(), RegistryError> {
        self.inner
            .store_credential(issuer, credential_said, credential_bytes)
    }

    fn load_credential(
        &self,
        issuer: &Prefix,
        credential_said: &Said,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        self.inner.load_credential(issuer, credential_said)
    }

    fn commit_batch(&self, batch: &AtomicWriteBatch) -> Result<(), RegistryError> {
        self.inner.commit_batch(batch)
    }
}

struct Fixture {
    state: AppState,
    counter: Arc<CountingRegistry>,
}

fn build_ctx(
    registry: Arc<dyn RegistryBackend + Send + Sync>,
    path: &std::path::Path,
    keychain: Arc<dyn KeyStorage + Send + Sync>,
    provider: Option<Arc<dyn PassphraseProvider + Send + Sync>>,
) -> AuthsContext {
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(path.to_path_buf()));
    let store = Arc::new(RegistryAttestationStorage::new(path));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&store) as Arc<dyn AttestationSink + Send + Sync>;
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        store as Arc<dyn AttestationSource + Send + Sync>;

    let mut builder = AuthsContext::builder()
        .registry(registry)
        .key_storage(keychain)
        .clock(Arc::new(SystemClock))
        .identity_storage(identity_storage)
        .attestation_sink(attestation_sink)
        .attestation_source(attestation_source)
        .repo_path(path.to_path_buf());
    if let Some(provider) = provider {
        builder = builder.passphrase_provider(provider);
    }
    builder.build()
}

/// Boot a real org over a git-backed registry wrapped in the counting
/// decorator, with `agent_count` delegated agents.
fn setup(agent_count: usize) -> (Fixture, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path();
    if git2::Repository::open(path).is_err() {
        git2::Repository::init(path).unwrap();
    }

    let git_backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(path)),
    );
    let counter = Arc::new(CountingRegistry::new(git_backend));
    let registry: Arc<dyn RegistryBackend + Send + Sync> =
        Arc::clone(&counter) as Arc<dyn RegistryBackend + Send + Sync>;

    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
    let boot = build_ctx(
        Arc::clone(&registry),
        path,
        Arc::new(keychain.clone()),
        None,
    );
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("org-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let result = match initialize(
        IdentityConfig::Developer(config),
        &boot,
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

    let arc_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx = build_ctx(registry, path, Arc::new(keychain), Some(arc_provider));

    let org_prefix = ctx
        .identity_storage
        .load_identity()
        .unwrap()
        .controller_did
        .as_str()
        .strip_prefix("did:keri:")
        .unwrap()
        .to_string();

    for n in 0..agent_count {
        add_agent(&ctx, &result.key_alias, n);
    }

    let state = AppState::new(
        Arc::new(ctx),
        result.key_alias,
        org_prefix,
        Arc::new(InMemoryChallengeStore::new(16)),
        Audience::parse("api.example.com").unwrap(),
    );

    (Fixture { state, counter }, tmp)
}

fn add_agent(ctx: &AuthsContext, org_alias: &KeyAlias, n: usize) {
    add_scoped(
        ctx,
        org_alias,
        &KeyAlias::new_unchecked(format!("agent-{n}")),
        CurveType::Ed25519,
        &[Capability::sign_commit()],
        None,
    )
    .expect("add agent");
}

fn params() -> Query<ListParams> {
    Query(ListParams {
        cursor: None,
        limit: None,
    })
}

async fn measure_list_agents(f: &Fixture, expected_members: usize) -> usize {
    f.counter.reset();
    let resp = list_agents(
        State(f.state.clone()),
        AxPath(f.state.org_prefix.clone()),
        params(),
    )
    .await
    .expect("list_agents");
    assert_eq!(resp.0.agents.len(), expected_members);
    f.counter.full_replays(&f.state.org_prefix)
}

async fn measure_list_fleet(f: &Fixture, expected_members: usize) -> usize {
    f.counter.reset();
    let resp = list_fleet(
        State(f.state.clone()),
        AxPath(f.state.org_prefix.clone()),
        params(),
    )
    .await
    .expect("list_fleet");
    assert_eq!(resp.0.members.len(), expected_members);
    f.counter.full_replays(&f.state.org_prefix)
}

/// The handler's org-KEL replay budget per request. `list()` walks the KEL
/// once for the roster and `OrgKelSnapshot::load` twice (roster + events);
/// lowering this constant is an improvement — update it deliberately, never
/// raise it to absorb a per-member regression.
const ORG_REPLAY_BUDGET: usize = 3;

#[tokio::test]
async fn list_agents_org_replays_constant_in_member_count() {
    let (f, _tmp) = setup(3);
    let replays_at_3 = measure_list_agents(&f, 3).await;

    for n in 3..6 {
        add_agent(&f.state.ctx, &f.state.org_alias, n);
    }
    let replays_at_6 = measure_list_agents(&f, 6).await;

    assert_eq!(
        replays_at_3, replays_at_6,
        "org-KEL full replays grew with member count — the D1 N+1 regression"
    );
    assert!(
        replays_at_6 <= ORG_REPLAY_BUDGET,
        "expected at most {ORG_REPLAY_BUDGET} org-KEL replays per request, got {replays_at_6}"
    );
}

#[tokio::test]
async fn list_fleet_org_replays_constant_in_member_count() {
    let (f, _tmp) = setup(3);
    let replays_at_3 = measure_list_fleet(&f, 3).await;

    for n in 3..6 {
        add_agent(&f.state.ctx, &f.state.org_alias, n);
    }
    let replays_at_6 = measure_list_fleet(&f, 6).await;

    assert_eq!(
        replays_at_3, replays_at_6,
        "org-KEL full replays grew with member count — the D1 N+1 regression"
    );
    assert!(
        replays_at_6 <= ORG_REPLAY_BUDGET,
        "expected at most {ORG_REPLAY_BUDGET} org-KEL replays per request, got {replays_at_6}"
    );
}
