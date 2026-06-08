//! Single-host control-plane server boot.
//!
//! Builds an [`AppState`] over the local `~/.auths` registry (the org's own host holds
//! its signing key + passphrase) and serves the control-plane router. Configuration is
//! via env: `AUTHS_ORG_KEY` (org key alias), `AUTHS_AUDIENCE` (this RP's audience),
//! `AUTHS_KEY_PASSPHRASE` (org key passphrase).

// The binary entry is the configuration boundary: it reads `std::env::var` here (the
// SDK below it stays injection-based), mirroring the CLAUDE.md "CLI/API reads env at
// the presentation boundary" rule.
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use auths_api::app::{build_router, AppState};
use auths_core::ports::clock::SystemClock;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::KeyAlias;
use auths_core::AgentError;
use auths_id::attestation::export::AttestationSink;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_rp::{Audience, InMemoryChallengeStore};
use auths_sdk::context::AuthsContext;
use auths_sdk::keychain::get_platform_keychain;
use auths_sdk::storage::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};

/// A passphrase provider that reads the org key passphrase from the environment —
/// the single-host server's key-custody mechanism.
struct EnvPassphraseProvider {
    passphrase: zeroize::Zeroizing<String>,
}

impl PassphraseProvider for EnvPassphraseProvider {
    fn get_passphrase(&self, _prompt: &str) -> Result<zeroize::Zeroizing<String>, AgentError> {
        Ok(self.passphrase.clone())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = match build_state() {
        Ok(state) => state,
        Err(e) => {
            tracing::error!("Failed to build control-plane state: {e}");
            return;
        }
    };

    let app = build_router(state);

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:8080").await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind server: {}", e);
            return;
        }
    };
    tracing::info!("Control plane listening on 127.0.0.1:8080");
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("Server error: {}", e);
    }
}

/// Build the control-plane state from the local `~/.auths` registry + env config.
fn build_state() -> anyhow::Result<AppState> {
    let home = auths_sdk::paths::auths_home()?;
    let org_alias = std::env::var("AUTHS_ORG_KEY").unwrap_or_else(|_| "main".to_string());
    let audience_str = std::env::var("AUTHS_AUDIENCE")
        .map_err(|_| anyhow::anyhow!("AUTHS_AUDIENCE must be set"))?;
    let passphrase = std::env::var("AUTHS_KEY_PASSPHRASE")
        .map_err(|_| anyhow::anyhow!("AUTHS_KEY_PASSPHRASE must be set"))?;

    let registry: Arc<dyn auths_id::ports::registry::RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&home)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(home.clone()));
    let attestation_store = Arc::new(RegistryAttestationStorage::new(&home));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&attestation_store) as Arc<dyn AttestationSink + Send + Sync>;
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        attestation_store as Arc<dyn AttestationSource + Send + Sync>;
    let key_storage: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::from(get_platform_keychain()?);
    let passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(EnvPassphraseProvider {
            passphrase: zeroize::Zeroizing::new(passphrase),
        });

    let ctx = AuthsContext::builder()
        .registry(registry)
        .key_storage(key_storage)
        .clock(Arc::new(SystemClock))
        .identity_storage(Arc::clone(&identity_storage))
        .attestation_sink(attestation_sink)
        .attestation_source(attestation_source)
        .passphrase_provider(passphrase_provider)
        .repo_path(home.clone())
        .build();

    let managed = identity_storage
        .load_identity()
        .map_err(|e| anyhow::anyhow!("no org identity in {home:?}: {e}"))?;
    let org_prefix = managed
        .controller_did
        .as_str()
        .strip_prefix("did:keri:")
        .unwrap_or(managed.controller_did.as_str())
        .to_string();

    let audience = Audience::parse(&audience_str)
        .map_err(|e| anyhow::anyhow!("invalid AUTHS_AUDIENCE: {e}"))?;
    let challenges = Arc::new(InMemoryChallengeStore::new(4096));

    Ok(AppState::new(
        Arc::new(ctx),
        KeyAlias::new_unchecked(org_alias),
        org_prefix,
        challenges,
        audience,
    ))
}
