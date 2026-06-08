//! Standalone server bootstrap shared by the binary and the `auths scim serve` CLI.
//!
//! Builds the real [`SdkProvisioner`] over the local `~/.auths` registry (single-host
//! custody — the org's own host holds its signing key), assembles the tenant table,
//! and serves the [`router`](crate::router). Both the binary's `main` and the CLI
//! call [`run`], so there is one bootstrap, not two.

use std::path::PathBuf;
use std::sync::Arc;

use auths_core::ports::clock::SystemClock;
use auths_core::signing::PassphraseProvider;
use auths_id::attestation::export::AttestationSink;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_sdk::context::AuthsContext;
use auths_sdk::keychain::get_platform_keychain;
use auths_sdk::signing::PrefilledPassphraseProvider;
use auths_sdk::storage::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};

use crate::provisioner::{Provisioner, SdkProvisioner};
use crate::state::{ScimServerState, TenantConfig};

/// A single-tenant bootstrap: maps one IdP provisioning channel to one org.
#[derive(Debug, Clone)]
pub struct TenantBootstrap {
    /// Stable tenant identifier (matches the IdP's configured tenant).
    pub tenant_id: String,
    /// The Auths org prefix this tenant provisions into.
    pub org_prefix: String,
    /// The SCIM channel bearer token (stored only as a hash).
    pub bearer_token: String,
    /// Org signing-key alias (defaults to the derived `org-<slug>`).
    pub org_key_alias: Option<String>,
    /// Base URL for SCIM `meta.location`.
    pub base_url: Option<String>,
}

impl TenantBootstrap {
    fn into_config(self) -> TenantConfig {
        let mut config = TenantConfig::new(self.tenant_id, self.org_prefix, &self.bearer_token);
        if let Some(alias) = self.org_key_alias {
            config = config.with_org_key_alias(alias);
        }
        if let Some(url) = self.base_url {
            config = config.with_base_url(url);
        }
        config
    }
}

/// Configuration for running the SCIM server.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Bind address (e.g. `0.0.0.0:8787`).
    pub bind: String,
    /// The configured tenant, if any. `None` runs discovery-only (every `/Users`
    /// call rejects with 401 — honest for a not-yet-configured deployment).
    pub tenant: Option<TenantBootstrap>,
    /// Path to the Auths registry (defaults to `~/.auths`).
    pub home: Option<PathBuf>,
    /// Passphrase for the org signing key (single-host custody).
    pub passphrase: String,
}

/// Serve the SCIM router until the process is stopped.
///
/// Args:
/// * `config`: Bind address, optional tenant, registry home, and key passphrase.
///
/// Usage:
/// ```ignore
/// auths_scim_server::run(ServeConfig { bind: "0.0.0.0:8787".into(), .. }).await?;
/// ```
pub async fn run(config: ServeConfig) -> anyhow::Result<()> {
    let provisioner = build_provisioner(config.home.clone(), &config.passphrase)?;
    let tenants = config
        .tenant
        .map(|t| vec![t.into_config()])
        .unwrap_or_default();
    let state = ScimServerState::new(tenants, provisioner);
    let app = crate::router(state);

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!("Auths SCIM server listening on {}", config.bind);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Build the real identity provisioner over the local registry.
///
/// Args:
/// * `home`: Registry path; `None` resolves to `~/.auths`.
/// * `passphrase`: Passphrase for the org signing key.
///
/// Usage:
/// ```ignore
/// let provisioner = build_provisioner(None, &passphrase)?;
/// ```
pub fn build_provisioner(
    home: Option<PathBuf>,
    passphrase: &str,
) -> anyhow::Result<Arc<dyn Provisioner>> {
    let home = match home {
        Some(h) => h,
        None => auths_sdk::paths::auths_home()?,
    };

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
        Arc::new(PrefilledPassphraseProvider::new(passphrase));

    let ctx = AuthsContext::builder()
        .registry(registry)
        .key_storage(key_storage)
        .clock(Arc::new(SystemClock))
        .identity_storage(identity_storage)
        .attestation_sink(attestation_sink)
        .attestation_source(attestation_source)
        .passphrase_provider(passphrase_provider)
        .repo_path(home)
        .build();

    Ok(Arc::new(SdkProvisioner::new(ctx)))
}
