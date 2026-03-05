//! Shared bridge state.

use std::sync::Arc;

use tokio::sync::RwLock;

use crate::config::BridgeConfig;
use crate::error::BridgeError;
use crate::issuer::{ClockFn, OidcIssuer};
use crate::jwks::{Jwks, KeyManager};
use crate::rate_limit::PrefixRateLimiter;

/// Shared state for the OIDC bridge, wrapped in Arc for Axum handlers.
#[derive(Clone)]
pub struct BridgeState {
    inner: Arc<BridgeStateInner>,
}

struct BridgeStateInner {
    issuer: RwLock<OidcIssuer>,
    key_manager: RwLock<KeyManager>,
    config: BridgeConfig,
    clock: ClockFn,
    rate_limiter: Option<PrefixRateLimiter>,
    #[cfg(feature = "oidc-policy")]
    workload_policy: Option<auths_policy::CompiledPolicy>,
    #[cfg(feature = "oidc-trust")]
    trust_registry: Option<auths_policy::TrustRegistry>,
    #[cfg(feature = "github-oidc")]
    github_jwks: Option<crate::github_oidc::JwksClient>,
}

impl BridgeState {
    /// Create a new bridge state from configuration using the system clock.
    #[allow(clippy::disallowed_methods)]
    pub fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        Self::new_with_clock(config, Arc::new(|| chrono::Utc::now().timestamp() as u64))
    }

    /// Create a new bridge state with an injectable clock function.
    pub fn new_with_clock(config: BridgeConfig, clock: ClockFn) -> Result<Self, BridgeError> {
        let key_manager = load_key_manager(&config)?;
        let issuer = OidcIssuer::new_with_clock(&config, &key_manager, clock.clone())?;
        let rate_limiter = build_rate_limiter(&config);

        #[cfg(feature = "oidc-policy")]
        let workload_policy = build_workload_policy(&config)?;

        #[cfg(feature = "oidc-trust")]
        let trust_registry = build_trust_registry(&config)?;

        #[cfg(feature = "github-oidc")]
        let github_jwks = build_github_jwks_client(&config);

        Ok(Self {
            inner: Arc::new(BridgeStateInner {
                issuer: RwLock::new(issuer),
                key_manager: RwLock::new(key_manager),
                config,
                clock,
                rate_limiter,
                #[cfg(feature = "oidc-policy")]
                workload_policy,
                #[cfg(feature = "oidc-trust")]
                trust_registry,
                #[cfg(feature = "github-oidc")]
                github_jwks,
            }),
        })
    }

    /// Get a reference to the OIDC issuer lock.
    pub fn issuer(&self) -> &RwLock<OidcIssuer> {
        &self.inner.issuer
    }

    /// Get a reference to the key manager lock.
    pub fn key_manager(&self) -> &RwLock<KeyManager> {
        &self.inner.key_manager
    }

    /// Get a reference to the bridge config.
    pub fn config(&self) -> &BridgeConfig {
        &self.inner.config
    }

    /// Get a reference to the rate limiter (if enabled).
    pub fn rate_limiter(&self) -> Option<&PrefixRateLimiter> {
        self.inner.rate_limiter.as_ref()
    }

    /// Get a reference to the compiled workload policy (if configured).
    #[cfg(feature = "oidc-policy")]
    pub fn workload_policy(&self) -> Option<&auths_policy::CompiledPolicy> {
        self.inner.workload_policy.as_ref()
    }

    /// Get a reference to the trust registry (if configured).
    #[cfg(feature = "oidc-trust")]
    pub fn trust_registry(&self) -> Option<&auths_policy::TrustRegistry> {
        self.inner.trust_registry.as_ref()
    }

    /// Get a reference to the GitHub JWKS client (if configured).
    #[cfg(feature = "github-oidc")]
    pub fn github_jwks(&self) -> Option<&crate::github_oidc::JwksClient> {
        self.inner.github_jwks.as_ref()
    }

    /// Rotate the signing key. The current key becomes the previous key
    /// in JWKS (for overlap), and the new PEM becomes the active signing key.
    ///
    /// Returns the updated JWKS (with both keys).
    pub async fn rotate_key(&self, new_pem: &[u8]) -> Result<Jwks, BridgeError> {
        let mut km = self.inner.key_manager.write().await;
        let mut issuer = self.inner.issuer.write().await;

        let new_km = km.rotate(new_pem)?;
        let new_issuer =
            OidcIssuer::new_with_clock(&self.inner.config, &new_km, self.inner.clock.clone())?;

        let jwks = new_km.jwks();
        *km = new_km;
        *issuer = new_issuer;

        Ok(jwks)
    }

    /// Drop the previous key from JWKS (call after the overlap window).
    ///
    /// Returns the updated JWKS (with only the active key).
    pub async fn drop_previous_key(&self) -> Jwks {
        let mut km = self.inner.key_manager.write().await;
        km.drop_previous();
        km.jwks()
    }
}

#[cfg(feature = "github-oidc")]
fn build_github_jwks_client(config: &BridgeConfig) -> Option<crate::github_oidc::JwksClient> {
    let audience = config.github_expected_audience.as_deref()?;
    let issuer = config
        .github_oidc_issuer
        .as_deref()
        .unwrap_or("https://token.actions.githubusercontent.com");
    let ttl = std::time::Duration::from_secs(config.github_jwks_cache_ttl_secs);

    tracing::info!(
        issuer = issuer,
        audience = audience,
        cache_ttl_secs = config.github_jwks_cache_ttl_secs,
        "GitHub OIDC cross-reference enabled"
    );

    Some(crate::github_oidc::JwksClient::new(issuer, audience, ttl))
}

/// Build the rate limiter based on config.
fn build_rate_limiter(config: &BridgeConfig) -> Option<PrefixRateLimiter> {
    if config.rate_limit_enabled {
        Some(PrefixRateLimiter::new(
            config.rate_limit_rpm,
            config.rate_limit_burst,
        ))
    } else {
        None
    }
}

#[cfg(feature = "oidc-policy")]
fn build_workload_policy(
    config: &BridgeConfig,
) -> Result<Option<auths_policy::CompiledPolicy>, BridgeError> {
    let json_bytes = if let Some(ref path) = config.workload_policy_path {
        let bytes = std::fs::read(path).map_err(|e| {
            BridgeError::PolicyCompilationFailed(format!(
                "failed to read policy file {}: {e}",
                path.display()
            ))
        })?;
        tracing::info!(path = %path.display(), "Loading workload policy from file");
        Some(bytes)
    } else if let Some(ref json) = config.workload_policy_json {
        tracing::info!("Loading workload policy from inline JSON");
        Some(json.as_bytes().to_vec())
    } else {
        None
    };

    match json_bytes {
        Some(bytes) => {
            let policy = auths_policy::compile_from_json(&bytes).map_err(|errors| {
                let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                BridgeError::PolicyCompilationFailed(msgs.join("; "))
            })?;
            tracing::info!("Workload policy compiled successfully");
            Ok(Some(policy))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "oidc-trust")]
fn build_trust_registry(
    config: &BridgeConfig,
) -> Result<Option<auths_policy::TrustRegistry>, BridgeError> {
    let Some(ref path) = config.trust_registry_path else {
        return Ok(None);
    };

    let bytes = std::fs::read(path).map_err(|e| {
        BridgeError::Internal(format!(
            "failed to read trust registry file {}: {e}",
            path.display()
        ))
    })?;

    let registry: auths_policy::TrustRegistry = serde_json::from_slice(&bytes).map_err(|e| {
        BridgeError::Internal(format!(
            "failed to parse trust registry file {}: {e}",
            path.display()
        ))
    })?;

    tracing::info!(entries = registry.entries().len(), "Loaded trust registry");
    Ok(Some(registry))
}

/// Load or generate the RSA signing key based on config.
fn load_key_manager(config: &BridgeConfig) -> Result<KeyManager, BridgeError> {
    if let Some(ref pem) = config.signing_key_pem {
        KeyManager::from_pem(pem.as_bytes())
    } else if let Some(ref path) = config.signing_key_path {
        KeyManager::load_or_generate(path)
    } else {
        tracing::warn!("No signing key configured, generating ephemeral RSA key");
        KeyManager::generate()
    }
}
