//! Auths Auth Server
//!
//! "Login with Auths" authentication server. Proves un-phishable authentication
//! via KERI identities. Issues challenges, verifies signed responses by resolving
//! identity keys from the registry server over HTTP.

pub mod adapters;
pub mod config;
pub mod domain;
pub mod error;
pub mod ports;
pub mod routes;

use std::sync::Arc;

pub use config::AuthServerConfig;
pub use domain::app_service::AuthAppService;

use auths_verifier::clock::SystemClock;
use ports::{ClientStore, IdentityResolver, SessionStore};

/// Shared server state.
#[derive(Clone)]
pub struct AuthServerState {
    inner: Arc<AuthServerStateInner>,
}

struct AuthServerStateInner {
    app_service: AuthAppService,
    clients: Box<dyn ClientStore>,
    config: AuthServerConfig,
}

impl AuthServerState {
    /// Create a new auth server state with the given resolver, store, and config.
    pub fn new(
        resolver: impl IdentityResolver + 'static,
        sessions: impl SessionStore + 'static,
        clients: impl ClientStore + 'static,
        config: AuthServerConfig,
    ) -> Self {
        let sessions: Arc<dyn SessionStore> = Arc::new(sessions);
        let resolver: Arc<dyn IdentityResolver> = Arc::new(resolver);
        Self {
            inner: Arc::new(AuthServerStateInner {
                app_service: AuthAppService::new(sessions, resolver, Arc::new(SystemClock)),
                clients: Box::new(clients),
                config,
            }),
        }
    }

    pub fn app_service(&self) -> &AuthAppService {
        &self.inner.app_service
    }

    pub fn clients(&self) -> &dyn ClientStore {
        self.inner.clients.as_ref()
    }

    pub fn config(&self) -> &AuthServerConfig {
        &self.inner.config
    }
}

/// Run the auth server.
pub async fn run_server(state: AuthServerState) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = state.config().bind_addr;
    let app = routes::router(state);

    tracing::info!("Starting auth server on {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
