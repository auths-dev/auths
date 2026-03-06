//! Server state shared across handlers.

use std::sync::Arc;

use deadpool_postgres::Pool;

use crate::config::ScimServerConfig;

/// Shared server state, cloneable via Arc.
#[derive(Clone)]
pub struct ScimServerState {
    inner: Arc<Inner>,
}

struct Inner {
    config: ScimServerConfig,
    db: Pool,
}

impl ScimServerState {
    /// Create new server state.
    pub fn new(config: ScimServerConfig, db: Pool) -> Self {
        Self {
            inner: Arc::new(Inner { config, db }),
        }
    }

    /// Access the configuration.
    pub fn config(&self) -> &ScimServerConfig {
        &self.inner.config
    }

    /// Access the database pool.
    pub fn db(&self) -> &Pool {
        &self.inner.db
    }

    /// Base URL for resource locations.
    pub fn base_url(&self) -> &str {
        &self.inner.config.base_url
    }
}
