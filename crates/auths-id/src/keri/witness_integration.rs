//! Witness receipt collection and storage after KEL events.
//!
//! This module ties together:
//! - `HttpAsyncWitnessClient` (auths-infra-http) for talking to witness servers
//! - `ReceiptCollector` (auths-core) for parallel k-of-n collection
//! - `GitReceiptStorage` (auths-id) for persisting receipts in Git
//!
//! Feature-gated behind `witness-client`.

use std::path::Path;
use std::sync::Arc;

use auths_core::witness::{AsyncWitnessProvider, CollectionError, Receipt, ReceiptCollector};
use auths_infra_http::HttpAsyncWitnessClient;

use super::types::{Prefix, Said};
use crate::keri::event::EventReceipts;
use crate::storage::receipts::{GitReceiptStorage, ReceiptStorage};
use crate::witness_config::{WitnessConfig, WitnessPolicy};

#[allow(clippy::expect_used)]
// INVARIANT: tokio runtime builder with standard settings cannot fail
fn shared_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("INVARIANT: tokio runtime builder with standard settings cannot fail")
    })
}

/// Errors from witness integration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessIntegrationError {
    #[error("Receipt collection failed: {0}")]
    Collection(#[from] CollectionError),

    #[error("Receipt storage failed: {0}")]
    Storage(#[from] crate::error::StorageError),

    #[error("Tokio runtime error: {0}")]
    Runtime(#[from] std::io::Error),
}

impl auths_core::error::AuthsErrorInfo for WitnessIntegrationError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Collection(_) => "AUTHS-E4971",
            Self::Storage(_) => "AUTHS-E4972",
            Self::Runtime(_) => "AUTHS-E4973",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Collection(_) => {
                Some("Check witness server connectivity and threshold configuration")
            }
            Self::Storage(_) => Some("Check storage backend permissions"),
            Self::Runtime(_) => None,
        }
    }
}

/// Collect witness receipts for an event and store them in Git.
///
/// Builds `HttpWitnessClient` instances from the config URLs, runs
/// the `ReceiptCollector`, and persists results via `GitReceiptStorage`.
///
/// Respects `WitnessPolicy`:
/// - **Enforce**: propagates errors as hard failures
/// - **Warn**: logs a warning and returns `Ok(vec![])`
/// - **Skip**: returns `Ok(vec![])` immediately
pub fn collect_and_store_receipts(
    repo_path: &Path,
    prefix: &Prefix,
    event_said: &Said,
    event_json: &[u8],
    config: &WitnessConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<Receipt>, WitnessIntegrationError> {
    // Skip policy → return early
    if config.policy == WitnessPolicy::Skip || !config.is_enabled() {
        return Ok(vec![]);
    }

    // Build witness clients from URLs
    let witnesses: Vec<Arc<dyn AsyncWitnessProvider>> = config
        .witness_urls
        .iter()
        .map(|url| {
            let client = HttpAsyncWitnessClient::new(url.to_string(), config.threshold)
                .with_timeout(std::time::Duration::from_millis(config.timeout_ms));
            Arc::new(client) as Arc<dyn AsyncWitnessProvider>
        })
        .collect();

    // Build collector
    let collector = ReceiptCollector::new(witnesses, config.threshold, config.timeout_ms);

    // SECURITY: witness API returns unsigned Receipt — signatures not verified
    // at collection time. Tracked for protocol-level fix.
    let result = {
        let prefix_newtype = Prefix::new_unchecked(prefix.as_str().to_string());
        let event_json = event_json.to_vec();
        let rt = shared_runtime();
        rt.block_on(async { collector.collect(&prefix_newtype, &event_json).await })
    };

    match result {
        Ok(receipts) => {
            // Store receipts in Git
            let storage = GitReceiptStorage::new(repo_path);
            let event_receipts = EventReceipts {
                event_said: event_said.clone(),
                receipts: receipts.clone(),
            };
            storage
                .store_receipts(prefix, &event_receipts, now)
                .map_err(WitnessIntegrationError::Storage)?;

            log::info!(
                "Collected and stored {} witness receipts for event {} (prefix {})",
                receipts.len(),
                event_said.as_str(),
                prefix.as_str(),
            );
            Ok(receipts)
        }
        Err(e) => match config.policy {
            WitnessPolicy::Warn => {
                log::warn!(
                    "Witness receipt collection failed (policy=Warn, continuing): {}",
                    e
                );
                Ok(vec![])
            }
            WitnessPolicy::Enforce => Err(WitnessIntegrationError::Collection(e)),
            WitnessPolicy::Skip => Ok(vec![]), // unreachable, but safe
        },
    }
}
