//! Witness receipt collection and storage after KEL events.
//!
//! This module ties together:
//! - `HttpAsyncWitnessClient` (auths-infra-http) for talking to witness servers
//! - `ReceiptCollector` (auths-core) for parallel k-of-n collection
//! - `GitReceiptStorage` (auths-id) for persisting receipts in Git
//!
//! Receipts are verified at the auths-core chokepoint (`verify_receipt`) *inside*
//! `ReceiptCollector::collect`, which yields only `VerifiedReceipt`s: a forged
//! signature, a key that is not the pinned witness, or a receipt for an event
//! other than the one just authored is dropped and never counts toward quorum.
//! This module therefore only orchestrates collection and storage — it does not
//! re-implement verification.
//!
//! Feature-gated behind `witness-client`.

use std::path::Path;
use std::sync::Arc;

use auths_core::witness::{
    AsyncWitnessProvider, CollectionError, ReceiptCollector, StoredReceipt, VerifiedReceipt,
};
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

    #[error("witness quorum not met: {valid} valid receipt(s), need {required}")]
    QuorumNotMet {
        /// Receipts required by the configured threshold.
        required: usize,
        /// Receipts that survived signature/provenance verification.
        valid: usize,
    },

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
            Self::QuorumNotMet { .. } => "AUTHS-E4974",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Collection(_) => {
                Some("Check witness server connectivity and threshold configuration")
            }
            Self::QuorumNotMet { .. } => {
                Some("Too few witnesses returned a valid, verifiable receipt for this event")
            }
            Self::Storage(_) => Some("Check storage backend permissions"),
            Self::Runtime(_) => None,
        }
    }
}

/// Collect witness receipts for an event and store the verified ones in Git.
///
/// Builds `(witness_aid, HttpAsyncWitnessClient)` pairs from the config and runs the
/// `ReceiptCollector`, which verifies each receipt against its pinned witness key at
/// the auths-core chokepoint before returning it; survivors are persisted via
/// `GitReceiptStorage`.
///
/// Respects `WitnessPolicy`:
/// - **Enforce**: collection failure, or too few *verified* receipts, is a hard error
/// - **Warn**: logs a warning and continues (storing whatever verified)
/// - **Skip**: returns `Ok(vec![])` immediately
///
/// Args:
/// * `repo_path`: Path to the Git repository holding the receipt refs.
/// * `prefix`: Controller AID whose event is being receipted.
/// * `event_said`: SAID of the just-authored event the receipts must reference.
/// * `event_json`: Canonical bytes of the event to submit to witnesses.
/// * `config`: The identity's pinned witness set, threshold, and policy.
/// * `now`: Injected timestamp for the storage commit.
///
/// Usage:
/// ```ignore
/// let stored = collect_and_store_receipts(repo, &prefix, &said, &bytes, &config, now)?;
/// ```
pub fn collect_and_store_receipts(
    repo_path: &Path,
    prefix: &Prefix,
    event_said: &Said,
    event_json: &[u8],
    config: &WitnessConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<StoredReceipt>, WitnessIntegrationError> {
    // Skip policy → return early
    if config.policy == WitnessPolicy::Skip || !config.is_enabled() {
        return Ok(vec![]);
    }

    // Build (witness_aid, client) pairs. Attribution is free — the config already
    // pins each witness's AID — so no extra `/health` round-trip is needed.
    let witnesses: Vec<(Prefix, Arc<dyn AsyncWitnessProvider>)> = config
        .witnesses
        .iter()
        .map(|w| {
            let client = HttpAsyncWitnessClient::new(w.url.to_string(), config.threshold)
                .with_timeout(std::time::Duration::from_millis(config.timeout_ms));
            (
                w.aid.clone(),
                Arc::new(client) as Arc<dyn AsyncWitnessProvider>,
            )
        })
        .collect();

    let collector = ReceiptCollector::new(witnesses, config.threshold, config.timeout_ms);

    let result = {
        let prefix_newtype = Prefix::new_unchecked(prefix.as_str().to_string());
        let event_json = event_json.to_vec();
        let rt = shared_runtime();
        rt.block_on(async {
            collector
                .collect(&prefix_newtype, event_said, &event_json)
                .await
        })
    };

    match result {
        Ok(collected) => {
            // `collect` already verified every receipt at the auths-core chokepoint;
            // unwrap the `VerifiedReceipt`s to their storable form.
            let valid: Vec<StoredReceipt> = collected
                .into_iter()
                .map(VerifiedReceipt::into_stored)
                .collect();

            if valid.len() < config.threshold {
                match config.policy {
                    WitnessPolicy::Enforce => {
                        return Err(WitnessIntegrationError::QuorumNotMet {
                            required: config.threshold,
                            valid: valid.len(),
                        });
                    }
                    WitnessPolicy::Warn => {
                        log::warn!(
                            "Witness quorum not met after verification (policy=Warn): {} valid, need {}",
                            valid.len(),
                            config.threshold,
                        );
                    }
                    WitnessPolicy::Skip => {} // unreachable: Skip returns early
                }
            }

            // Persist the verified receipts (deduped by witness AID).
            let storage = GitReceiptStorage::new(repo_path);
            let event_receipts = EventReceipts::new(event_said.as_str(), valid);
            storage
                .store_receipts(prefix, &event_receipts, now)
                .map_err(WitnessIntegrationError::Storage)?;

            log::info!(
                "Stored {} verified witness receipt(s) for event {} (prefix {})",
                event_receipts.count(),
                event_said.as_str(),
                prefix.as_str(),
            );
            Ok(event_receipts.receipts)
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

// Receipt verification (signature, pinned-key, wrong-event drops) lives at the
// single auths-core chokepoint `verify_receipt`, exercised by `collect`. It is
// unit-tested in `auths-core::witness::verify`; this module only orchestrates.
