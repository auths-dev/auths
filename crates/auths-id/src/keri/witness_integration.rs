//! Witness receipt collection and storage after KEL events.
//!
//! This module ties together:
//! - `HttpAsyncWitnessClient` (auths-infra-http) for talking to witness servers
//! - `ReceiptCollector` (auths-core) for parallel k-of-n collection
//! - `GitReceiptStorage` (auths-id) for persisting receipts in Git
//!
//! Collected receipts are **verified against their pinned witness key** before
//! storage: a forged signature, a receipt attributed to a witness not in the
//! configured set, or a receipt for an event other than the one just authored is
//! dropped and never counts toward quorum.
//!
//! Feature-gated behind `witness-client`.

use std::path::Path;
use std::sync::Arc;

use auths_core::witness::{AsyncWitnessProvider, CollectionError, ReceiptCollector, StoredReceipt};
use auths_infra_http::HttpAsyncWitnessClient;
use auths_keri::KeriPublicKey;

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
/// Builds `(witness_aid, HttpAsyncWitnessClient)` pairs from the config, runs the
/// `ReceiptCollector`, verifies each collected receipt against its pinned witness
/// key, and persists the survivors via `GitReceiptStorage`.
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
        rt.block_on(async { collector.collect(&prefix_newtype, &event_json).await })
    };

    match result {
        Ok(collected) => {
            // Drop forged / foreign / wrong-event receipts before they can reach
            // storage or count toward quorum.
            let valid = verify_collected_receipts(collected, event_said, config);

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

/// Keep only the receipts that are cryptographically attributable to a configured
/// witness for *this* event.
///
/// A receipt is dropped unless all three hold:
/// 1. its witness AID is in the configured set (`config.contains_aid`),
/// 2. its body's `d` equals the authored `event_said`, and
/// 3. its signature verifies against the witness's pinned (curve-tagged) key.
fn verify_collected_receipts(
    collected: Vec<StoredReceipt>,
    event_said: &Said,
    config: &WitnessConfig,
) -> Vec<StoredReceipt> {
    collected
        .into_iter()
        .filter(|stored| receipt_is_attributable(stored, event_said, config))
        .collect()
}

/// Whether a single collected receipt is a valid, in-set attestation of `event_said`.
fn receipt_is_attributable(
    stored: &StoredReceipt,
    event_said: &Said,
    config: &WitnessConfig,
) -> bool {
    if !config.contains_aid(&stored.witness) {
        return false;
    }
    if stored.signed.receipt.d.as_str() != event_said.as_str() {
        return false;
    }
    let Ok(key) = KeriPublicKey::parse(stored.witness.as_str()) else {
        return false;
    };
    let Ok(payload) = serde_json::to_vec(&stored.signed.receipt) else {
        return false;
    };
    key.verify_signature(&payload, &stored.signed.signature)
        .is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use auths_core::witness::{Receipt, ReceiptTag, SignedReceipt};
    use auths_keri::{KeriSequence, VersionString};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use url::Url;

    /// A fresh Ed25519 witness keypair and its CESR AID (`D…` prefix).
    fn witness_keypair() -> (Ed25519KeyPair, Prefix) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let aid = KeriPublicKey::ed25519(kp.public_key().as_ref())
            .unwrap()
            .to_qb64()
            .unwrap();
        (kp, Prefix::new_unchecked(aid))
    }

    /// A receipt for `event_said` signed by `kp`.
    fn signed_for(kp: &Ed25519KeyPair, event_said: &str) -> SignedReceipt {
        let receipt = Receipt {
            v: VersionString::placeholder(),
            t: ReceiptTag,
            d: Said::new_unchecked(event_said.to_string()),
            i: Prefix::new_unchecked("EController00000000000000000000000000000000".to_string()),
            s: KeriSequence::new(0),
        };
        let payload = serde_json::to_vec(&receipt).unwrap();
        let signature = kp.sign(&payload).as_ref().to_vec();
        SignedReceipt { receipt, signature }
    }

    /// A one-witness config pinning `aid` with threshold 1.
    fn config_pinning(aid: &Prefix) -> WitnessConfig {
        WitnessConfig {
            witnesses: vec![crate::witness_config::WitnessRef {
                url: Url::parse("http://witness:3333").unwrap(),
                aid: aid.clone(),
            }],
            threshold: 1,
            timeout_ms: 5000,
            policy: WitnessPolicy::Enforce,
            ..Default::default()
        }
    }

    #[test]
    fn stored_receipt_carries_witness_aid() {
        let (kp, aid) = witness_keypair();
        let stored = StoredReceipt {
            signed: signed_for(&kp, "EEvent000000000000000000000000000000000000"),
            witness: aid.clone(),
        };
        let said = Said::new_unchecked("EEvent000000000000000000000000000000000000".to_string());

        let valid = verify_collected_receipts(vec![stored], &said, &config_pinning(&aid));

        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].witness, aid);
    }

    #[test]
    fn receipt_signature_rejected_when_forged() {
        let (kp, aid) = witness_keypair();
        let mut stored = StoredReceipt {
            signed: signed_for(&kp, "EEvent000000000000000000000000000000000000"),
            witness: aid.clone(),
        };
        stored.signed.signature = vec![0u8; 64]; // forged
        let said = Said::new_unchecked("EEvent000000000000000000000000000000000000".to_string());

        let valid = verify_collected_receipts(vec![stored], &said, &config_pinning(&aid));

        assert!(valid.is_empty());
    }

    #[test]
    fn receipt_from_unconfigured_witness_ignored() {
        let (kp, aid) = witness_keypair();
        let (_other_kp, other_aid) = witness_keypair();
        // Signature is genuine, but the witness is not the one the config pins.
        let stored = StoredReceipt {
            signed: signed_for(&kp, "EEvent000000000000000000000000000000000000"),
            witness: aid,
        };
        let said = Said::new_unchecked("EEvent000000000000000000000000000000000000".to_string());

        let valid = verify_collected_receipts(vec![stored], &said, &config_pinning(&other_aid));

        assert!(valid.is_empty());
    }

    #[test]
    fn receipt_for_wrong_said_ignored() {
        let (kp, aid) = witness_keypair();
        // Genuinely signed, in-set witness — but receipts a different event.
        let stored = StoredReceipt {
            signed: signed_for(&kp, "EOtherEvent00000000000000000000000000000000"),
            witness: aid.clone(),
        };
        let said = Said::new_unchecked("EEvent000000000000000000000000000000000000".to_string());

        let valid = verify_collected_receipts(vec![stored], &said, &config_pinning(&aid));

        assert!(valid.is_empty());
    }
}
