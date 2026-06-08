//! Receipt collection from multiple witnesses.
//!
//! This module provides the `ReceiptCollector` which coordinates receipt
//! collection from multiple witnesses in parallel, enforcing threshold
//! requirements for security.
//!
//! # Threshold Semantics
//!
//! KERI uses k-of-n witness thresholds:
//! - n = total number of witnesses
//! - k = minimum receipts required (threshold)
//!
//! For example, with 3 witnesses and threshold 2:
//! - Need at least 2 receipts to succeed
//! - Can tolerate 1 witness being unavailable
//!
//! # Parallel Collection
//!
//! Receipts are collected in parallel for efficiency. The collector
//! returns as soon as the threshold is met, or waits for all witnesses
//! if the threshold cannot be met.

use std::sync::Arc;

use auths_keri::{Prefix, Said};
use tokio::time::{Duration, timeout};

use super::async_provider::AsyncWitnessProvider;
use super::error::{DuplicityEvidence, WitnessError};
use super::receipt::StoredReceipt;
use super::verify::{VerifiedReceipt, verify_receipt};

/// Error during receipt collection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CollectionError {
    /// Duplicity detected during collection.
    #[error("duplicity detected: {0}")]
    Duplicity(DuplicityEvidence),

    /// Threshold not met - insufficient receipts collected.
    #[error("threshold not met: got {got} receipts, need {required}")]
    ThresholdNotMet {
        /// Number of receipts successfully collected
        got: usize,
        /// Number of receipts required
        required: usize,
        /// Errors from failed witness requests
        errors: Vec<(String, WitnessError)>,
    },

    /// All witnesses failed.
    #[error("all witnesses failed")]
    AllFailed {
        /// Errors from each witness
        errors: Vec<(String, WitnessError)>,
    },

    /// No witnesses configured.
    #[error("no witnesses configured")]
    NoWitnesses,
}

/// Collects receipts from multiple witnesses.
///
/// The collector queries witnesses in parallel and returns when either:
/// - Threshold receipts have been collected (success)
/// - Duplicity is detected (error)
/// - Not enough witnesses respond successfully (error)
///
/// Each witness is pinned to its CESR verkey AID. `collect` returns only
/// [`VerifiedReceipt`]s — receipts whose signatures verify against that pinned
/// AID for the submitted event — so forged or wrong-event receipts can never
/// reach the threshold.
///
/// # Example
///
/// ```rust,ignore
/// use auths_core::witness::{ReceiptCollector, VerifiedReceipt};
///
/// let witnesses: Vec<(Prefix, Arc<dyn AsyncWitnessProvider>)> = pinned_witnesses();
/// let collector = ReceiptCollector::new(witnesses, 2, 5000);
///
/// let receipts: Vec<VerifiedReceipt> =
///     collector.collect(&prefix, &event_said, &event_json).await?;
/// assert!(receipts.len() >= 2);
/// ```
pub struct ReceiptCollector {
    /// Witnesses to query, each paired with its pinned AID so collected
    /// receipts can be attributed without an extra `/health` round-trip.
    witnesses: Vec<(Prefix, Arc<dyn AsyncWitnessProvider>)>,
    /// Minimum receipts required
    threshold: usize,
    /// Timeout per witness in milliseconds
    timeout_ms: u64,
}

impl ReceiptCollector {
    /// Create a new receipt collector.
    ///
    /// # Arguments
    ///
    /// * `witnesses` - Witnesses to query, each as a `(witness_aid, provider)`
    ///   pair. The AID is the witness's pinned CESR verkey prefix; each collected
    ///   receipt's signature is verified against it before it counts toward quorum.
    /// * `threshold` - Minimum number of receipts required
    /// * `timeout_ms` - Timeout per witness operation in milliseconds
    pub fn new(
        witnesses: Vec<(Prefix, Arc<dyn AsyncWitnessProvider>)>,
        threshold: usize,
        timeout_ms: u64,
    ) -> Self {
        Self {
            witnesses,
            threshold,
            timeout_ms,
        }
    }

    /// Get the number of witnesses.
    pub fn witness_count(&self) -> usize {
        self.witnesses.len()
    }

    /// Get the threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Collect receipts from witnesses.
    ///
    /// Queries all witnesses in parallel and returns when threshold is met
    /// or all witnesses have responded.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI prefix of the identity
    /// * `event_said` - SAID of the event being receipted; every counted receipt
    ///   must reference exactly this event
    /// * `event_json` - The canonicalized JSON bytes of the event
    ///
    /// # Returns
    ///
    /// * `Ok(receipts)` - At least `threshold` *verified* receipts, each carrying
    ///   the AID of the witness that produced it
    /// * `Err(CollectionError::Duplicity(_))` - A witness reported duplicity
    /// * `Err(CollectionError::ThresholdNotMet { .. })` - Too few verified receipts
    pub async fn collect(
        &self,
        prefix: &Prefix,
        event_said: &Said,
        event_json: &[u8],
    ) -> Result<Vec<VerifiedReceipt>, CollectionError> {
        if self.witnesses.is_empty() {
            return Err(CollectionError::NoWitnesses);
        }

        // Spawn tasks for all witnesses
        let mut handles = Vec::with_capacity(self.witnesses.len());
        let timeout_duration = Duration::from_millis(self.timeout_ms);

        for (idx, (aid, witness)) in self.witnesses.iter().enumerate() {
            let witness = Arc::clone(witness);
            let aid = aid.clone();
            let prefix = prefix.clone();
            let event_json = event_json.to_vec();

            let handle = tokio::spawn(async move {
                let result =
                    timeout(timeout_duration, witness.submit_event(&prefix, &event_json)).await;

                match result {
                    Ok(Ok(signed)) => Ok((
                        idx,
                        StoredReceipt {
                            signed,
                            witness: aid,
                        },
                    )),
                    Ok(Err(e)) => Err((idx, e)),
                    Err(_) => Err((
                        idx,
                        WitnessError::Timeout(timeout_duration.as_millis() as u64),
                    )),
                }
            });

            handles.push(handle);
        }

        // Collect results, verifying each receipt before it can count.
        let mut receipts: Vec<VerifiedReceipt> = Vec::new();
        let mut errors: Vec<(String, WitnessError)> = Vec::new();

        for handle in handles {
            match handle.await {
                Ok(Ok((idx, stored))) => match verify_receipt(stored, event_said) {
                    Ok(verified) => receipts.push(verified),
                    // Forged, foreign-key, or wrong-event receipts are dropped
                    // here — never counted toward the threshold.
                    Err(e) => errors.push((format!("witness_{idx}"), e)),
                },
                Ok(Err((idx, e))) => {
                    // A witness that itself reports duplicity is a hard stop.
                    if let WitnessError::Duplicity(evidence) = e {
                        return Err(CollectionError::Duplicity(evidence));
                    }
                    errors.push((format!("witness_{}", idx), e));
                }
                Err(join_err) => {
                    errors.push((
                        "unknown".to_string(),
                        WitnessError::Network(format!("task join error: {}", join_err)),
                    ));
                }
            }
        }

        // Check if we met the threshold
        if receipts.len() >= self.threshold {
            Ok(receipts)
        } else if receipts.is_empty() && !errors.is_empty() {
            Err(CollectionError::AllFailed { errors })
        } else {
            Err(CollectionError::ThresholdNotMet {
                got: receipts.len(),
                required: self.threshold,
                errors,
            })
        }
    }
}

/// Builder for ReceiptCollector.
#[derive(Default)]
pub struct ReceiptCollectorBuilder {
    witnesses: Vec<(Prefix, Arc<dyn AsyncWitnessProvider>)>,
    threshold: Option<usize>,
    timeout_ms: Option<u64>,
}

impl std::fmt::Debug for ReceiptCollectorBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptCollectorBuilder")
            .field("witnesses_count", &self.witnesses.len())
            .field("threshold", &self.threshold)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl ReceiptCollectorBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a witness paired with its pinned AID.
    pub fn witness(mut self, aid: Prefix, witness: Arc<dyn AsyncWitnessProvider>) -> Self {
        self.witnesses.push((aid, witness));
        self
    }

    /// Add multiple `(witness_aid, provider)` pairs.
    pub fn witnesses(
        mut self,
        witnesses: impl IntoIterator<Item = (Prefix, Arc<dyn AsyncWitnessProvider>)>,
    ) -> Self {
        self.witnesses.extend(witnesses);
        self
    }

    /// Set the threshold.
    pub fn threshold(mut self, threshold: usize) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Set the timeout in milliseconds.
    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    /// Build the collector.
    ///
    /// Uses default timeout of 5000ms if not specified.
    /// Threshold defaults to 1 if not specified.
    pub fn build(self) -> ReceiptCollector {
        ReceiptCollector {
            witnesses: self.witnesses,
            threshold: self.threshold.unwrap_or(1),
            timeout_ms: self.timeout_ms.unwrap_or(5000),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::witness::NoOpAsyncWitness;
    use async_trait::async_trait;
    use auths_keri::KeriPublicKey;
    use auths_keri::witness::{EventHash, Receipt, ReceiptTag, SignedReceipt};
    use auths_keri::{KeriSequence, VersionString};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const EVENT_SAID: &str = "EEvent00000000000000000000000000000000000000";
    const OTHER_SAID: &str = "EOther00000000000000000000000000000000000000";

    fn event_said() -> Said {
        Said::new_unchecked(EVENT_SAID.to_string())
    }

    /// A fresh Ed25519 keypair and its CESR `D…` verkey AID.
    fn keypair_and_aid() -> (Arc<Ed25519KeyPair>, Prefix) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let aid = KeriPublicKey::ed25519(kp.public_key().as_ref())
            .unwrap()
            .to_qb64()
            .unwrap();
        (Arc::new(kp), Prefix::new_unchecked(aid))
    }

    /// A witness that signs a receipt for `said` with `kp` on every submission.
    struct SigningWitness {
        kp: Arc<Ed25519KeyPair>,
        said: Said,
    }

    #[async_trait]
    impl AsyncWitnessProvider for SigningWitness {
        async fn submit_event(
            &self,
            prefix: &Prefix,
            _event_json: &[u8],
        ) -> Result<SignedReceipt, WitnessError> {
            let receipt = Receipt {
                v: VersionString::placeholder(),
                t: ReceiptTag,
                d: self.said.clone(),
                i: prefix.clone(),
                s: KeriSequence::new(0),
            };
            let payload = serde_json::to_vec(&receipt)
                .map_err(|e| WitnessError::Serialization(e.to_string()))?;
            let signature = self.kp.sign(&payload).as_ref().to_vec();
            Ok(SignedReceipt { receipt, signature })
        }

        async fn observe_identity_head(
            &self,
            _prefix: &Prefix,
        ) -> Result<Option<EventHash>, WitnessError> {
            Ok(None)
        }

        async fn get_receipt(
            &self,
            _prefix: &Prefix,
            _event_said: &Said,
        ) -> Result<Option<Receipt>, WitnessError> {
            Ok(None)
        }

        fn quorum(&self) -> usize {
            0
        }
    }

    fn witness_pair(
        kp: Arc<Ed25519KeyPair>,
        aid: Prefix,
        said: Said,
    ) -> (Prefix, Arc<dyn AsyncWitnessProvider>) {
        (
            aid,
            Arc::new(SigningWitness { kp, said }) as Arc<dyn AsyncWitnessProvider>,
        )
    }

    /// An honest witness: signs the expected event with the key its AID pins.
    fn honest() -> (Prefix, Arc<dyn AsyncWitnessProvider>) {
        let (kp, aid) = keypair_and_aid();
        witness_pair(kp, aid, event_said())
    }

    /// A witness pinned to one AID but signing with a *different* key (forged).
    fn forged() -> (Prefix, Arc<dyn AsyncWitnessProvider>) {
        let (signing_kp, _signing_aid) = keypair_and_aid();
        let (_pinned_kp, pinned_aid) = keypair_and_aid();
        witness_pair(signing_kp, pinned_aid, event_said())
    }

    #[tokio::test]
    async fn verified_receipts_reach_quorum() {
        let collector = ReceiptCollector::new(vec![honest(), honest(), honest()], 2, 5000);
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let receipts = collector
            .collect(&prefix, &event_said(), b"{}")
            .await
            .unwrap();

        assert!(receipts.len() >= 2);
        assert!(receipts.iter().all(|r| !r.witness.as_str().is_empty()));
    }

    #[tokio::test]
    async fn forged_receipt_does_not_count() {
        // Two honest + one forged; threshold 2 succeeds with only the honest two.
        let collector = ReceiptCollector::new(vec![honest(), honest(), forged()], 2, 5000);
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let receipts = collector
            .collect(&prefix, &event_said(), b"{}")
            .await
            .unwrap();

        assert_eq!(receipts.len(), 2, "forged receipt must be dropped");
    }

    #[tokio::test]
    async fn forged_receipt_drops_below_threshold() {
        // One honest + one forged, threshold 2: only 1 verifies → not met.
        let collector = ReceiptCollector::new(vec![honest(), forged()], 2, 5000);
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let result = collector.collect(&prefix, &event_said(), b"{}").await;

        assert!(matches!(
            result,
            Err(CollectionError::ThresholdNotMet {
                got: 1,
                required: 2,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn wrong_said_receipt_dropped() {
        let (kp, aid) = keypair_and_aid();
        let wrong = witness_pair(kp, aid, Said::new_unchecked(OTHER_SAID.to_string()));
        let collector = ReceiptCollector::new(vec![honest(), wrong], 2, 5000);
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let result = collector.collect(&prefix, &event_said(), b"{}").await;

        assert!(matches!(
            result,
            Err(CollectionError::ThresholdNotMet { got: 1, .. })
        ));
    }

    #[tokio::test]
    async fn no_witnesses_error() {
        let collector = ReceiptCollector::new(vec![], 1, 5000);
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let result = collector.collect(&prefix, &event_said(), b"{}").await;

        assert!(matches!(result, Err(CollectionError::NoWitnesses)));
    }

    #[tokio::test]
    async fn builder_pattern() {
        let (_, aid0) = keypair_and_aid();
        let (_, aid1) = keypair_and_aid();
        let collector = ReceiptCollectorBuilder::new()
            .witness(aid0, Arc::new(NoOpAsyncWitness))
            .witness(aid1, Arc::new(NoOpAsyncWitness))
            .threshold(2)
            .timeout_ms(1000)
            .build();

        assert_eq!(collector.witness_count(), 2);
        assert_eq!(collector.threshold(), 2);
    }

    #[test]
    fn collection_error_display() {
        let err = CollectionError::ThresholdNotMet {
            got: 1,
            required: 2,
            errors: vec![],
        };
        assert!(format!("{}", err).contains("threshold not met"));

        let err = CollectionError::NoWitnesses;
        assert!(format!("{}", err).contains("no witnesses"));
    }
}
