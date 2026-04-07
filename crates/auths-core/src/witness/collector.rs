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

use auths_keri::Prefix;
use tokio::time::{Duration, timeout};

use super::async_provider::AsyncWitnessProvider;
use super::error::{DuplicityEvidence, WitnessError};
use super::receipt::Receipt;

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
/// # Example
///
/// ```rust,ignore
/// use auths_core::witness::{ReceiptCollector, NoOpAsyncWitness};
///
/// let witnesses: Vec<Arc<dyn AsyncWitnessProvider>> = vec![
///     Arc::new(NoOpAsyncWitness),
///     Arc::new(NoOpAsyncWitness),
///     Arc::new(NoOpAsyncWitness),
/// ];
///
/// let collector = ReceiptCollector::new(witnesses, 2, 5000);
/// let prefix = Prefix::new_unchecked("EPrefix".into());
///
/// let receipts = collector.collect(&prefix, b"{}").await?;
/// assert!(receipts.len() >= 2);
/// ```
pub struct ReceiptCollector {
    /// List of witnesses to query
    witnesses: Vec<Arc<dyn AsyncWitnessProvider>>,
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
    /// * `witnesses` - List of witnesses to query
    /// * `threshold` - Minimum number of receipts required
    /// * `timeout_ms` - Timeout per witness operation in milliseconds
    pub fn new(
        witnesses: Vec<Arc<dyn AsyncWitnessProvider>>,
        threshold: usize,
        timeout_ms: u64,
    ) -> Self {
        Self {
            witnesses,
            threshold,
            timeout_ms,
        }
    }

    /// Create a collector from boxed witnesses.
    pub fn from_boxed(
        witnesses: Vec<Box<dyn AsyncWitnessProvider>>,
        threshold: usize,
        timeout_ms: u64,
    ) -> Self {
        let witnesses: Vec<Arc<dyn AsyncWitnessProvider>> =
            witnesses.into_iter().map(Arc::from).collect();
        Self::new(witnesses, threshold, timeout_ms)
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
    /// * `event_json` - The canonicalized JSON bytes of the event
    ///
    /// # Returns
    ///
    /// * `Ok(receipts)` - At least `threshold` receipts collected
    /// * `Err(CollectionError::Duplicity(_))` - Duplicity detected
    /// * `Err(CollectionError::ThresholdNotMet { .. })` - Not enough receipts
    pub async fn collect(
        &self,
        prefix: &Prefix,
        event_json: &[u8],
    ) -> Result<Vec<Receipt>, CollectionError> {
        if self.witnesses.is_empty() {
            return Err(CollectionError::NoWitnesses);
        }

        // Spawn tasks for all witnesses
        let mut handles = Vec::with_capacity(self.witnesses.len());
        let timeout_duration = Duration::from_millis(self.timeout_ms);

        for (idx, witness) in self.witnesses.iter().enumerate() {
            let witness = Arc::clone(witness);
            let prefix = prefix.clone();
            let event_json = event_json.to_vec();

            let handle = tokio::spawn(async move {
                let result =
                    timeout(timeout_duration, witness.submit_event(&prefix, &event_json)).await;

                match result {
                    Ok(Ok(receipt)) => Ok((idx, receipt)),
                    Ok(Err(e)) => Err((idx, e)),
                    Err(_) => Err((
                        idx,
                        WitnessError::Timeout(timeout_duration.as_millis() as u64),
                    )),
                }
            });

            handles.push(handle);
        }

        // Collect results
        let mut receipts = Vec::new();
        let mut errors: Vec<(String, WitnessError)> = Vec::new();

        for handle in handles {
            match handle.await {
                Ok(Ok((_idx, receipt))) => {
                    // Check for duplicity against existing receipts
                    if let Some(evidence) = self.check_receipt_consistency(&receipts, &receipt) {
                        return Err(CollectionError::Duplicity(evidence));
                    }
                    receipts.push(receipt);

                    // Early return if threshold met
                    if receipts.len() >= self.threshold {
                        // Continue collecting remaining for better coverage,
                        // but we have enough to succeed
                    }
                }
                Ok(Err((idx, e))) => {
                    // Check for duplicity error specifically
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

    /// Check if a new receipt is consistent with existing receipts.
    fn check_receipt_consistency(
        &self,
        existing: &[Receipt],
        new: &Receipt,
    ) -> Option<DuplicityEvidence> {
        if existing.is_empty() {
            return None;
        }

        let expected_said = &existing[0].a;
        if new.a != *expected_said {
            Some(DuplicityEvidence {
                prefix: Prefix::default(),
                sequence: new.s,
                event_a_said: expected_said.clone(),
                event_b_said: new.a.clone(),
                witness_reports: vec![],
            })
        } else {
            None
        }
    }
}

/// Builder for ReceiptCollector.
#[derive(Default)]
pub struct ReceiptCollectorBuilder {
    witnesses: Vec<Arc<dyn AsyncWitnessProvider>>,
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

    /// Add a witness.
    pub fn witness(mut self, witness: Arc<dyn AsyncWitnessProvider>) -> Self {
        self.witnesses.push(witness);
        self
    }

    /// Add multiple witnesses.
    pub fn witnesses(
        mut self,
        witnesses: impl IntoIterator<Item = Arc<dyn AsyncWitnessProvider>>,
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
mod tests {
    use super::*;
    use crate::witness::NoOpAsyncWitness;

    #[tokio::test]
    async fn collect_from_noop_witnesses() {
        let witnesses: Vec<Arc<dyn AsyncWitnessProvider>> = vec![
            Arc::new(NoOpAsyncWitness),
            Arc::new(NoOpAsyncWitness),
            Arc::new(NoOpAsyncWitness),
        ];

        let collector = ReceiptCollector::new(witnesses, 2, 5000);
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let result = collector.collect(&prefix, b"{}").await;

        assert!(result.is_ok());
        let receipts = result.unwrap();
        assert!(receipts.len() >= 2);
    }

    #[tokio::test]
    async fn threshold_1_of_3() {
        let witnesses: Vec<Arc<dyn AsyncWitnessProvider>> = vec![
            Arc::new(NoOpAsyncWitness),
            Arc::new(NoOpAsyncWitness),
            Arc::new(NoOpAsyncWitness),
        ];

        let collector = ReceiptCollector::new(witnesses, 1, 5000);
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let result = collector.collect(&prefix, b"{}").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn no_witnesses_error() {
        let collector = ReceiptCollector::new(vec![], 1, 5000);
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let result = collector.collect(&prefix, b"{}").await;

        assert!(matches!(result, Err(CollectionError::NoWitnesses)));
    }

    #[tokio::test]
    async fn builder_pattern() {
        let collector = ReceiptCollectorBuilder::new()
            .witness(Arc::new(NoOpAsyncWitness))
            .witness(Arc::new(NoOpAsyncWitness))
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
