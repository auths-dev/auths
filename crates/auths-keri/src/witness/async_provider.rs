//! Async witness provider trait for network-based witness operations.
//!
//! This module defines the async version of the witness provider trait,
//! designed for network-based witness interactions that require async I/O.
//!
//! # Design Rationale
//!
//! The sync [`WitnessProvider`] trait is preserved for backward compatibility
//! and for use cases where blocking is acceptable (e.g., local caching).
//! This async trait is designed for:
//!
//! - HTTP-based witness servers
//! - Network I/O with configurable timeouts
//! - Parallel receipt collection from multiple witnesses
//!
//! # Example
//!
//! ```rust,ignore
//! use auths_keri::witness::{AsyncWitnessProvider, Receipt, WitnessError, EventHash};
//! use auths_keri::{Prefix, Said};
//! use async_trait::async_trait;
//!
//! struct HttpWitness {
//!     base_url: String,
//!     timeout_ms: u64,
//! }
//!
//! #[async_trait]
//! impl AsyncWitnessProvider for HttpWitness {
//!     async fn submit_event(&self, prefix: &Prefix, event_json: &[u8]) -> Result<Receipt, WitnessError> {
//!         todo!()
//!     }
//!
//!     async fn observe_identity_head(&self, prefix: &Prefix) -> Result<Option<EventHash>, WitnessError> {
//!         todo!()
//!     }
//!
//!     async fn get_receipt(&self, prefix: &Prefix, event_said: &Said) -> Result<Option<Receipt>, WitnessError> {
//!         todo!()
//!     }
//! }
//! ```

use crate::{Prefix, Said};
use async_trait::async_trait;

use super::error::WitnessError;
use super::hash::EventHash;
use super::receipt::Receipt;

/// Async witness provider for network-based witness operations.
///
/// This trait defines the interface for interacting with witness servers
/// asynchronously. Implementations typically communicate over HTTP with
/// witness infrastructure.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow use in async contexts
/// across multiple tasks.
///
/// # Error Handling
///
/// All methods return `Result<T, WitnessError>` to enable proper error
/// propagation and handling of network failures, timeouts, and security
/// violations (like duplicity detection).
#[async_trait]
pub trait AsyncWitnessProvider: Send + Sync {
    /// Submit an event to the witness for receipting.
    ///
    /// The witness will:
    /// 1. Parse and validate the event
    /// 2. Check for duplicity (same prefix+seq with different SAID)
    /// 3. If valid and not duplicate, sign and return a receipt
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI prefix of the identity
    /// * `event_json` - The canonicalized JSON bytes of the event
    ///
    /// # Returns
    ///
    /// * `Ok(Receipt)` - The witness accepted the event and issued a receipt
    /// * `Err(WitnessError::Duplicity(_))` - Duplicity detected (split-view attack)
    /// * `Err(WitnessError::Rejected { .. })` - Event rejected (invalid format, etc.)
    /// * `Err(WitnessError::Network(_))` - Network error
    /// * `Err(WitnessError::Timeout(_))` - Operation timed out
    async fn submit_event(
        &self,
        prefix: &Prefix,
        event_json: &[u8],
    ) -> Result<Receipt, WitnessError>;

    /// Query the current observed head for an identity.
    ///
    /// Returns the hash of the most recent event the witness has observed
    /// for the given identity prefix.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI prefix of the identity
    ///
    /// # Returns
    ///
    /// * `Ok(Some(hash))` - The witness has an observed head for this identity
    /// * `Ok(None)` - The witness has not observed any events for this identity
    /// * `Err(_)` - Error during query
    async fn observe_identity_head(
        &self,
        prefix: &Prefix,
    ) -> Result<Option<EventHash>, WitnessError>;

    /// Retrieve a previously issued receipt.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI prefix of the identity
    /// * `event_said` - The SAID of the event to get the receipt for
    ///
    /// # Returns
    ///
    /// * `Ok(Some(receipt))` - Receipt found
    /// * `Ok(None)` - No receipt found for this event
    /// * `Err(_)` - Error during retrieval
    async fn get_receipt(
        &self,
        prefix: &Prefix,
        event_said: &Said,
    ) -> Result<Option<Receipt>, WitnessError>;

    /// Get the minimum quorum required for consistency.
    ///
    /// When using a multi-witness setup, this specifies how many witnesses
    /// must agree for the event to be considered properly witnessed.
    ///
    /// # Default
    ///
    /// Returns `1` (single witness is sufficient).
    fn quorum(&self) -> usize {
        1
    }

    /// Get the timeout for operations in milliseconds.
    ///
    /// # Default
    ///
    /// Returns `5000` (5 seconds).
    fn timeout_ms(&self) -> u64 {
        5000
    }

    /// Check if this provider is currently available.
    ///
    /// # Default
    ///
    /// Returns `Ok(true)`. Implementations may override to perform actual
    /// health checks.
    async fn is_available(&self) -> Result<bool, WitnessError> {
        Ok(true)
    }
}

/// A no-op async witness provider that always succeeds without doing anything.
///
/// This is useful for testing or when witness functionality is disabled.
#[derive(Debug, Clone, Default)]
pub struct NoOpAsyncWitness;

#[async_trait]
impl AsyncWitnessProvider for NoOpAsyncWitness {
    async fn submit_event(
        &self,
        _prefix: &Prefix,
        _event_json: &[u8],
    ) -> Result<Receipt, WitnessError> {
        Ok(Receipt {
            v: crate::VersionString::placeholder(),
            t: super::receipt::RECEIPT_TYPE.into(),
            d: Said::new_unchecked("ENoop".into()),
            i: Prefix::new_unchecked("did:key:noop".into()),
            s: crate::KeriSequence::new(0),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_witness_submit_returns_dummy_receipt() {
        let witness = NoOpAsyncWitness;
        let prefix = Prefix::new_unchecked("ETest".into());
        let receipt = witness.submit_event(&prefix, b"{}").await.unwrap();
        assert_eq!(receipt.t, "rct");
    }

    #[tokio::test]
    async fn noop_witness_observe_returns_none() {
        let witness = NoOpAsyncWitness;
        let prefix = Prefix::new_unchecked("ETest".into());
        let head = witness.observe_identity_head(&prefix).await.unwrap();
        assert!(head.is_none());
    }

    #[tokio::test]
    async fn noop_witness_get_receipt_returns_none() {
        let witness = NoOpAsyncWitness;
        let prefix = Prefix::new_unchecked("ETest".into());
        let said = Said::new_unchecked("ESAID".into());
        let receipt = witness.get_receipt(&prefix, &said).await.unwrap();
        assert!(receipt.is_none());
    }

    #[tokio::test]
    async fn noop_witness_quorum_is_zero() {
        let witness = NoOpAsyncWitness;
        assert_eq!(witness.quorum(), 0);
    }

    #[tokio::test]
    async fn noop_witness_is_available() {
        let witness = NoOpAsyncWitness;
        assert!(witness.is_available().await.unwrap());
    }

    #[test]
    fn default_timeout() {
        let witness = NoOpAsyncWitness;
        assert_eq!(witness.timeout_ms(), 5000);
    }
}
