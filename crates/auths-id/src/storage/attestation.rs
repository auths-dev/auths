use crate::error::StorageError;
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;

/// Abstracts the source and loading of device attestations from the underlying storage.
///
/// Implementations may read from Git refs, SQLite indexes, packed registries, or
/// in-memory stores. Domain logic interacts with attestation data exclusively
/// through this trait without knowledge of the backing store.
///
/// Args:
/// * `device_did`: A `DeviceDID` identifying the device whose attestations to load.
///
/// Usage:
/// ```ignore
/// use auths_id::storage::attestation::AttestationSource;
///
/// fn count_device_attestations(source: &dyn AttestationSource, did: &DeviceDID) -> usize {
///     source.load_attestations_for_device(did)
///         .map(|atts| atts.len())
///         .unwrap_or(0)
/// }
/// ```
pub trait AttestationSource {
    /// Loads all attestations found for a specific device DID using the configured layout.
    fn load_attestations_for_device(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, StorageError>;

    /// Loads all known attestations from the storage backend by discovering devices
    /// based on the configured layout.
    fn load_all_attestations(&self) -> Result<Vec<Attestation>, StorageError>;

    /// Loads attestations for a bounded page of devices.
    ///
    /// Avoids loading the entire device set at once, which can stall
    /// the thread when thousands of devices exist. `limit` controls
    /// the maximum number of devices to process, and `offset` skips
    /// that many devices from the discovered list.
    ///
    /// Args:
    /// * `limit`: Maximum number of devices to load attestations for.
    /// * `offset`: Number of devices to skip before loading.
    ///
    /// Usage:
    /// ```ignore
    /// let page = storage.load_all_attestations_paginated(100, 0)?;
    /// ```
    fn load_all_attestations_paginated(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Attestation>, StorageError> {
        let devices = self.discover_device_dids()?;
        let mut all_attestations = Vec::new();

        for device_did in devices.into_iter().skip(offset).take(limit) {
            match self.load_attestations_for_device(&device_did) {
                Ok(atts) => all_attestations.extend(atts),
                Err(e) => {
                    log::warn!(
                        "Failed to load attestations for device {}: {}",
                        device_did,
                        e
                    );
                }
            }
        }

        Ok(all_attestations)
    }

    /// Discovers device DIDs that have attestations stored based on the configured layout.
    fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, StorageError>;
}
