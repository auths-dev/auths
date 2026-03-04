use crate::error::StorageError;
use crate::identity::managed::ManagedIdentity;

/// Trait for abstracting the storage and retrieval of identity information.
///
/// Implementations handle the underlying storage mechanism (e.g., Git repository)
/// and use a `StorageLayoutConfig` to determine specific paths and filenames.
pub trait IdentityStorage {
    /// Creates or updates the identity reference (defined in config) with the
    /// controller DID and optional, arbitrary metadata.
    ///
    /// The structure and interpretation of the `metadata` JSON is the responsibility
    /// of the caller. This function stores the provided `controller_did` and `metadata`
    /// generically in a blob (name defined in config).
    ///
    /// # Arguments
    /// * `controller_did`: The DID string controlling this identity.
    /// * `metadata`: Optional arbitrary JSON value representing identity metadata.
    fn create_identity(
        &self,
        controller_did: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), StorageError>;

    /// Loads the identity information (controller DID, metadata, storage ID)
    /// from the configured identity reference and blob name.
    ///
    /// Returns a `ManagedIdentity` struct containing the loaded `controller_did`,
    /// the storage identifier (e.g., repository name), and the full `metadata`
    /// field as a `serde_json::Value` for the caller to interpret.
    fn load_identity(&self) -> Result<ManagedIdentity, StorageError>;

    /// Gets the configured primary Git reference used for storing the identity commit.
    fn get_identity_ref(&self) -> Result<String, StorageError>;
}
