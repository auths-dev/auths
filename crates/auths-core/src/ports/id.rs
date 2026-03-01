//! ID generation port.

use uuid::Uuid;

/// Port for UUID generation, enabling injection of deterministic implementations
/// in tests and alternative ID schemes (ULIDs, Snowflake IDs) in production.
pub trait UuidProvider: Send + Sync {
    /// Generate a fresh unique identifier.
    fn new_id(&self) -> Uuid;
}

/// Production adapter that delegates to `Uuid::new_v4()`.
pub struct SystemUuidProvider;

impl UuidProvider for SystemUuidProvider {
    #[allow(clippy::disallowed_methods)]
    fn new_id(&self) -> Uuid {
        Uuid::new_v4()
    }
}
