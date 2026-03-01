mod adapter;
mod attestation_adapter;
mod config;
mod identity_adapter;
pub mod paths;
mod tree_ops;
pub mod vfs;

pub use adapter::GitRegistryBackend;
pub use adapter::REGISTRY_REF;
pub use attestation_adapter::RegistryAttestationStorage;
pub use config::{RegistryConfig, TenantMetadata, TenantStatus};
pub use identity_adapter::RegistryIdentityStorage;
pub use vfs::{FixedClock, OsVfs, Vfs};
