mod adapter;
pub mod approval;
mod attestation_adapter;
mod config;
mod identity_adapter;
pub mod oobi;
pub mod paths;
pub mod remote;
pub mod standalone_attestation;
pub mod standalone_export;
pub mod standalone_identity;
mod tree_ops;
pub mod vfs;

pub use adapter::GitRegistryBackend;
pub use adapter::REGISTRY_REF;
pub use attestation_adapter::RegistryAttestationStorage;
pub use config::{RegistryConfig, TenantMetadata, TenantStatus};
pub use identity_adapter::RegistryIdentityStorage;
pub use oobi::{
    OOBI_KEL_FILE, OOBI_RECEIPTS_FILE, OobiExportError, export_identity_oobi, export_receipts_oobi,
    oobi_receipts_relative_path, oobi_relative_path, parse_oobi_kel, parse_oobi_receipts,
};
pub use remote::{MAX_KEL_BYTES, MAX_KEL_EVENTS, RemoteKelError, RemoteKelSource};
pub use standalone_attestation::GitAttestationStorage;
pub use standalone_export::GitRefSink;
pub use standalone_identity::GitIdentityStorage;
pub use vfs::{FixedClock, OsVfs, Vfs};
