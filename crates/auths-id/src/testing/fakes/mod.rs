pub mod attestation;
pub mod identity_storage;
pub mod registry;

pub use attestation::{FakeAttestationSink, FakeAttestationSource};
pub use identity_storage::FakeIdentityStorage;
pub use registry::FakeRegistryBackend;
