#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod attestation;
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod identity_storage;
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod registry;

pub use attestation::{FakeAttestationSink, FakeAttestationSource};
pub use identity_storage::FakeIdentityStorage;
pub use registry::FakeRegistryBackend;
