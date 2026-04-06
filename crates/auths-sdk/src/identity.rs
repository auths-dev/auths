//! Re-exports of identity types and operations from `auths-id`.

pub use auths_id::identity::helpers::{
    ManagedIdentity, encode_seed_as_pkcs8, load_keypair_from_der_or_seed,
};
pub use auths_id::identity::initialize::initialize_registry_identity;
pub use auths_id::identity::resolve::{DefaultDidResolver, DidResolver, RegistryDidResolver};
pub use auths_id::identity::rotate::rotate_keri_identity;

// Agent identity types
pub use auths_id::agent_identity::{AgentProvisioningConfig, AgentStorageMode, format_agent_toml};

// Identity events (used in tests)
pub use auths_id::identity::events::KeyRotationEvent;
