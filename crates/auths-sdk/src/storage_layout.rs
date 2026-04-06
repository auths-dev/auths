//! Re-exports of storage layout types from `auths-id`.

pub use auths_id::storage::layout;
pub use auths_id::storage::layout::{
    StorageLayoutConfig, attestation_ref_for_device, identity_ref, resolve_repo_path,
};
pub use auths_id::storage::registry::install_linearity_hook;
