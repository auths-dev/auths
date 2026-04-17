//! Re-exports of keychain, encrypted file storage, and passphrase cache types from `auths-core`.

pub use auths_core::storage::encrypted_file::EncryptedFileStorage;
pub use auths_core::storage::keychain;
pub use auths_core::storage::keychain::{
    KeyAlias, KeyRole, KeyStorage, extract_public_key_bytes, get_platform_keychain,
    get_platform_keychain_with_config, migrate_legacy_alias, sign_with_key,
};
pub use auths_core::storage::passphrase_cache::{get_passphrase_cache, parse_duration_str};

// IdentityDID is re-exported from keychain
pub use auths_core::storage::keychain::IdentityDID;
