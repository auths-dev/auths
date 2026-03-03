//! Key storage backends.

#[cfg(target_os = "android")]
pub mod android_keystore;
pub mod encrypted_file;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod ios_keychain;
pub mod keychain;
#[cfg(all(target_os = "linux", feature = "keychain-linux-secretservice"))]
pub mod linux_secret_service;
#[cfg(target_os = "macos")]
pub mod macos_keychain;
pub mod memory;
#[cfg(all(target_os = "windows", feature = "keychain-windows"))]
pub mod windows_credential;

pub use encrypted_file::EncryptedFileStorage;
pub use keychain::KeyStorage;
pub use memory::MemoryStorage;
