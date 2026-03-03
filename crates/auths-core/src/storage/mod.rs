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

#[cfg(target_os = "android")]
pub(crate) use android_keystore::AndroidKeystoreStorage;
pub use encrypted_file::EncryptedFileStorage;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use ios_keychain::IOSKeychain;
pub use keychain::KeyStorage;
#[cfg(all(target_os = "linux", feature = "keychain-linux-secretservice"))]
pub(crate) use linux_secret_service::LinuxSecretServiceStorage;
#[cfg(target_os = "macos")]
pub(crate) use macos_keychain::MacOSKeychain;
pub use memory::MemoryStorage;
#[cfg(all(target_os = "windows", feature = "keychain-windows"))]
pub(crate) use windows_credential::WindowsCredentialStorage;
