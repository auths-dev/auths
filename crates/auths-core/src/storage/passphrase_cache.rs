//! OS keychain-backed passphrase cache.
//!
//! Stores and retrieves passphrases by key alias using the platform keychain.
//! Separate from the main key storage — uses service name `dev.auths.passphrase`.

use crate::error::AgentError;
use zeroize::Zeroizing;

/// Trait for storing/retrieving passphrases in the OS keychain.
pub trait PassphraseCache: Send + Sync {
    /// Store a passphrase for the given alias.
    fn store(&self, alias: &str, passphrase: &str, stored_at_unix: i64) -> Result<(), AgentError>;

    /// Load a cached passphrase for the given alias.
    /// Returns `None` if no cached passphrase exists.
    fn load(&self, alias: &str) -> Result<Option<(Zeroizing<String>, i64)>, AgentError>;

    /// Delete a cached passphrase for the given alias.
    fn delete(&self, alias: &str) -> Result<(), AgentError>;
}

const PASSPHRASE_SERVICE: &str = "dev.auths.passphrase";

/// No-op cache that never stores or returns anything.
pub struct NoopPassphraseCache;

impl PassphraseCache for NoopPassphraseCache {
    fn store(
        &self,
        _alias: &str,
        _passphrase: &str,
        _stored_at_unix: i64,
    ) -> Result<(), AgentError> {
        Ok(())
    }

    fn load(&self, _alias: &str) -> Result<Option<(Zeroizing<String>, i64)>, AgentError> {
        Ok(None)
    }

    fn delete(&self, _alias: &str) -> Result<(), AgentError> {
        Ok(())
    }
}

// The stored secret value format is: "timestamp|passphrase"
fn encode_secret(passphrase: &str, stored_at_unix: i64) -> String {
    format!("{}|{}", stored_at_unix, passphrase)
}

fn decode_secret(secret: &str) -> Option<(Zeroizing<String>, i64)> {
    let (ts_str, passphrase) = secret.split_once('|')?;
    let ts: i64 = ts_str.parse().ok()?;
    Some((Zeroizing::new(passphrase.to_string()), ts))
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use core_foundation::base::{CFRelease, CFTypeRef, TCFType, kCFAllocatorDefault};
    use core_foundation::boolean::kCFBooleanTrue;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::{
        CFDictionaryCreate, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks,
    };
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use security_framework_sys::access_control::{
        SecAccessControlCreateWithFlags, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    };
    use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass,
        kSecClassGenericPassword, kSecMatchLimit, kSecReturnData, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
    use std::os::raw::c_void;
    use std::ptr;

    // kSecAccessControlUserPresence: Touch ID or device passcode
    const USER_PRESENCE: usize = 1 << 0;
    // User cancelled Touch ID or authentication failed
    const ERR_SEC_USER_CANCELED: i32 = -128;
    const ERR_SEC_AUTH_FAILED: i32 = -25293;

    pub struct MacOsPassphraseCache {
        pub biometric: bool,
    }

    impl MacOsPassphraseCache {
        fn store_with_biometric(
            &self,
            alias: &str,
            passphrase: &str,
            stored_at_unix: i64,
        ) -> Result<(), AgentError> {
            let service_cf = CFString::new(PASSPHRASE_SERVICE);
            let alias_cf = CFString::new(alias);
            let secret = encode_secret(passphrase, stored_at_unix);
            let data_cf = CFData::from_buffer(secret.as_bytes());

            unsafe {
                let access_control = SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
                    USER_PRESENCE,
                    ptr::null_mut(),
                );
                if access_control.is_null() {
                    return Err(AgentError::SecurityError(
                        "Failed to create biometric access control".to_string(),
                    ));
                }

                let keys: [*const c_void; 5] = [
                    kSecClass as *const c_void,
                    kSecAttrService as *const c_void,
                    kSecAttrAccount as *const c_void,
                    kSecValueData as *const c_void,
                    kSecAttrAccessControl as *const c_void,
                ];
                let values: [*const c_void; 5] = [
                    kSecClassGenericPassword as *const c_void,
                    service_cf.as_CFTypeRef(),
                    alias_cf.as_CFTypeRef(),
                    data_cf.as_CFTypeRef(),
                    access_control as *const c_void,
                ];
                let query = CFDictionaryCreate(
                    kCFAllocatorDefault,
                    keys.as_ptr(),
                    values.as_ptr(),
                    keys.len() as isize,
                    &kCFTypeDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks,
                );
                CFRelease(access_control as CFTypeRef);

                if query.is_null() {
                    return Err(AgentError::SecurityError(
                        "Failed to create CFDictionary for passphrase store".to_string(),
                    ));
                }
                let status = SecItemAdd(query, ptr::null_mut());
                CFRelease(query as CFTypeRef);

                if status == errSecSuccess {
                    Ok(())
                } else {
                    Err(AgentError::SecurityError(format!(
                        "SecItemAdd for passphrase cache failed (OSStatus: {})",
                        status
                    )))
                }
            }
        }

        fn store_without_biometric(
            &self,
            alias: &str,
            passphrase: &str,
            stored_at_unix: i64,
        ) -> Result<(), AgentError> {
            let service_cf = CFString::new(PASSPHRASE_SERVICE);
            let alias_cf = CFString::new(alias);
            let secret = encode_secret(passphrase, stored_at_unix);
            let data_cf = CFData::from_buffer(secret.as_bytes());

            unsafe {
                let keys: [*const c_void; 4] = [
                    kSecClass as *const c_void,
                    kSecAttrService as *const c_void,
                    kSecAttrAccount as *const c_void,
                    kSecValueData as *const c_void,
                ];
                let values: [*const c_void; 4] = [
                    kSecClassGenericPassword as *const c_void,
                    service_cf.as_CFTypeRef(),
                    alias_cf.as_CFTypeRef(),
                    data_cf.as_CFTypeRef(),
                ];
                let query = CFDictionaryCreate(
                    kCFAllocatorDefault,
                    keys.as_ptr(),
                    values.as_ptr(),
                    keys.len() as isize,
                    &kCFTypeDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks,
                );
                if query.is_null() {
                    return Err(AgentError::SecurityError(
                        "Failed to create CFDictionary for passphrase store".to_string(),
                    ));
                }
                let status = SecItemAdd(query, ptr::null_mut());
                CFRelease(query as CFTypeRef);

                if status == errSecSuccess {
                    Ok(())
                } else {
                    Err(AgentError::SecurityError(format!(
                        "SecItemAdd for passphrase cache failed (OSStatus: {})",
                        status
                    )))
                }
            }
        }
    }

    impl PassphraseCache for MacOsPassphraseCache {
        fn store(
            &self,
            alias: &str,
            passphrase: &str,
            stored_at_unix: i64,
        ) -> Result<(), AgentError> {
            let _ = self.delete(alias);

            if self.biometric {
                self.store_with_biometric(alias, passphrase, stored_at_unix)
            } else {
                self.store_without_biometric(alias, passphrase, stored_at_unix)
            }
        }

        fn load(&self, alias: &str) -> Result<Option<(Zeroizing<String>, i64)>, AgentError> {
            let service_cf = CFString::new(PASSPHRASE_SERVICE);
            let alias_cf = CFString::new(alias);
            let limit_one_cf = CFNumber::from(1i32);
            let mut result_ref: CFTypeRef = ptr::null_mut();

            let status = unsafe {
                let keys: [*const c_void; 5] = [
                    kSecClass as *const c_void,
                    kSecAttrService as *const c_void,
                    kSecAttrAccount as *const c_void,
                    kSecReturnData as *const c_void,
                    kSecMatchLimit as *const c_void,
                ];
                let values: [*const c_void; 5] = [
                    kSecClassGenericPassword as *const c_void,
                    service_cf.as_CFTypeRef(),
                    alias_cf.as_CFTypeRef(),
                    kCFBooleanTrue as *const c_void,
                    limit_one_cf.as_CFTypeRef(),
                ];
                let query = CFDictionaryCreate(
                    kCFAllocatorDefault,
                    keys.as_ptr(),
                    values.as_ptr(),
                    keys.len() as isize,
                    &kCFTypeDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks,
                );
                if query.is_null() {
                    return Err(AgentError::SecurityError(
                        "Failed to create CFDictionary for passphrase load".to_string(),
                    ));
                }
                let status = SecItemCopyMatching(query, &mut result_ref);
                CFRelease(query as CFTypeRef);
                status
            };

            if status == errSecItemNotFound {
                return Ok(None);
            }
            // Touch ID cancelled or auth failed — treat as cache miss
            if status == ERR_SEC_USER_CANCELED || status == ERR_SEC_AUTH_FAILED {
                return Ok(None);
            }
            if status != errSecSuccess {
                return Err(AgentError::SecurityError(format!(
                    "SecItemCopyMatching for passphrase cache failed (OSStatus: {})",
                    status
                )));
            }
            if result_ref.is_null() {
                return Ok(None);
            }

            let bytes = unsafe {
                let cf_data = CFData::wrap_under_create_rule(result_ref as _);
                cf_data.bytes().to_vec()
            };

            let secret_str = String::from_utf8(bytes).map_err(|e| {
                AgentError::SecurityError(format!("Invalid passphrase encoding: {}", e))
            })?;

            Ok(decode_secret(&secret_str))
        }

        fn delete(&self, alias: &str) -> Result<(), AgentError> {
            let service_cf = CFString::new(PASSPHRASE_SERVICE);
            let alias_cf = CFString::new(alias);

            unsafe {
                let keys: [*const c_void; 3] = [
                    kSecClass as *const c_void,
                    kSecAttrService as *const c_void,
                    kSecAttrAccount as *const c_void,
                ];
                let values: [*const c_void; 3] = [
                    kSecClassGenericPassword as *const c_void,
                    service_cf.as_CFTypeRef(),
                    alias_cf.as_CFTypeRef(),
                ];
                let query = CFDictionaryCreate(
                    kCFAllocatorDefault,
                    keys.as_ptr(),
                    values.as_ptr(),
                    keys.len() as isize,
                    &kCFTypeDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks,
                );
                if query.is_null() {
                    return Err(AgentError::SecurityError(
                        "Failed to create CFDictionary for passphrase delete".to_string(),
                    ));
                }
                let status = SecItemDelete(query);
                CFRelease(query as CFTypeRef);

                if status == errSecSuccess || status == errSecItemNotFound {
                    Ok(())
                } else {
                    Err(AgentError::SecurityError(format!(
                        "SecItemDelete for passphrase cache failed (OSStatus: {})",
                        status
                    )))
                }
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "keychain-linux-secretservice"))]
mod linux {
    use super::*;
    use secret_service::{EncryptionType, SecretService};
    use std::collections::HashMap;

    const ATTR_SERVICE: &str = "service";
    const ATTR_ALIAS: &str = "alias";

    pub struct LinuxPassphraseCache;

    impl PassphraseCache for LinuxPassphraseCache {
        fn store(
            &self,
            alias: &str,
            passphrase: &str,
            stored_at_unix: i64,
        ) -> Result<(), AgentError> {
            let secret = encode_secret(passphrase, stored_at_unix);
            let alias = alias.to_string();

            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let ss = SecretService::connect(EncryptionType::Dh)
                        .await
                        .map_err(|e| AgentError::BackendUnavailable {
                            backend: "linux-secret-service",
                            reason: format!("Failed to connect: {}", e),
                        })?;

                    let collection = ss.get_default_collection().await.map_err(|e| {
                        AgentError::SecurityError(format!(
                            "Failed to get default collection: {}",
                            e
                        ))
                    })?;

                    // Delete existing
                    let search_attrs: HashMap<&str, &str> = [
                        (ATTR_SERVICE, PASSPHRASE_SERVICE),
                        (ATTR_ALIAS, alias.as_str()),
                    ]
                    .into_iter()
                    .collect();

                    if let Ok(items) = ss.search_items(search_attrs).await {
                        for item in items.unlocked {
                            let _ = item.delete().await;
                        }
                    }

                    let attrs: HashMap<&str, &str> = [
                        (ATTR_SERVICE, PASSPHRASE_SERVICE),
                        (ATTR_ALIAS, alias.as_str()),
                    ]
                    .into_iter()
                    .collect();

                    let label = format!("Auths passphrase: {}", alias);
                    collection
                        .create_item(&label, attrs, secret.as_bytes(), true, "text/plain")
                        .await
                        .map_err(|e| {
                            AgentError::StorageError(format!("Failed to store passphrase: {}", e))
                        })?;

                    Ok(())
                })
            })
        }

        fn load(&self, alias: &str) -> Result<Option<(Zeroizing<String>, i64)>, AgentError> {
            let alias = alias.to_string();

            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let ss = SecretService::connect(EncryptionType::Dh)
                        .await
                        .map_err(|e| AgentError::BackendUnavailable {
                            backend: "linux-secret-service",
                            reason: format!("Failed to connect: {}", e),
                        })?;

                    let attrs: HashMap<&str, &str> = [
                        (ATTR_SERVICE, PASSPHRASE_SERVICE),
                        (ATTR_ALIAS, alias.as_str()),
                    ]
                    .into_iter()
                    .collect();

                    let items = ss.search_items(attrs).await.map_err(|e| {
                        AgentError::StorageError(format!("Failed to search items: {}", e))
                    })?;

                    let item = match items.unlocked.into_iter().next() {
                        Some(i) => i,
                        None => return Ok(None),
                    };

                    let secret_bytes = item.get_secret().await.map_err(|e| {
                        AgentError::StorageError(format!("Failed to get secret: {}", e))
                    })?;

                    let secret_str = String::from_utf8(secret_bytes).map_err(|e| {
                        AgentError::StorageError(format!("Invalid secret encoding: {}", e))
                    })?;

                    Ok(decode_secret(&secret_str))
                })
            })
        }

        fn delete(&self, alias: &str) -> Result<(), AgentError> {
            let alias = alias.to_string();

            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let ss = SecretService::connect(EncryptionType::Dh)
                        .await
                        .map_err(|e| AgentError::BackendUnavailable {
                            backend: "linux-secret-service",
                            reason: format!("Failed to connect: {}", e),
                        })?;

                    let attrs: HashMap<&str, &str> = [
                        (ATTR_SERVICE, PASSPHRASE_SERVICE),
                        (ATTR_ALIAS, alias.as_str()),
                    ]
                    .into_iter()
                    .collect();

                    let items = ss.search_items(attrs).await.map_err(|e| {
                        AgentError::StorageError(format!("Failed to search items: {}", e))
                    })?;

                    for item in items.unlocked {
                        let _ = item.delete().await;
                    }

                    Ok(())
                })
            })
        }
    }
}

/// Returns the platform-appropriate passphrase cache.
///
/// Args:
/// * `biometric`: When `true` on macOS, protects cached passphrases with Touch ID.
///   Ignored on other platforms.
///
/// Usage:
/// ```ignore
/// let cache = get_passphrase_cache(true);
/// cache.store("main", "my-secret", chrono::Utc::now().timestamp())?;
/// ```
pub fn get_passphrase_cache(biometric: bool) -> Box<dyn PassphraseCache> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsPassphraseCache { biometric })
    }

    #[cfg(all(target_os = "linux", feature = "keychain-linux-secretservice"))]
    {
        let _ = biometric;
        Box::new(linux::LinuxPassphraseCache)
    }

    #[cfg(not(any(
        target_os = "macos",
        all(target_os = "linux", feature = "keychain-linux-secretservice")
    )))]
    {
        let _ = biometric;
        Box::new(NoopPassphraseCache)
    }
}

/// Parses a human-friendly duration string into seconds.
///
/// Supports: `"7d"` (days), `"24h"` (hours), `"30m"` (minutes), `"3600s"` or `"3600"` (seconds).
///
/// Args:
/// * `s`: Duration string.
///
/// Usage:
/// ```ignore
/// assert_eq!(parse_duration_str("7d"), Some(604800));
/// assert_eq!(parse_duration_str("24h"), Some(86400));
/// ```
pub fn parse_duration_str(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('d') {
        (n, 86400i64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else {
        (s, 1)
    };

    let n: i64 = num_str.parse().ok()?;
    if n <= 0 {
        return None;
    }
    Some(n * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_cache_returns_none() {
        let cache = NoopPassphraseCache;
        assert!(cache.load("any").unwrap().is_none());
    }

    #[test]
    fn noop_cache_store_and_delete_succeed() {
        let cache = NoopPassphraseCache;
        cache.store("any", "pass", 12345).unwrap();
        cache.delete("any").unwrap();
    }

    #[test]
    fn encode_decode_roundtrip() {
        let encoded = encode_secret("my-passphrase", 1700000000);
        let (pass, ts) = decode_secret(&encoded).unwrap();
        assert_eq!(*pass, "my-passphrase");
        assert_eq!(ts, 1700000000);
    }

    #[test]
    fn decode_handles_pipe_in_passphrase() {
        let encoded = encode_secret("pass|with|pipes", 100);
        let (pass, ts) = decode_secret(&encoded).unwrap();
        assert_eq!(*pass, "pass|with|pipes");
        assert_eq!(ts, 100);
    }

    #[test]
    fn decode_rejects_empty() {
        assert!(decode_secret("").is_none());
    }

    #[test]
    fn decode_rejects_no_pipe() {
        assert!(decode_secret("12345").is_none());
    }

    #[test]
    fn decode_rejects_bad_timestamp() {
        assert!(decode_secret("notanumber|pass").is_none());
    }

    #[test]
    fn parse_duration_days() {
        assert_eq!(parse_duration_str("7d"), Some(604800));
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration_str("24h"), Some(86400));
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration_str("30m"), Some(1800));
    }

    #[test]
    fn parse_duration_seconds_suffix() {
        assert_eq!(parse_duration_str("3600s"), Some(3600));
    }

    #[test]
    fn parse_duration_bare_number() {
        assert_eq!(parse_duration_str("3600"), Some(3600));
    }

    #[test]
    fn parse_duration_empty() {
        assert!(parse_duration_str("").is_none());
    }

    #[test]
    fn parse_duration_zero() {
        assert!(parse_duration_str("0d").is_none());
    }

    #[test]
    fn parse_duration_negative() {
        assert!(parse_duration_str("-1d").is_none());
    }

    #[test]
    fn parse_duration_whitespace() {
        assert_eq!(parse_duration_str("  7d  "), Some(604800));
    }
}
