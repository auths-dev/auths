//! iOS Keychain storage backend.

use crate::error::AgentError;
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};

use core_foundation::array::{CFArrayGetCount, CFArrayGetValueAtIndex, CFArrayRef};
use core_foundation::base::{CFRelease, CFTypeRef, OSStatus, TCFType};
use core_foundation::boolean::kCFBooleanTrue;
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::dictionary::{CFDictionaryGetValue, CFDictionaryRef, CFMutableDictionary};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};

use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrDescription, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecMatchLimit, kSecMatchLimitAll, kSecReturnAttributes, kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

use log::{debug, error, info, warn};
use std::os::raw::c_void;
use std::ptr;

/// iOS Keychain storage backend.
pub struct IOSKeychain {
    service_name: String,
}

impl IOSKeychain {
    /// Create a new `IOSKeychain` using the given service name.
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }

    /// Helper function to convert OSStatus to AgentError
    fn map_os_status_err(status: OSStatus, context: &str) -> AgentError {
        if status == errSecItemNotFound {
            AgentError::KeyNotFound
        } else {
            let msg = format!("{} failed with OSStatus: {}", context, status);
            error!("{}", msg);
            AgentError::SecurityError(msg)
        }
    }

    /// Helper to extract a String value from a CFDictionary. Assumes value is CFString.
    fn get_string_from_dict_ref(dict_ref: CFDictionaryRef, key: CFTypeRef) -> Option<String> {
        unsafe {
            let value_ref = CFDictionaryGetValue(dict_ref, key);
            if value_ref.is_null() {
                return None;
            }
            let cf_string = CFString::wrap_under_get_rule(value_ref as CFStringRef);
            Some(cf_string.to_string())
        }
    }

    /// Helper to extract a Vec<u8> value from a CFDictionary. Assumes value is CFData.
    fn get_data_from_dict_ref(dict_ref: CFDictionaryRef, key: CFTypeRef) -> Option<Vec<u8>> {
        unsafe {
            let value_ref = CFDictionaryGetValue(dict_ref, key);
            if value_ref.is_null() {
                return None;
            }
            let cf_data = CFData::wrap_under_get_rule(value_ref as CFDataRef);
            Some(cf_data.bytes().to_vec())
        }
    }

    /// Builds a Security Framework query dictionary from key-value pairs.
    ///
    /// Each pair is a raw `CFTypeRef` key (e.g., `kSecClass`) and a safe `CFType` value.
    /// The returned `CFMutableDictionary` owns all entries and handles cleanup on drop.
    fn build_query(pairs: &[(CFTypeRef, CFTypeRef)]) -> CFMutableDictionary {
        let mut dict = CFMutableDictionary::new();
        for (key, value) in pairs {
            dict.add(key, value);
        }
        dict
    }
}

impl KeyStorage for IOSKeychain {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        let alias = alias.as_str();
        info!("Storing key for alias '{}' (DID: {})", alias, identity_did);

        let service_cf = CFString::new(&self.service_name);
        let alias_cf = CFString::new(alias);
        let did_cf = CFString::new(identity_did.as_str());
        let data_cf = CFData::from_buffer(encrypted_key_data);
        // The raw string value for kSecAttrAccessible is "pdmn"
        let key_accessible_cf = CFString::new("pdmn");

        unsafe {
            // 1. Delete existing item first
            let delete_query = Self::build_query(&[
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (kSecAttrService as CFTypeRef, service_cf.as_CFTypeRef()),
                (kSecAttrAccount as CFTypeRef, alias_cf.as_CFTypeRef()),
            ]);

            let delete_status = SecItemDelete(delete_query.as_concrete_TypeRef());

            if delete_status != errSecSuccess && delete_status != errSecItemNotFound {
                warn!(
                    "SecItemDelete before add failed (status: {}) for alias '{}'. Continuing add attempt.",
                    delete_status, alias
                );
            }

            // 2. Add new item
            let add_query = Self::build_query(&[
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (kSecAttrService as CFTypeRef, service_cf.as_CFTypeRef()),
                (kSecAttrAccount as CFTypeRef, alias_cf.as_CFTypeRef()),
                (kSecAttrDescription as CFTypeRef, did_cf.as_CFTypeRef()),
                (kSecValueData as CFTypeRef, data_cf.as_CFTypeRef()),
                (
                    key_accessible_cf.as_CFTypeRef(),
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as CFTypeRef,
                ),
            ]);

            let add_status = SecItemAdd(add_query.as_concrete_TypeRef(), ptr::null_mut());

            if add_status == errSecSuccess {
                info!("Successfully stored key for alias '{}'", alias);
                Ok(())
            } else {
                Err(Self::map_os_status_err(
                    add_status,
                    &format!("SecItemAdd for alias '{}'", alias),
                ))
            }
        }
    }

    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, Vec<u8>), AgentError> {
        let alias = alias.as_str();
        debug!("Loading key for alias '{}'", alias);

        let service_cf = CFString::new(&self.service_name);
        let alias_cf = CFString::new(alias);
        let match_limit_one = CFNumber::from(1i64);
        let mut result: CFTypeRef = ptr::null_mut();

        unsafe {
            let query = Self::build_query(&[
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (kSecAttrService as CFTypeRef, service_cf.as_CFTypeRef()),
                (kSecAttrAccount as CFTypeRef, alias_cf.as_CFTypeRef()),
                (kSecReturnData as CFTypeRef, kCFBooleanTrue as CFTypeRef),
                (
                    kSecReturnAttributes as CFTypeRef,
                    kCFBooleanTrue as CFTypeRef,
                ),
                (kSecMatchLimit as CFTypeRef, match_limit_one.as_CFTypeRef()),
            ]);

            let status = SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result);

            if status != errSecSuccess {
                return Err(Self::map_os_status_err(
                    status,
                    &format!("SecItemCopyMatching (load) for alias '{}'", alias),
                ));
            }
        }

        let result_dict = result as CFDictionaryRef;
        let key_data_opt: Option<Vec<u8>>;
        let identity_did_opt: Option<String>;

        unsafe {
            key_data_opt =
                Self::get_data_from_dict_ref(result_dict, kSecValueData as *const c_void);
            identity_did_opt =
                Self::get_string_from_dict_ref(result_dict, kSecAttrDescription as *const c_void);
            CFRelease(result);
        }

        let key_data = key_data_opt.ok_or_else(|| {
            AgentError::SecurityError(format!(
                "Keychain item for alias '{}' missing key data",
                alias
            ))
        })?;
        let identity_did_str = identity_did_opt.ok_or_else(|| {
            AgentError::SecurityError(format!(
                "Keychain item for alias '{}' missing description (IdentityDID)",
                alias
            ))
        })?;

        debug!("Successfully loaded key for alias '{}'", alias);
        Ok((IdentityDID::new_unchecked(identity_did_str), key_data))
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        let alias = alias.as_str();
        info!("Deleting key for alias '{}'", alias);
        let service_cf = CFString::new(&self.service_name);
        let alias_cf = CFString::new(alias);

        let status = unsafe {
            let query = Self::build_query(&[
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (kSecAttrService as CFTypeRef, service_cf.as_CFTypeRef()),
                (kSecAttrAccount as CFTypeRef, alias_cf.as_CFTypeRef()),
            ]);

            SecItemDelete(query.as_concrete_TypeRef())
        };

        if status == errSecSuccess || status == errSecItemNotFound {
            info!(
                "Successfully deleted (or did not find) key for alias '{}'",
                alias
            );
            Ok(())
        } else {
            Err(Self::map_os_status_err(
                status,
                &format!("SecItemDelete for alias '{}'", alias),
            ))
        }
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        debug!("Listing all aliases for service '{}'", self.service_name);
        let service_cf = CFString::new(&self.service_name);
        let mut result: CFTypeRef = ptr::null_mut();

        let status = unsafe {
            let query = Self::build_query(&[
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (kSecAttrService as CFTypeRef, service_cf.as_CFTypeRef()),
                (
                    kSecReturnAttributes as CFTypeRef,
                    kCFBooleanTrue as CFTypeRef,
                ),
                (kSecMatchLimit as CFTypeRef, kSecMatchLimitAll as CFTypeRef),
            ]);

            SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result)
        };

        if status == errSecItemNotFound {
            return Ok(vec![]);
        }
        if status != errSecSuccess {
            return Err(Self::map_os_status_err(
                status,
                "SecItemCopyMatching (list_aliases)",
            ));
        }

        let result_array = result as CFArrayRef;
        let count = unsafe { CFArrayGetCount(result_array) };
        let mut aliases = Vec::with_capacity(count as usize);

        for i in 0..count {
            unsafe {
                let item_dict = CFArrayGetValueAtIndex(result_array, i) as CFDictionaryRef;
                if item_dict.is_null() {
                    continue;
                }
                if let Some(alias) =
                    Self::get_string_from_dict_ref(item_dict, kSecAttrAccount as *const c_void)
                {
                    aliases.push(KeyAlias::new_unchecked(alias));
                } else {
                    warn!(
                        "Keychain item found for service '{}' missing account (alias) at index {}",
                        self.service_name, i
                    );
                }
            }
        }
        unsafe {
            CFRelease(result);
        }
        debug!(
            "Found {} aliases for service '{}'",
            aliases.len(),
            self.service_name
        );
        Ok(aliases)
    }

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        debug!("Listing aliases for identity DID '{}'", identity_did);
        let service_cf = CFString::new(&self.service_name);
        let did_cf = CFString::new(identity_did.as_str());
        let mut result: CFTypeRef = ptr::null_mut();

        let status = unsafe {
            let query = Self::build_query(&[
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (kSecAttrService as CFTypeRef, service_cf.as_CFTypeRef()),
                (kSecAttrDescription as CFTypeRef, did_cf.as_CFTypeRef()),
                (
                    kSecReturnAttributes as CFTypeRef,
                    kCFBooleanTrue as CFTypeRef,
                ),
                (kSecMatchLimit as CFTypeRef, kSecMatchLimitAll as CFTypeRef),
            ]);

            SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result)
        };

        if status == errSecItemNotFound {
            return Ok(vec![]);
        }
        if status != errSecSuccess {
            return Err(Self::map_os_status_err(
                status,
                &format!(
                    "SecItemCopyMatching (list_aliases_for_identity) for DID '{}'",
                    identity_did
                ),
            ));
        }

        let result_array = result as CFArrayRef;
        let count = unsafe { CFArrayGetCount(result_array) };
        let mut aliases = Vec::with_capacity(count as usize);

        for i in 0..count {
            unsafe {
                let item_dict = CFArrayGetValueAtIndex(result_array, i) as CFDictionaryRef;
                if item_dict.is_null() {
                    continue;
                }
                if let Some(alias) =
                    Self::get_string_from_dict_ref(item_dict, kSecAttrAccount as *const c_void)
                {
                    aliases.push(KeyAlias::new_unchecked(alias));
                } else {
                    warn!(
                        "Keychain item found for DID '{}' missing account (alias) at index {}",
                        identity_did, i
                    );
                }
            }
        }
        unsafe {
            CFRelease(result_array as CFTypeRef);
        }
        debug!(
            "Found {} aliases for identity DID '{}'",
            aliases.len(),
            identity_did
        );
        Ok(aliases)
    }

    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        let alias = alias.as_str();
        debug!("Getting identity DID for alias '{}'", alias);
        let service_cf = CFString::new(&self.service_name);
        let alias_cf = CFString::new(alias);
        let match_limit_one = CFNumber::from(1i64);
        let mut result: CFTypeRef = ptr::null_mut();

        let status = unsafe {
            let query = Self::build_query(&[
                (
                    kSecClass as CFTypeRef,
                    kSecClassGenericPassword as CFTypeRef,
                ),
                (kSecAttrService as CFTypeRef, service_cf.as_CFTypeRef()),
                (kSecAttrAccount as CFTypeRef, alias_cf.as_CFTypeRef()),
                (
                    kSecReturnAttributes as CFTypeRef,
                    kCFBooleanTrue as CFTypeRef,
                ),
                (kSecMatchLimit as CFTypeRef, match_limit_one.as_CFTypeRef()),
            ]);

            SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result)
        };

        if status != errSecSuccess {
            return Err(Self::map_os_status_err(
                status,
                &format!("SecItemCopyMatching (get_identity) for alias '{}'", alias),
            ));
        }

        let result_dict = result as CFDictionaryRef;
        let identity_did_opt: Option<String>;

        unsafe {
            identity_did_opt =
                Self::get_string_from_dict_ref(result_dict, kSecAttrDescription as *const c_void);
            CFRelease(result);
        }

        let identity_did = identity_did_opt.ok_or_else(|| {
            AgentError::SecurityError(format!(
                "Keychain item for alias '{}' missing description (IdentityDID)",
                alias
            ))
        })?;

        debug!("Found identity DID for alias '{}'", alias);
        Ok(IdentityDID::new_unchecked(identity_did))
    }

    fn backend_name(&self) -> &'static str {
        "iOS Keychain"
    }
}
