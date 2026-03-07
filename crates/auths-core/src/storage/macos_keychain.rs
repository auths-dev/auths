//! macOS Keychain storage backend.

use crate::error::AgentError;
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};

use core_foundation::array::{CFArrayGetCount, CFArrayGetValueAtIndex, CFArrayRef};
use core_foundation::base::{CFRelease, CFTypeRef, OSStatus, TCFType, kCFAllocatorDefault};
use core_foundation::boolean::kCFBooleanTrue;
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::dictionary::{
    CFDictionaryCreate, CFDictionaryGetValue, CFDictionaryRef, kCFTypeDictionaryKeyCallBacks,
    kCFTypeDictionaryValueCallBacks,
};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};

use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrComment, kSecAttrDescription, kSecAttrService, kSecClass,
    kSecClassGenericPassword, kSecMatchLimit, kSecMatchLimitAll, kSecReturnAttributes,
    kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

// --- Standard Lib Imports ---
use log::{debug, error, info, warn};
use std::os::raw::c_void;
use std::ptr;

/// macOS Keychain storage backend.
#[derive(Debug)]
pub struct MacOSKeychain {
    service_name: String,
}

impl MacOSKeychain {
    /// Create a new `MacOSKeychain` using the given service name.
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }

    /// Helper function to convert OSStatus to AgentError
    fn map_os_status_err(status: OSStatus, context: &str) -> AgentError {
        // Use codes directly from security-framework-sys::base
        if status == errSecItemNotFound {
            AgentError::KeyNotFound
        } else {
            let msg = format!("{} failed with OSStatus: {}", context, status);
            error!("{}", msg); // Log the specific error
            AgentError::SecurityError(msg)
        }
    }

    /// Helper to extract a String value from a CFDictionary. Assumes value is CFString.
    /// Takes ownership of the value_ref if successful, caller doesn't need to release.
    fn get_string_from_dict_ref(dict_ref: CFDictionaryRef, key: CFTypeRef) -> Option<String> {
        unsafe {
            let value_ref = CFDictionaryGetValue(dict_ref, key);
            if value_ref.is_null() {
                return None;
            }
            // Check if it's actually a CFString before wrapping
            let type_id = core_foundation::base::CFGetTypeID(value_ref);
            if type_id != CFString::type_id() {
                warn!(
                    "Expected CFString for key but got different type ID: {}",
                    type_id
                );
                return None;
            }
            // Wrap (doesn't retain, assumes value is valid)
            let cf_string = CFString::wrap_under_get_rule(value_ref as CFStringRef);
            Some(cf_string.to_string()) // Convert to Rust String
        }
    }

    /// Helper to extract a Vec<u8> value from a CFDictionary. Assumes value is CFData.
    /// Takes ownership of the value_ref if successful, caller doesn't need to release.
    fn get_data_from_dict_ref(dict_ref: CFDictionaryRef, key: CFTypeRef) -> Option<Vec<u8>> {
        unsafe {
            let value_ref = CFDictionaryGetValue(dict_ref, key);
            if value_ref.is_null() {
                return None;
            }
            // Check if it's actually a CFData before wrapping
            let type_id = core_foundation::base::CFGetTypeID(value_ref);
            if type_id != CFData::type_id() {
                warn!(
                    "Expected CFData for key but got different type ID: {}",
                    type_id
                );
                return None;
            }
            // Wrap (doesn't retain, assumes value is valid)
            let cf_data = CFData::wrap_under_get_rule(value_ref as CFDataRef);
            Some(cf_data.bytes().to_vec()) // Convert to Vec<u8>
        }
    }
}

impl KeyStorage for MacOSKeychain {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        role: KeyRole,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        let alias = alias.as_str();
        info!(
            "Storing key for alias '{}' (DID: {}, role: {}) in macOS Keychain",
            alias, identity_did, role
        );

        // Create CFString/CFData (must be manually released later or use TCFType wrappers)
        // Using TCFType wrappers is generally safer.
        let service_cf = CFString::new(&self.service_name);
        let alias_cf = CFString::new(alias);
        let did_cf = CFString::new(identity_did.as_str());
        let role_cf = CFString::new(&role.to_string());
        let data_cf = CFData::from_buffer(encrypted_key_data);
        // --- MANUALLY CREATE `kSecAttrAccessible` KEY ---
        // The raw string value for kSecAttrAccessible is "pdmn"
        // See iOS Docs: https://developer.apple.com/documentation/security/ksecattraccessible
        let key_accessible_cf = CFString::new("pdmn");

        unsafe {
            // --- 1. Delete existing item first ---
            let delete_keys: [*const c_void; 3] = [
                kSecClass as *const c_void,
                kSecAttrService as *const c_void,
                kSecAttrAccount as *const c_void,
            ];
            let delete_values: [*const c_void; 3] = [
                kSecClassGenericPassword as *const c_void,
                service_cf.as_CFTypeRef(),
                alias_cf.as_CFTypeRef(),
            ];
            let delete_query = CFDictionaryCreate(
                kCFAllocatorDefault,
                delete_keys.as_ptr(),
                delete_values.as_ptr(),
                delete_keys.len() as isize,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            );

            if delete_query.is_null() {
                return Err(AgentError::SecurityError(
                    "Failed to create CFDictionary for delete query".to_string(),
                ));
            }
            let delete_status = SecItemDelete(delete_query);
            CFRelease(delete_query as CFTypeRef);

            if delete_status != errSecSuccess && delete_status != errSecItemNotFound {
                // Log warning but continue, Add might still work or provide better error
                warn!(
                    "SecItemDelete before add failed (status: {}) for alias '{}'. Continuing add attempt.",
                    delete_status, alias
                );
            } else {
                debug!(
                    "SecItemDelete status for alias '{}': {}",
                    alias, delete_status
                );
            }

            // --- 2. Add new item ---
            let add_keys: [*const c_void; 7] = [
                kSecClass as *const c_void,
                kSecAttrService as *const c_void,
                kSecAttrAccount as *const c_void,
                kSecAttrDescription as *const c_void, // Store DID in description
                kSecAttrComment as *const c_void,     // Store role in comment
                kSecValueData as *const c_void,
                key_accessible_cf.as_CFTypeRef(),
            ];
            let add_values: [*const c_void; 7] = [
                kSecClassGenericPassword as *const c_void,
                service_cf.as_CFTypeRef(),
                alias_cf.as_CFTypeRef(),
                did_cf.as_CFTypeRef(),
                role_cf.as_CFTypeRef(),
                data_cf.as_CFTypeRef(),
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as *const c_void,
            ];
            let add_query = CFDictionaryCreate(
                kCFAllocatorDefault,
                add_keys.as_ptr(),
                add_values.as_ptr(),
                add_keys.len() as isize,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            );

            if add_query.is_null() {
                return Err(AgentError::SecurityError(
                    "Failed to create CFDictionary for add query".to_string(),
                ));
            }
            // SecItemAdd does not return data, so result pointer is null
            let add_status = SecItemAdd(add_query, ptr::null_mut());
            CFRelease(add_query as CFTypeRef);

            // --- 3. Check status ---
            if add_status == errSecSuccess {
                info!(
                    "Successfully stored key for alias '{}' in macOS Keychain",
                    alias
                );
                Ok(())
            } else {
                Err(Self::map_os_status_err(
                    add_status,
                    &format!("SecItemAdd for alias '{}'", alias),
                ))
            }
        } // end unsafe
    }

    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
        let alias = alias.as_str();
        debug!("Loading key for alias '{}' from macOS Keychain", alias);

        let service_cf = CFString::new(&self.service_name);
        let alias_cf = CFString::new(alias);
        // Use CFNumber::from(1i32) for CFNumber representation of 1
        let limit_one_cf = CFNumber::from(1i32);

        let mut result_ref: CFTypeRef = ptr::null_mut();
        let status: OSStatus;

        unsafe {
            let query_keys: [*const c_void; 6] = [
                kSecClass as *const c_void,
                kSecAttrService as *const c_void,
                kSecAttrAccount as *const c_void,
                kSecReturnData as *const c_void,       // Request data
                kSecReturnAttributes as *const c_void, // Request attributes (for description)
                kSecMatchLimit as *const c_void,       // Limit results
            ];
            let query_values: [*const c_void; 6] = [
                kSecClassGenericPassword as *const c_void,
                service_cf.as_CFTypeRef(),
                alias_cf.as_CFTypeRef(),
                kCFBooleanTrue as *const c_void,
                kCFBooleanTrue as *const c_void,
                limit_one_cf.as_CFTypeRef(), // Use CFNumberRef for limit
            ];
            let query = CFDictionaryCreate(
                kCFAllocatorDefault,
                query_keys.as_ptr(),
                query_values.as_ptr(),
                query_keys.len() as isize,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            );

            if query.is_null() {
                return Err(AgentError::SecurityError(
                    "Failed to create CFDictionary for load query".into(),
                ));
            }
            status = SecItemCopyMatching(query, &mut result_ref);
            CFRelease(query as CFTypeRef); // Release query dict immediately
        } // end unsafe

        if status != errSecSuccess {
            // map_os_status_err handles KeyNotFound case
            return Err(Self::map_os_status_err(
                status,
                &format!("SecItemCopyMatching (load) for alias '{}'", alias),
            ));
        }

        // Check if result is NULL before casting (shouldn't happen on errSecSuccess, but be safe)
        if result_ref.is_null() {
            error!(
                "SecItemCopyMatching succeeded for '{}' but returned NULL result",
                alias
            );
            return Err(AgentError::SecurityError(
                "Keychain returned NULL result on success".into(),
            ));
        }

        // According to docs, if kSecReturnAttributes is true and kSecMatchLimitOne is set,
        // the result is a single CFDictionaryRef, not an array.
        let result_dict = result_ref as CFDictionaryRef;
        let key_data: Vec<u8>;
        let identity_did_str: String;
        let role_str: Option<String>;

        unsafe {
            key_data = Self::get_data_from_dict_ref(result_dict, kSecValueData as *const c_void)
                .ok_or_else(|| {
                    AgentError::SecurityError(format!(
                        "Keychain item for '{}' missing key data",
                        alias
                    ))
                })?;
            identity_did_str =
                Self::get_string_from_dict_ref(result_dict, kSecAttrDescription as *const c_void)
                    .ok_or_else(|| {
                    AgentError::SecurityError(format!(
                        "Keychain item for '{}' missing description (IdentityDID)",
                        alias
                    ))
                })?;
            role_str =
                Self::get_string_from_dict_ref(result_dict, kSecAttrComment as *const c_void);
            CFRelease(result_ref);
        }

        let role = role_str
            .and_then(|s| s.parse::<KeyRole>().ok())
            .unwrap_or(KeyRole::Primary);

        debug!("Successfully loaded key for alias '{}'", alias);
        Ok((IdentityDID::new_unchecked(identity_did_str), role, key_data))
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        let alias = alias.as_str();
        info!("Deleting key for alias '{}' from macOS Keychain", alias);
        let service_cf = CFString::new(&self.service_name);
        let alias_cf = CFString::new(alias);
        let status: OSStatus;

        unsafe {
            let query_keys: [*const c_void; 3] = [
                kSecClass as *const c_void,
                kSecAttrService as *const c_void,
                kSecAttrAccount as *const c_void,
            ];
            let query_values: [*const c_void; 3] = [
                kSecClassGenericPassword as *const c_void,
                service_cf.as_CFTypeRef(),
                alias_cf.as_CFTypeRef(),
            ];
            let query = CFDictionaryCreate(
                kCFAllocatorDefault,
                query_keys.as_ptr(),
                query_values.as_ptr(),
                query_keys.len() as isize,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            );

            if query.is_null() {
                return Err(AgentError::SecurityError(
                    "Failed to create CFDictionary for delete query".into(),
                ));
            }
            status = SecItemDelete(query);
            CFRelease(query as CFTypeRef);
        } // end unsafe

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
        debug!(
            "Listing all aliases for service '{}' from macOS Keychain",
            self.service_name
        );
        let service_cf = CFString::new(&self.service_name);
        let mut result_ref: CFTypeRef = ptr::null_mut();
        let status: OSStatus;

        unsafe {
            let query_keys: [*const c_void; 4] = [
                kSecClass as *const c_void,
                kSecAttrService as *const c_void,
                kSecReturnAttributes as *const c_void, // Request attributes (to get account name)
                kSecMatchLimit as *const c_void,
            ];
            let query_values: [*const c_void; 4] = [
                kSecClassGenericPassword as *const c_void,
                service_cf.as_CFTypeRef(),
                kCFBooleanTrue as *const c_void,
                kSecMatchLimitAll as *const c_void, // Get all matches
            ];
            let query = CFDictionaryCreate(
                kCFAllocatorDefault,
                query_keys.as_ptr(),
                query_values.as_ptr(),
                query_keys.len() as isize,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            );

            if query.is_null() {
                return Err(AgentError::SecurityError(
                    "Failed to create CFDictionary for list_aliases query".into(),
                ));
            }
            status = SecItemCopyMatching(query, &mut result_ref);
            CFRelease(query as CFTypeRef);
        } // end unsafe

        if status == errSecItemNotFound {
            debug!(
                "No keychain items found for service '{}'",
                self.service_name
            );
            return Ok(vec![]); // No items found is not an error
        }
        if status != errSecSuccess {
            return Err(Self::map_os_status_err(
                status,
                "SecItemCopyMatching (list_aliases)",
            ));
        }

        if result_ref.is_null() {
            error!("SecItemCopyMatching succeeded for list_aliases but returned NULL result");
            return Err(AgentError::SecurityError(
                "Keychain returned NULL result on success".into(),
            ));
        }

        let result_array = result_ref as CFArrayRef;
        let count = unsafe { CFArrayGetCount(result_array) };
        let mut aliases = Vec::with_capacity(count as usize);

        for i in 0..count {
            unsafe {
                let item_dict = CFArrayGetValueAtIndex(result_array, i) as CFDictionaryRef;
                if item_dict.is_null() {
                    warn!("list_aliases: Found NULL item dictionary at index {}", i);
                    continue;
                }
                // Extract the alias (account name) using the helper
                if let Some(alias) =
                    Self::get_string_from_dict_ref(item_dict, kSecAttrAccount as *const c_void)
                {
                    aliases.push(KeyAlias::new_unchecked(alias));
                } else {
                    warn!(
                        "list_aliases: Keychain item found for service '{}' missing account (alias) at index {}",
                        self.service_name, i
                    );
                }
            }
        }

        unsafe {
            CFRelease(result_ref); // Release the array ref
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
        debug!(
            "Listing aliases for identity DID '{}' and service '{}'",
            identity_did, self.service_name
        );
        let service_cf = CFString::new(&self.service_name);
        let did_cf = CFString::new(identity_did.as_str());
        let mut result_ref: CFTypeRef = ptr::null_mut();
        let status: OSStatus;

        unsafe {
            let query_keys: [*const c_void; 5] = [
                kSecClass as *const c_void,
                kSecAttrService as *const c_void,
                kSecAttrDescription as *const c_void, // Match identity DID
                kSecReturnAttributes as *const c_void,
                kSecMatchLimit as *const c_void,
            ];
            let query_values: [*const c_void; 5] = [
                kSecClassGenericPassword as *const c_void,
                service_cf.as_CFTypeRef(),
                did_cf.as_CFTypeRef(),
                kCFBooleanTrue as *const c_void,
                kSecMatchLimitAll as *const c_void,
            ];
            let query = CFDictionaryCreate(
                kCFAllocatorDefault,
                query_keys.as_ptr(),
                query_values.as_ptr(),
                query_keys.len() as isize,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            );

            if query.is_null() {
                return Err(AgentError::SecurityError(
                    "Failed to create CFDictionary for list_aliases_for_identity query".into(),
                ));
            }
            status = SecItemCopyMatching(query, &mut result_ref);
            CFRelease(query as CFTypeRef);
        } // end unsafe

        if status == errSecItemNotFound {
            debug!(
                "No keychain items found for identity DID '{}'",
                identity_did
            );
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

        if result_ref.is_null() {
            error!(
                "SecItemCopyMatching succeeded for list_aliases_for_identity but returned NULL result"
            );
            return Err(AgentError::SecurityError(
                "Keychain returned NULL result on success".into(),
            ));
        }

        let result_array = result_ref as CFArrayRef;
        let count = unsafe { CFArrayGetCount(result_array) };
        let mut aliases = Vec::with_capacity(count as usize);

        for i in 0..count {
            unsafe {
                let item_dict = CFArrayGetValueAtIndex(result_array, i) as CFDictionaryRef;
                if item_dict.is_null() {
                    warn!(
                        "list_aliases_for_identity: Found NULL item dictionary at index {}",
                        i
                    );
                    continue;
                }
                if let Some(alias) =
                    Self::get_string_from_dict_ref(item_dict, kSecAttrAccount as *const c_void)
                {
                    aliases.push(KeyAlias::new_unchecked(alias));
                } else {
                    warn!(
                        "list_aliases_for_identity: Keychain item found for DID '{}' missing account (alias) at index {}",
                        identity_did, i
                    );
                }
            }
        }

        unsafe {
            CFRelease(result_ref); // Release the array ref
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
        debug!(
            "Getting identity DID for alias '{}' from macOS Keychain",
            alias
        );
        let service_cf = CFString::new(&self.service_name);
        let alias_cf = CFString::new(alias);
        let limit_one_cf = CFNumber::from(1i32);
        let mut result_ref: CFTypeRef = ptr::null_mut();
        let status: OSStatus;

        unsafe {
            let query_keys: [*const c_void; 5] = [
                kSecClass as *const c_void,
                kSecAttrService as *const c_void,
                kSecAttrAccount as *const c_void,
                kSecReturnAttributes as *const c_void, // Request attributes
                kSecMatchLimit as *const c_void,
            ];
            let query_values: [*const c_void; 5] = [
                kSecClassGenericPassword as *const c_void,
                service_cf.as_CFTypeRef(),
                alias_cf.as_CFTypeRef(),
                kCFBooleanTrue as *const c_void,
                limit_one_cf.as_CFTypeRef(),
            ];
            let query = CFDictionaryCreate(
                kCFAllocatorDefault,
                query_keys.as_ptr(),
                query_values.as_ptr(),
                query_keys.len() as isize,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            );

            if query.is_null() {
                return Err(AgentError::SecurityError(
                    "Failed to create CFDictionary for get_identity_for_alias query".into(),
                ));
            }
            status = SecItemCopyMatching(query, &mut result_ref);
            CFRelease(query as CFTypeRef);
        } // end unsafe

        if status != errSecSuccess {
            return Err(Self::map_os_status_err(
                status,
                &format!("SecItemCopyMatching (get_identity) for alias '{}'", alias),
            ));
        }

        if result_ref.is_null() {
            error!(
                "SecItemCopyMatching succeeded for get_identity_for_alias '{}' but returned NULL result",
                alias
            );
            return Err(AgentError::SecurityError(
                "Keychain returned NULL result on success".into(),
            ));
        }

        let result_dict = result_ref as CFDictionaryRef;
        let identity_did_str: String;

        unsafe {
            identity_did_str =
                Self::get_string_from_dict_ref(result_dict, kSecAttrDescription as *const c_void)
                    .ok_or_else(|| {
                    AgentError::SecurityError(format!(
                        "Keychain item for '{}' missing description (IdentityDID)",
                        alias
                    ))
                })?;
            CFRelease(result_ref);
        }

        debug!("Found identity DID for alias '{}'", alias);
        Ok(IdentityDID::new_unchecked(identity_did_str))
    }

    fn backend_name(&self) -> &'static str {
        "macOS Keychain" // Update backend name
    }
}
