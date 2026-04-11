//! Apple Secure Enclave P-256 key storage backend.
//!
//! Uses CryptoKit via a Swift FFI bridge. Private keys never leave the SE
//! hardware. Signing triggers Touch ID / Face ID. Key handles (encrypted
//! blobs) are stored as files in `~/.auths/se_keys/`.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

use log::debug;

use crate::error::AgentError;
use crate::signing::{PassphraseProvider, SecureSigner};
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};

// FFI declarations — symbols from the Swift static library
unsafe extern "C" {
    fn se_is_available() -> bool;
    fn se_create_key(
        out_handle: *mut u8,
        out_handle_len: *mut usize,
        out_pubkey: *mut u8,
        out_pubkey_len: *mut usize,
    ) -> i32;
    fn se_sign(
        handle: *const u8,
        handle_len: usize,
        msg: *const u8,
        msg_len: usize,
        out_sig: *mut u8,
        out_sig_len: *mut usize,
    ) -> i32;
    fn se_load_key(
        handle: *const u8,
        handle_len: usize,
        out_pubkey: *mut u8,
        out_pubkey_len: *mut usize,
    ) -> i32;
}

/// Check if Secure Enclave hardware is available.
pub fn is_available() -> bool {
    unsafe { se_is_available() }
}

fn se_error(code: i32) -> AgentError {
    match code {
        1 => AgentError::BackendUnavailable {
            backend: "secure-enclave",
            reason: "Secure Enclave not available".into(),
        },
        2 => AgentError::SigningFailed("biometric authentication failed or cancelled".into()),
        3 => AgentError::SigningFailed("Secure Enclave key operation failed".into()),
        _ => AgentError::SigningFailed(format!("Secure Enclave error code {code}")),
    }
}

/// Metadata stored alongside the SE key handle file.
#[derive(serde::Serialize, serde::Deserialize)]
struct KeyMetadata {
    identity_did: String,
    role: String,
}

/// Secure Enclave key storage backend.
///
/// Keys are generated inside the SE hardware and never leave it. The
/// `dataRepresentation` (an encrypted opaque blob) is stored as a file
/// in `~/.auths/se_keys/<alias>.se`. Only the same SE hardware can use it.
pub struct SecureEnclaveKeyStorage {
    keys_dir: PathBuf,
    /// Cache of loaded key handles to avoid re-reading files
    handle_cache: Mutex<HashMap<String, Vec<u8>>>,
}

impl SecureEnclaveKeyStorage {
    /// Create a new SE storage backend.
    ///
    /// Args:
    /// * `auths_home`: Path to `~/.auths` directory.
    pub fn new(auths_home: &std::path::Path) -> Result<Self, AgentError> {
        if !is_available() {
            return Err(AgentError::BackendUnavailable {
                backend: "secure-enclave",
                reason: "Secure Enclave not available on this hardware".into(),
            });
        }
        let keys_dir = auths_home.join("se_keys");
        if !keys_dir.exists() {
            fs::create_dir_all(&keys_dir).map_err(|e| {
                AgentError::IO(std::io::Error::other(format!(
                    "failed to create SE keys directory: {e}"
                )))
            })?;
            fs::set_permissions(&keys_dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
                AgentError::IO(std::io::Error::other(format!(
                    "failed to set SE keys directory permissions: {e}"
                )))
            })?;
        }
        Ok(Self {
            keys_dir,
            handle_cache: Mutex::new(HashMap::new()),
        })
    }

    fn handle_path(&self, alias: &KeyAlias) -> PathBuf {
        self.keys_dir.join(format!("{}.se", alias.as_str()))
    }

    fn meta_path(&self, alias: &KeyAlias) -> PathBuf {
        self.keys_dir.join(format!("{}.meta.json", alias.as_str()))
    }

    fn load_handle(&self, alias: &KeyAlias) -> Result<Vec<u8>, AgentError> {
        let mut cache = self.handle_cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = cache.get(alias.as_str()) {
            return Ok(h.clone());
        }
        let path = self.handle_path(alias);
        let handle = fs::read(&path).map_err(|e| {
            AgentError::StorageError(format!(
                "SE key handle not found for '{}': {e}",
                alias.as_str()
            ))
        })?;
        cache.insert(alias.as_str().to_string(), handle.clone());
        Ok(handle)
    }
}

impl KeyStorage for SecureEnclaveKeyStorage {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        role: KeyRole,
        _encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        // Ignore encrypted_key_data — generate key in SE hardware
        let mut handle_buf = vec![0u8; 512];
        let mut handle_len: usize = 0;
        let mut pubkey_buf = vec![0u8; 65];
        let mut pubkey_len: usize = 0;

        let code = unsafe {
            se_create_key(
                handle_buf.as_mut_ptr(),
                &mut handle_len,
                pubkey_buf.as_mut_ptr(),
                &mut pubkey_len,
            )
        };
        if code != 0 {
            return Err(se_error(code));
        }

        handle_buf.truncate(handle_len);

        // Write handle file
        let path = self.handle_path(alias);
        fs::write(&path, &handle_buf).map_err(|e| {
            AgentError::IO(std::io::Error::other(format!(
                "failed to write SE key handle: {e}"
            )))
        })?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok();

        // Write metadata
        let meta = KeyMetadata {
            identity_did: identity_did.to_string(),
            role: format!("{role:?}"),
        };
        let meta_json = serde_json::to_string_pretty(&meta).unwrap_or_default();
        fs::write(self.meta_path(alias), meta_json).ok();

        // Cache the handle
        let mut cache = self.handle_cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(alias.as_str().to_string(), handle_buf);

        debug!(
            "SE key created for alias '{}', pubkey {} bytes",
            alias.as_str(),
            pubkey_len
        );
        Ok(())
    }

    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
        let handle = self.load_handle(alias)?;

        // Read metadata
        let meta_path = self.meta_path(alias);
        let meta: KeyMetadata = if meta_path.exists() {
            let json = fs::read_to_string(&meta_path).map_err(|e| {
                AgentError::StorageError(format!("SE key metadata read failed: {e}"))
            })?;
            serde_json::from_str(&json).map_err(|e| {
                AgentError::KeyDeserializationError(format!("SE key metadata parse failed: {e}"))
            })?
        } else {
            KeyMetadata {
                identity_did: "unknown".to_string(),
                role: "Device".to_string(),
            }
        };

        #[allow(clippy::disallowed_methods)]
        // INVARIANT: identity_did was stored by store_key from a validated IdentityDID
        let identity_did = IdentityDID::new_unchecked(&meta.identity_did);
        let role = if meta.role.contains("NextRotation") {
            KeyRole::NextRotation
        } else if meta.role.contains("DelegatedAgent") {
            KeyRole::DelegatedAgent
        } else {
            KeyRole::Primary
        };

        Ok((identity_did, role, handle))
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        let path = self.handle_path(alias);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                AgentError::IO(std::io::Error::other(format!(
                    "failed to delete SE key handle: {e}"
                )))
            })?;
        }
        let meta_path = self.meta_path(alias);
        if meta_path.exists() {
            fs::remove_file(&meta_path).ok();
        }
        let mut cache = self.handle_cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.remove(alias.as_str());
        Ok(())
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        let mut aliases = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.keys_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(alias) = name.strip_suffix(".se") {
                    #[allow(clippy::disallowed_methods)]
                    // INVARIANT: alias comes from a filename we created in store_key
                    aliases.push(KeyAlias::new_unchecked(alias));
                }
            }
        }
        Ok(aliases)
    }

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        let all = self.list_aliases()?;
        let mut matching = Vec::new();
        for alias in all {
            if let Ok(meta_str) = fs::read_to_string(self.meta_path(&alias))
                && let Ok(meta) = serde_json::from_str::<KeyMetadata>(&meta_str)
                && meta.identity_did == identity_did.as_str()
            {
                matching.push(alias);
            }
        }
        Ok(matching)
    }

    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        let (did, _, _) = self.load_key(alias)?;
        Ok(did)
    }

    fn backend_name(&self) -> &'static str {
        "secure-enclave"
    }

    fn is_hardware_backend(&self) -> bool {
        true
    }
}

impl SecureSigner for SecureEnclaveKeyStorage {
    fn sign_with_alias(
        &self,
        alias: &KeyAlias,
        _passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        let handle = self.load_handle(alias)?;
        sign_with_handle(&handle, message)
    }

    fn sign_for_identity(
        &self,
        identity_did: &IdentityDID,
        passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        let aliases = self.list_aliases_for_identity(identity_did)?;
        let alias = aliases.first().ok_or_else(|| {
            AgentError::StorageError(format!(
                "no SE key found for identity {}",
                identity_did.as_str()
            ))
        })?;
        self.sign_with_alias(alias, passphrase_provider, message)
    }
}

/// Get the compressed P-256 public key for an SE key handle.
pub fn public_key_from_handle(handle: &[u8]) -> Result<Vec<u8>, AgentError> {
    let mut pubkey_buf = vec![0u8; 65];
    let mut pubkey_len: usize = 0;

    let code = unsafe {
        se_load_key(
            handle.as_ptr(),
            handle.len(),
            pubkey_buf.as_mut_ptr(),
            &mut pubkey_len,
        )
    };
    if code != 0 {
        return Err(se_error(code));
    }

    pubkey_buf.truncate(pubkey_len);
    Ok(pubkey_buf)
}

/// Sign a message using an SE key handle. Triggers biometric prompt.
pub fn sign_with_handle(handle: &[u8], message: &[u8]) -> Result<Vec<u8>, AgentError> {
    let mut sig_buf = vec![0u8; 64];
    let mut sig_len: usize = 0;

    let code = unsafe {
        se_sign(
            handle.as_ptr(),
            handle.len(),
            message.as_ptr(),
            message.len(),
            sig_buf.as_mut_ptr(),
            &mut sig_len,
        )
    };
    if code != 0 {
        return Err(se_error(code));
    }

    sig_buf.truncate(sig_len);
    Ok(sig_buf)
}
