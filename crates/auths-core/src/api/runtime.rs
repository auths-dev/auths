//! Application-level runtime API for managing the identity agent and keys.
//!
//! Provides functions to interact with core components: secure key storage (`KeyStorage`),
//! cryptographic operations, the in-memory agent (`AgentCore`), and the agent listener.
//! Uses `AgentHandle` for lifecycle management of agent instances.
//! Also includes functions for interacting with the platform's SSH agent (on macOS).

use crate::agent::AgentCore;
use crate::agent::AgentHandle;
#[cfg(unix)]
use crate::agent::AgentSession;
use crate::crypto::provider_bridge;
use crate::crypto::signer::extract_seed_from_key_bytes;
use crate::crypto::signer::{decrypt_keypair, encrypt_keypair};
use crate::error::AgentError;
use crate::signing::PassphraseProvider;
use crate::storage::keychain::{KeyAlias, KeyRole, KeyStorage};
use log::{debug, error, info, warn};
#[cfg(target_os = "macos")]
use pkcs8::PrivateKeyInfo;
#[cfg(target_os = "macos")]
use pkcs8::der::Decode;
#[cfg(target_os = "macos")]
use pkcs8::der::asn1::OctetString;
use serde::Serialize;
#[cfg(unix)]
use ssh_agent_lib;
#[cfg(unix)]
use ssh_agent_lib::agent::listen;
#[cfg(target_os = "macos")]
use ssh_key::Fingerprint;
use ssh_key::private::{Ed25519Keypair as SshEdKeypair, KeypairData};
use ssh_key::{
    self, LineEnding, PrivateKey as SshPrivateKey, PublicKey as SshPublicKey,
    public::Ed25519PublicKey as SshEd25519PublicKey,
};
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use tokio::net::UnixListener;
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
use std::io::Write;

#[cfg(target_os = "macos")]
use {
    std::fs::{self, Permissions},
    std::os::unix::fs::PermissionsExt,
    tempfile::Builder as TempFileBuilder,
};

#[cfg(target_os = "macos")]
#[derive(Debug)]
enum SshRegError {
    Agent(crate::ports::ssh_agent::SshAgentError),
    Io(std::io::Error),
    Conversion(String),
    BadSeedLength(usize),
}

#[cfg(target_os = "macos")]
impl std::fmt::Display for SshRegError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Agent(e) => write!(f, "ssh agent error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Conversion(s) => write!(f, "key conversion failed: {s}"),
            Self::BadSeedLength(n) => {
                write!(f, "invalid PKCS#8 seed length: expected 32 bytes, got {n}")
            }
        }
    }
}

// --- Public Structs ---

/// Represents the result of trying to load a single key into the agent core.
#[derive(Serialize, Debug, Clone)]
pub struct KeyLoadStatus {
    /// Key alias.
    pub alias: KeyAlias,
    /// Whether the key was successfully loaded.
    pub loaded: bool,
    /// Load error message, if any.
    pub error: Option<String>,
}

/// Represents the outcome of attempting to register a key with the system SSH agent.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub enum RegistrationOutcome {
    /// Key was successfully added to the agent.
    Added,
    /// Key already exists in the agent.
    AlreadyExists,
    /// The SSH agent process was not found.
    AgentNotFound,
    /// The agent command failed.
    CommandFailed,
    /// The key type is not supported by this agent.
    UnsupportedKeyType,
    /// Key format conversion failed.
    ConversionFailed,
    /// An I/O error occurred.
    IoError,
    /// An unexpected internal error occurred.
    InternalError,
}

/// Represents the status of registering a single key with the system SSH agent.
#[derive(Serialize, Debug, Clone)]
pub struct KeyRegistrationStatus {
    /// Key fingerprint.
    pub fingerprint: String,
    /// Registration outcome.
    pub status: RegistrationOutcome,
    /// Additional message, if any.
    pub message: Option<String>,
}

// --- Public API Functions ---

/// Clears all unlocked keys from the specified agent handle.
///
/// This effectively locks the agent until keys are reloaded.
///
/// # Arguments
/// * `handle` - The agent handle to clear keys from
///
/// # Example
/// ```rust,ignore
/// use auths_core::AgentHandle;
/// use auths_core::api::clear_agent_keys_with_handle;
///
/// let handle = AgentHandle::new(socket_path);
/// clear_agent_keys_with_handle(&handle)?;
/// ```
pub fn clear_agent_keys_with_handle(handle: &AgentHandle) -> Result<(), AgentError> {
    info!("Clearing all keys from agent handle.");
    let mut agent_guard = handle.lock()?;
    agent_guard.clear_keys();
    debug!("Agent keys cleared.");
    Ok(())
}

/// Loads specific keys (by alias) from secure storage into the specified agent handle.
///
/// Requires the correct passphrase for each key, obtained via the `passphrase_provider`.
/// Replaces any keys currently loaded in the agent. Stores decrypted PKCS#8 bytes securely
/// in memory using `zeroize`.
///
/// # Arguments
/// * `handle` - The agent handle to load keys into
/// * `aliases`: A list of key aliases to load from secure storage.
/// * `passphrase_provider`: A component responsible for securely obtaining passphrases.
/// * `keychain`: The key storage backend to load keys from.
///
/// # Returns
/// A `Result` containing a list of `KeyLoadStatus` structs, indicating the outcome
/// for each requested alias, or an `AgentError` if a fatal error occurs.
pub fn load_keys_into_agent_with_handle(
    handle: &AgentHandle,
    aliases: Vec<String>,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<Vec<KeyLoadStatus>, AgentError> {
    info!(
        "Attempting to load keys into agent handle for aliases: {:?}",
        aliases
    );
    if aliases.is_empty() {
        warn!("load_keys_into_agent_with_handle called with empty alias list. Clearing agent.");
        clear_agent_keys_with_handle(handle)?;
        return Ok(vec![]);
    }

    let mut load_statuses = Vec::new();
    let mut temp_unlocked_core = AgentCore::default();

    for alias in aliases {
        debug!("Processing alias for agent load: {}", alias);
        let key_alias = KeyAlias::new_unchecked(&alias);
        let mut status = KeyLoadStatus {
            alias: key_alias.clone(),
            loaded: false,
            error: None,
        };

        let load_result = || -> Result<Zeroizing<Vec<u8>>, AgentError> {
            let (_controller_did, encrypted_pkcs8) = keychain.load_key(&key_alias)?;
            let prompt = format!(
                "Enter passphrase to unlock key '{}' for agent session:",
                key_alias
            );
            let passphrase = passphrase_provider.get_passphrase(&prompt)?;
            let pkcs8_bytes = decrypt_keypair(&encrypted_pkcs8, &passphrase)?;
            let _ = extract_seed_from_key_bytes(&pkcs8_bytes).map_err(|e| {
                AgentError::KeyDeserializationError(format!(
                    "Failed to parse key for alias '{}' after decryption: {}",
                    key_alias, e
                ))
            })?;
            Ok(pkcs8_bytes)
        }();

        match load_result {
            Ok(pkcs8_bytes) => {
                info!("Successfully unlocked key for alias '{}'", key_alias);
                match temp_unlocked_core.register_key(pkcs8_bytes) {
                    Ok(()) => status.loaded = true,
                    Err(e) => {
                        error!(
                            "Failed to register key '{}' in agent core state after successful unlock/parse: {}",
                            key_alias, e
                        );
                        status.error = Some(format!(
                            "Internal error: Failed to register key in agent core state: {}",
                            e
                        ));
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to load/decrypt key for alias '{}': {}",
                    key_alias, e
                );
                match e {
                    AgentError::IncorrectPassphrase => {
                        status.error = Some("Incorrect passphrase".to_string())
                    }
                    AgentError::KeyNotFound => status.error = Some("Key not found".to_string()),
                    AgentError::UserInputCancelled => {
                        status.error = Some("Operation cancelled by user".to_string())
                    }
                    AgentError::KeyDeserializationError(_) => {
                        status.error = Some(format!("Failed to parse key after decryption: {}", e))
                    }
                    _ => status.error = Some(e.to_string()),
                }
            }
        }
        load_statuses.push(status);
    }

    // Atomically update the agent state
    let mut agent_guard = handle.lock()?;
    info!(
        "Replacing agent core with {} unlocked keys ({} aliases attempted).",
        temp_unlocked_core.key_count(),
        load_statuses.len()
    );
    *agent_guard = temp_unlocked_core;

    Ok(load_statuses)
}

/// Rotates the keypair for a given alias *in the secure storage only*.
///
/// This generates a new Ed25519 keypair, encrypts it with the `new_passphrase`,
/// and overwrites the existing entry for `alias` in the platform's keychain or
/// secure storage. The key remains associated with the *same Controller DID*
/// as the original key.
///
/// **Warning:** This function does *not* update any corresponding identity
/// representation in a Git repository (e.g., changing the Controller DID stored
/// in an identity commit or creating a KERI rotation event). Using this function
/// alone may lead to inconsistencies if the identity representation relies on the
/// public key associated with the Controller DID. It also does not automatically
/// update the key loaded in the running agent; `load_keys_into_agent` or restarting
/// the agent may be required.
///
/// # Arguments
/// * `alias`: The alias of the key entry in secure storage to rotate.
/// * `new_passphrase`: The passphrase to encrypt the *new* private key with.
///
/// # Returns
/// `Ok(())` on success, or an `AgentError` if the alias is not found, key generation
/// fails, encryption fails, or storage fails.
pub fn rotate_key(
    alias: &str,
    new_passphrase: &str,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(), AgentError> {
    info!(
        "[API] Attempting secure storage key rotation for local alias: {}",
        alias
    );
    if alias.trim().is_empty() {
        return Err(AgentError::InvalidInput(
            "Alias cannot be empty".to_string(),
        ));
    }
    if new_passphrase.is_empty() {
        return Err(AgentError::InvalidInput(
            "New passphrase cannot be empty".to_string(),
        ));
    }

    // 1. Verify the alias exists and retrieve its associated Controller DID
    let key_alias = KeyAlias::new_unchecked(alias);
    let existing_did = keychain.get_identity_for_alias(&key_alias)?;
    info!(
        "Found existing key for alias '{}', associated with Controller DID '{}'. Proceeding with rotation.",
        alias, existing_did
    );

    // 2. Generate new keypair via CryptoProvider
    let (seed, pubkey) = provider_bridge::generate_ed25519_keypair_sync()
        .map_err(|e| AgentError::CryptoError(format!("Failed to generate new keypair: {}", e)))?;
    // Build PKCS#8 v2 DER for storage compatibility
    let new_pkcs8_bytes = auths_crypto::build_ed25519_pkcs8_v2(seed.as_bytes(), &pubkey);
    debug!("Generated new keypair via CryptoProvider.");

    // 3. Encrypt the new keypair with the new passphrase
    let encrypted_new_key = encrypt_keypair(&new_pkcs8_bytes, new_passphrase)?;
    debug!("Encrypted new keypair with provided passphrase.");

    // 4. Overwrite the existing entry in secure storage with the new encrypted key,
    //    keeping the original Controller DID association.
    keychain.store_key(
        &key_alias,
        &existing_did,
        KeyRole::Primary,
        &encrypted_new_key,
    )?;
    info!(
        "Successfully overwrote secure storage for alias '{}' with new encrypted key.",
        alias
    );

    warn!(
        "Secure storage key rotated for alias '{}'. This did NOT update any Git identity representation. The running agent may still hold the old decrypted key. Consider reloading keys into the agent.",
        alias
    );
    Ok(())
}

/// Signs a message using a key currently loaded in the specified agent handle.
///
/// This retrieves the decrypted key material from the agent handle based on the
/// provided public key bytes and performs the signing operation. It does *not*
/// require a passphrase as the key is assumed to be already unlocked.
///
/// # Arguments
/// * `handle` - The agent handle containing the loaded keys
/// * `pubkey`: The public key bytes of the key to use for signing.
/// * `data`: The data bytes to sign.
///
/// # Returns
/// The raw signature bytes, or an `AgentError` if the key is not found in the
/// agent core or if the signing operation fails internally.
pub fn agent_sign_with_handle(
    handle: &AgentHandle,
    pubkey: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, AgentError> {
    debug!(
        "Agent sign request for pubkey starting with: {:x?}...",
        &pubkey[..core::cmp::min(pubkey.len(), 8)]
    );

    // Use the handle's sign method which includes lock check
    handle.sign(pubkey, data)
}

/// Exports the decrypted private key in OpenSSH PEM format.
///
/// Retrieves the encrypted key from secure storage, decrypts it using the
/// provided passphrase, and formats it as a standard OpenSSH PEM private key string.
///
/// # Arguments
/// * `alias`: The alias of the key in secure storage.
/// * `passphrase`: The passphrase to decrypt the key.
///
/// # Returns
/// A `Zeroizing<String>` containing the PEM data on success, or an `AgentError`.
pub fn export_key_openssh_pem(
    alias: &str,
    passphrase: &str,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<Zeroizing<String>, AgentError> {
    info!("Exporting PEM for local alias: {}", alias);
    if alias.trim().is_empty() {
        return Err(AgentError::InvalidInput(
            "Alias cannot be empty".to_string(),
        ));
    }
    // 1. Load encrypted key data
    let key_alias = KeyAlias::new_unchecked(alias);
    let (_controller_did, encrypted_pkcs8) = keychain.load_key(&key_alias)?;

    // 2. Decrypt key data
    let pkcs8_bytes = decrypt_keypair(&encrypted_pkcs8, passphrase)?;

    // 3. Extract seed via the consolidated SSH crypto module
    let secure_seed = crate::crypto::ssh::extract_seed_from_pkcs8(&pkcs8_bytes).map_err(|e| {
        AgentError::KeyDeserializationError(format!(
            "Failed to extract Ed25519 seed for alias '{}': {}",
            alias, e
        ))
    })?;

    let ssh_ed_keypair = SshEdKeypair::from_seed(secure_seed.as_bytes());
    let keypair_data = KeypairData::Ed25519(ssh_ed_keypair);
    // Create the private key object (comment is typically empty for PEM)
    let ssh_private_key = SshPrivateKey::new(keypair_data, "") // Empty comment
        .map_err(|e| {
            // Use CryptoError for ssh-key object creation failure
            AgentError::CryptoError(format!(
                "Failed to create ssh_key::PrivateKey for alias '{}': {}",
                alias, e
            ))
        })?;

    // 5. Format as OpenSSH PEM (uses LF line endings by default)
    let pem = ssh_private_key.to_openssh(LineEnding::LF).map_err(|e| {
        // Use CryptoError for formatting failure
        AgentError::CryptoError(format!(
            "Failed to encode OpenSSH PEM for alias '{}': {}",
            alias, e
        ))
    })?;

    debug!("Successfully generated PEM for alias '{}'", alias);
    Ok(pem) // Returns Zeroizing<String>
}

/// Exports the public key in OpenSSH `.pub` format.
///
/// Retrieves the encrypted key from secure storage, decrypts it using the
/// provided passphrase, derives the public key, and formats it as a standard
/// OpenSSH `.pub` line (including the alias as a comment).
///
/// # Arguments
/// * `alias`: The alias of the key in secure storage.
/// * `passphrase`: The passphrase to decrypt the key.
///
/// # Returns
/// A `String` containing the public key line on success, or an `AgentError`.
pub fn export_key_openssh_pub(
    alias: &str,
    passphrase: &str,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<String, AgentError> {
    info!("Exporting OpenSSH public key for local alias: {}", alias);
    if alias.trim().is_empty() {
        return Err(AgentError::InvalidInput(
            "Alias cannot be empty".to_string(),
        ));
    }
    // 1. Load encrypted key data
    let key_alias = KeyAlias::new_unchecked(alias);
    let (_controller_did, encrypted_pkcs8) = keychain.load_key(&key_alias)?;

    // 2. Decrypt key data
    let pkcs8_bytes = decrypt_keypair(&encrypted_pkcs8, passphrase)?;

    // 3. Extract seed and derive public key via CryptoProvider
    let (seed, pubkey_bytes) =
        crate::crypto::signer::load_seed_and_pubkey(&pkcs8_bytes).map_err(|e| {
            AgentError::CryptoError(format!(
                "Failed to extract key for alias '{}': {}",
                alias, e
            ))
        })?;
    let _ = seed; // seed not needed for public key export
    let ssh_ed25519_pubkey =
        SshEd25519PublicKey::try_from(pubkey_bytes.as_slice()).map_err(|e| {
            AgentError::CryptoError(format!(
                "Failed to create Ed25519PublicKey from bytes: {}",
                e
            ))
        })?;
    let key_data = ssh_key::public::KeyData::Ed25519(ssh_ed25519_pubkey);

    // 5. Create the ssh-key PublicKey object (comment is optional here)
    let ssh_pub_key = SshPublicKey::new(key_data, ""); // Use empty comment for base formatting

    // 6. Format the base public key string (type and key material)
    let pubkey_base = ssh_pub_key.to_openssh().map_err(|e| {
        // Use CryptoError for formatting failure
        AgentError::CryptoError(format!("Failed to format OpenSSH pubkey base: {}", e))
    })?;

    // 7. Manually append the alias as the comment part of the .pub line
    let formatted_pubkey = format!("{} {}", pubkey_base, alias);

    debug!(
        "Successfully generated OpenSSH public key string for alias '{}'",
        alias
    );
    Ok(formatted_pubkey)
}

/// Returns the number of keys currently loaded in the specified agent handle.
///
/// # Arguments
/// * `handle` - The agent handle to query
///
/// # Returns
/// The number of keys currently loaded.
pub fn get_agent_key_count_with_handle(handle: &AgentHandle) -> Result<usize, AgentError> {
    handle.key_count()
}

/// Attempts to register all keys currently loaded in the specified agent handle
/// with the system's running SSH agent via the injected `SshAgentPort`.
///
/// This iterates through the unlocked keys in the agent core, converts each to
/// OpenSSH PEM format, writes it to a temporary file, and delegates to the
/// provided `ssh_agent` port for the actual registration.
///
/// Args:
/// * `handle` - The agent handle containing the keys to register.
/// * `ssh_agent_socket` - Optional path to the SSH agent socket (for diagnostics).
/// * `ssh_agent` - Port implementation that registers keys with the system agent.
///
/// Usage:
/// ```ignore
/// use auths_core::api::runtime::register_keys_with_macos_agent_with_handle;
///
/// let statuses = register_keys_with_macos_agent_with_handle(&handle, None, &adapter)?;
/// ```
#[cfg(target_os = "macos")]
pub fn register_keys_with_macos_agent_with_handle(
    handle: &AgentHandle,
    ssh_agent_socket: Option<&std::path::Path>,
    ssh_agent: &dyn crate::ports::ssh_agent::SshAgentPort,
) -> Result<Vec<KeyRegistrationStatus>, AgentError> {
    info!("Attempting to register keys from agent handle with system ssh-agent...");
    if ssh_agent_socket.is_none() {
        warn!("SSH_AUTH_SOCK not configured. System ssh-agent may not be running or configured.");
    }

    let keys_to_register: Vec<(Vec<u8>, Zeroizing<Vec<u8>>)> = {
        let agent_guard = handle.lock()?;
        agent_guard
            .keys
            .iter()
            .map(|(pubkey, seed)| {
                let pubkey_arr: [u8; 32] = pubkey.as_slice().try_into().unwrap_or([0u8; 32]);
                let pkcs8 = auths_crypto::build_ed25519_pkcs8_v2(seed.as_bytes(), &pubkey_arr);
                (pubkey.clone(), Zeroizing::new(pkcs8))
            })
            .collect()
    };

    register_keys_with_macos_agent_internal(keys_to_register, ssh_agent)
}

/// Stub function for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn register_keys_with_macos_agent_with_handle(
    _handle: &AgentHandle,
    _ssh_agent_socket: Option<&std::path::Path>,
    _ssh_agent: &dyn crate::ports::ssh_agent::SshAgentPort,
) -> Result<Vec<KeyRegistrationStatus>, AgentError> {
    info!("Not on macOS, skipping system ssh-agent registration.");
    Ok(vec![])
}

/// Internal helper that performs the actual system SSH agent registration.
///
/// Converts each PKCS#8 key to OpenSSH PEM, writes to a temp file, and
/// delegates to the injected `SshAgentPort` for the actual `ssh-add` call.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_lines)]
fn register_keys_with_macos_agent_internal(
    keys_to_register: Vec<(Vec<u8>, Zeroizing<Vec<u8>>)>,
    ssh_agent: &dyn crate::ports::ssh_agent::SshAgentPort,
) -> Result<Vec<KeyRegistrationStatus>, AgentError> {
    use crate::ports::ssh_agent::SshAgentError;

    if keys_to_register.is_empty() {
        info!("No keys to register with system agent.");
        return Ok(vec![]);
    }
    info!(
        "Found {} keys to attempt registration with system agent.",
        keys_to_register.len()
    );

    let mut results = Vec::with_capacity(keys_to_register.len());

    for (pubkey_bytes, pkcs8_bytes_zeroizing) in keys_to_register.into_iter() {
        let fingerprint_str = (|| -> Result<String, AgentError> {
            let pk = SshEd25519PublicKey::try_from(pubkey_bytes.as_slice()).map_err(|e| {
                AgentError::KeyDeserializationError(format!(
                    "Invalid pubkey bytes for fingerprint: {}",
                    e
                ))
            })?;
            let ssh_pub_key: SshPublicKey =
                SshPublicKey::new(ssh_key::public::KeyData::Ed25519(pk), "");
            let fp: Fingerprint = ssh_pub_key.fingerprint(Default::default());
            Ok(fp.to_string())
        })()
        .unwrap_or_else(|e| {
            warn!(
                "Could not calculate fingerprint for key being registered: {}",
                e
            );
            "unknown_fingerprint".to_string()
        });

        let mut status = KeyRegistrationStatus {
            fingerprint: fingerprint_str.clone(),
            status: RegistrationOutcome::InternalError,
            message: None,
        };

        let result: Result<(), SshRegError> = (|| {
            let pkcs8_bytes = pkcs8_bytes_zeroizing.as_ref();
            let private_key_info = PrivateKeyInfo::from_der(pkcs8_bytes)
                .map_err(|e| SshRegError::Conversion(e.to_string()))?;
            let seed_octet_string = OctetString::from_der(private_key_info.private_key)
                .map_err(|e| SshRegError::Conversion(e.to_string()))?;
            let seed_bytes = seed_octet_string.as_bytes();
            if seed_bytes.len() != 32 {
                return Err(SshRegError::BadSeedLength(seed_bytes.len()));
            }
            // SAFETY: length validated by the 32-byte check above
            #[allow(clippy::expect_used)]
            let seed_array: [u8; 32] = seed_bytes.try_into().expect("Length checked");
            let ssh_ed_keypair = SshEdKeypair::from_seed(&seed_array);
            let keypair_data = KeypairData::Ed25519(ssh_ed_keypair);
            let ssh_private_key = SshPrivateKey::new(keypair_data, "")
                .map_err(|e| SshRegError::Conversion(e.to_string()))?;
            let pem_zeroizing = ssh_private_key
                .to_openssh(LineEnding::LF)
                .map_err(|e| SshRegError::Conversion(e.to_string()))?;
            let pem_string = pem_zeroizing.to_string();

            let mut temp_file_guard = TempFileBuilder::new()
                .prefix("auths-key-")
                .suffix(".pem")
                .rand_bytes(5)
                .tempfile()
                .map_err(SshRegError::Io)?;
            if let Err(e) =
                fs::set_permissions(temp_file_guard.path(), Permissions::from_mode(0o600))
            {
                warn!(
                    "Failed to set 600 permissions on temp file {:?}: {}. Continuing...",
                    temp_file_guard.path(),
                    e
                );
            }
            temp_file_guard
                .write_all(pem_string.as_bytes())
                .map_err(SshRegError::Io)?;
            temp_file_guard.flush().map_err(SshRegError::Io)?;
            let temp_file_path = temp_file_guard.path().to_path_buf();

            debug!(
                "Attempting ssh-add for temporary key file: {:?}",
                temp_file_path
            );
            ssh_agent
                .register_key(&temp_file_path)
                .map_err(SshRegError::Agent)?;
            debug!("ssh-add finished for {:?}", temp_file_path);
            Ok(())
        })();

        match result {
            Ok(()) => {
                info!(
                    "ssh-add successful for {}: Identity added.",
                    fingerprint_str
                );
                status.status = RegistrationOutcome::Added;
                status.message = Some("Identity added via ssh-agent port".to_string());
            }
            Err(e) => {
                match &e {
                    SshRegError::Agent(SshAgentError::NotAvailable(_)) => {
                        status.status = RegistrationOutcome::AgentNotFound;
                    }
                    SshRegError::Agent(SshAgentError::CommandFailed(_)) => {
                        status.status = RegistrationOutcome::CommandFailed;
                    }
                    SshRegError::Agent(SshAgentError::IoError(_)) | SshRegError::Io(_) => {
                        status.status = RegistrationOutcome::IoError;
                    }
                    SshRegError::Conversion(_) | SshRegError::BadSeedLength(_) => {
                        status.status = RegistrationOutcome::ConversionFailed;
                    }
                }
                error!(
                    "Error during registration process for {}: {:?}",
                    fingerprint_str, e
                );
                status.message = Some(format!("Registration error: {}", e));
            }
        }
        results.push(status);
    }

    info!(
        "Finished attempting system agent registration for {} keys.",
        results.len()
    );
    Ok(results)
}

/// Starts the SSH agent listener using the provided `AgentHandle`.
///
/// Binds to the socket path from the handle, cleans up any old socket file if present,
/// and enters an asynchronous loop (`ssh_agent_lib::listen`) to accept and handle
/// incoming agent connections using `AgentSession`.
///
/// Requires a `tokio` runtime context. Runs indefinitely on success.
///
/// # Arguments
/// * `handle`: The agent handle containing the socket path and agent core.
///
/// # Returns
/// - `Ok(())` if the listener starts successfully (runs indefinitely).
/// - `Err(AgentError)` if binding/setup fails or the listener loop exits with an error.
#[cfg(unix)]
pub async fn start_agent_listener_with_handle(handle: Arc<AgentHandle>) -> Result<(), AgentError> {
    let socket_path = handle.socket_path();
    info!("Attempting to start agent listener at {:?}", socket_path);

    // --- Ensure parent directory exists ---
    if let Some(parent) = socket_path.parent()
        && !parent.exists()
    {
        debug!("Creating parent directory for socket: {:?}", parent);
        if let Err(e) = std::fs::create_dir_all(parent) {
            error!("Failed to create parent directory {:?}: {}", parent, e);
            return Err(AgentError::IO(e));
        }
    }

    // --- Clean up existing socket file (if any) ---
    match std::fs::remove_file(socket_path) {
        Ok(()) => info!("Removed existing socket file at {:?}", socket_path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            debug!(
                "No existing socket file found at {:?}, proceeding.",
                socket_path
            );
        }
        Err(e) => {
            warn!(
                "Failed to remove existing socket file at {:?}: {}. Binding might fail.",
                socket_path, e
            );
        }
    }

    // --- Bind the listener ---
    let listener = UnixListener::bind(socket_path).map_err(|e| {
        error!("Failed to bind listener socket at {:?}: {}", socket_path, e);
        AgentError::IO(e)
    })?;

    // --- Listener started successfully ---
    let actual_path = socket_path
        .canonicalize()
        .unwrap_or_else(|_| socket_path.to_path_buf());
    info!(
        "🚀 Agent listener started successfully at {:?}",
        actual_path
    );
    info!("   Set SSH_AUTH_SOCK={:?} to use this agent.", actual_path);

    // Mark agent as running
    handle.set_running(true);

    // --- Create the agent session handler using the provided handle ---
    let session = AgentSession::new(handle.clone());

    // --- Start the main listener loop from ssh_agent_lib ---
    let result = listen(listener, session).await;

    // Mark agent as no longer running
    handle.set_running(false);

    if let Err(e) = result {
        error!("SSH Agent listener failed: {:?}", e);
        return Err(AgentError::IO(io::Error::other(format!(
            "SSH Agent listener failed: {}",
            e
        ))));
    }

    warn!("Agent listener loop exited unexpectedly without error.");
    Ok(())
}

/// Starts the SSH agent listener on the specified Unix domain socket path.
///
/// This is a convenience function that creates an `AgentHandle` internally.
/// For more control over the agent lifecycle, use `start_agent_listener_with_handle`
/// with your own `AgentHandle`.
///
/// Requires a `tokio` runtime context. Runs indefinitely on success.
///
/// # Arguments
/// * `socket_path_str`: The filesystem path for the Unix domain socket.
///
/// # Returns
/// - `Ok(())` if the listener starts successfully (runs indefinitely).
/// - `Err(AgentError)` if binding/setup fails or the listener loop exits with an error.
#[cfg(unix)]
pub async fn start_agent_listener(socket_path_str: String) -> Result<(), AgentError> {
    use std::path::PathBuf;
    let handle = Arc::new(AgentHandle::new(PathBuf::from(&socket_path_str)));
    start_agent_listener_with_handle(handle).await
}
