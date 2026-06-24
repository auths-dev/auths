//! Application-level runtime API for managing the identity agent and keys.
//!
//! Provides functions to interact with core components: secure key storage (`KeyStorage`),
//! cryptographic operations, the in-memory agent (`AgentCore`), and the agent listener.
//! Uses `AgentHandle` for lifecycle management of agent instances.
//! Also includes functions for interacting with the platform's SSH agent (on macOS).

use crate::agent::AgentCore;
use crate::agent::AgentHandle;
#[cfg(unix)]
use crate::agent::PeerAuthorizedAgent;
use crate::crypto::provider_bridge;
use crate::crypto::signer::extract_seed_from_key_bytes;
use crate::crypto::signer::{decrypt_keypair, encrypt_keypair};
use crate::error::AgentError;
use crate::signing::{PassphraseProvider, PrefilledPassphraseProvider};
use crate::storage::keychain::{KeyAlias, KeyRole, KeyStorage};
use log::{debug, error, info, warn};
#[cfg(target_os = "macos")]
use p256::pkcs8::DecodePrivateKey;
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

/// Compute the SSH fingerprint for a public key of the given curve.
#[cfg(target_os = "macos")]
fn compute_ssh_fingerprint(pubkey_bytes: &[u8], curve: auths_crypto::CurveType) -> String {
    let key_data = match curve {
        auths_crypto::CurveType::Ed25519 => SshEd25519PublicKey::try_from(pubkey_bytes)
            .map(ssh_key::public::KeyData::Ed25519)
            .ok(),
        auths_crypto::CurveType::P256 => {
            ssh_key::public::EcdsaPublicKey::from_sec1_bytes(pubkey_bytes)
                .ok()
                .map(ssh_key::public::KeyData::Ecdsa)
        }
    };
    match key_data {
        Some(kd) => SshPublicKey::new(kd, "")
            .fingerprint(Default::default())
            .to_string(),
        None => {
            warn!("Could not build public key for fingerprint computation");
            "unknown_fingerprint".to_string()
        }
    }
}

/// Parse a PKCS#8 key blob into an `ssh_key::private::KeypairData` variant matching the curve.
#[cfg(target_os = "macos")]
fn build_ssh_keypair_data(
    pkcs8_bytes: &[u8],
    curve: auths_crypto::CurveType,
) -> Result<KeypairData, SshRegError> {
    match curve {
        auths_crypto::CurveType::Ed25519 => {
            let private_key_info = PrivateKeyInfo::from_der(pkcs8_bytes)
                .map_err(|e| SshRegError::Conversion(e.to_string()))?;
            let seed_octet_string = OctetString::from_der(private_key_info.private_key)
                .map_err(|e| SshRegError::Conversion(e.to_string()))?;
            let seed_bytes = seed_octet_string.as_bytes();
            if seed_bytes.len() != 32 {
                return Err(SshRegError::BadSeedLength(seed_bytes.len()));
            }
            #[allow(clippy::expect_used)]
            // INVARIANT: length validated by the 32-byte check above.
            let seed_array: [u8; 32] = seed_bytes.try_into().expect("Length checked");
            Ok(KeypairData::Ed25519(SshEdKeypair::from_seed(&seed_array)))
        }
        auths_crypto::CurveType::P256 => {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            use ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey};

            let secret = p256::SecretKey::from_pkcs8_der(pkcs8_bytes)
                .map_err(|e| SshRegError::Conversion(format!("P-256 PKCS#8 parse failed: {e}")))?;
            let public = secret.public_key();
            Ok(KeypairData::Ecdsa(EcdsaKeypair::NistP256 {
                public: public.to_encoded_point(false),
                private: EcdsaPrivateKey::from(secret),
            }))
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
            if keychain.is_hardware_backend() {
                return Err(AgentError::HardwareKeyNotExportable {
                    operation: "agent key load".to_string(),
                });
            }
            let (_controller_did, _role, encrypted_pkcs8) = keychain.load_key(&key_alias)?;
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
    if keychain.is_hardware_backend() {
        return Err(AgentError::HardwareKeyNotExportable {
            operation: "OpenSSH private key export".to_string(),
        });
    }
    // 1. Load encrypted key data
    let key_alias = KeyAlias::new_unchecked(alias);
    let (_controller_did, _role, encrypted_pkcs8) = keychain.load_key(&key_alias)?;

    // 2. Decrypt key data
    let pkcs8_bytes = decrypt_keypair(&encrypted_pkcs8, passphrase)?;

    // 3. Parse the key material (auto-detects curve)
    let parsed = auths_crypto::parse_key_material(&pkcs8_bytes[..]).map_err(|e| {
        AgentError::KeyDeserializationError(format!(
            "Failed to parse key material for alias '{}': {}",
            alias, e
        ))
    })?;

    let keypair_data = build_openssh_keypair_data(&parsed).map_err(|e| {
        AgentError::CryptoError(format!(
            "Failed to build SSH keypair for alias '{}': {}",
            alias, e
        ))
    })?;

    let ssh_private_key = SshPrivateKey::new(keypair_data, "").map_err(|e| {
        AgentError::CryptoError(format!(
            "Failed to create ssh_key::PrivateKey for alias '{}': {}",
            alias, e
        ))
    })?;

    let pem = ssh_private_key.to_openssh(LineEnding::LF).map_err(|e| {
        AgentError::CryptoError(format!(
            "Failed to encode OpenSSH PEM for alias '{}': {}",
            alias, e
        ))
    })?;

    debug!("Successfully generated PEM for alias '{}'", alias);
    Ok(pem)
}

/// Build `ssh_key::private::KeypairData` from a parsed key material, dispatching on curve.
fn build_openssh_keypair_data(parsed: &auths_crypto::ParsedKey) -> Result<KeypairData, String> {
    match parsed.seed.curve() {
        auths_crypto::CurveType::Ed25519 => Ok(KeypairData::Ed25519(SshEdKeypair::from_seed(
            parsed.seed.as_bytes(),
        ))),
        auths_crypto::CurveType::P256 => {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            use ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey};

            let secret = p256::SecretKey::from_slice(parsed.seed.as_bytes())
                .map_err(|e| format!("P-256 secret key parse: {e}"))?;
            let public = secret.public_key();
            Ok(KeypairData::Ecdsa(EcdsaKeypair::NistP256 {
                public: public.to_encoded_point(false),
                private: EcdsaPrivateKey::from(secret),
            }))
        }
    }
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
    // 1. Obtain public key bytes (hardware-aware; SE returns pubkey without decryption)
    let key_alias = KeyAlias::new_unchecked(alias);
    let passphrase_provider = PrefilledPassphraseProvider::new(passphrase);
    let (pubkey_bytes, curve) = crate::storage::keychain::extract_public_key_bytes(
        keychain,
        &key_alias,
        &passphrase_provider,
    )?;
    let key_data = match curve {
        auths_crypto::CurveType::Ed25519 => {
            let pk = SshEd25519PublicKey::try_from(pubkey_bytes.as_slice()).map_err(|e| {
                AgentError::CryptoError(format!(
                    "Failed to create Ed25519PublicKey from bytes: {}",
                    e
                ))
            })?;
            ssh_key::public::KeyData::Ed25519(pk)
        }
        auths_crypto::CurveType::P256 => {
            let pk = ssh_key::public::EcdsaPublicKey::from_sec1_bytes(pubkey_bytes.as_slice())
                .map_err(|e| {
                    AgentError::CryptoError(format!(
                        "Failed to create EcdsaPublicKey from bytes: {}",
                        e
                    ))
                })?;
            ssh_key::public::KeyData::Ecdsa(pk)
        }
    };

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
#[allow(clippy::disallowed_methods)]
// INVARIANT: macOS SSH agent registration — temp file creation and permissions are inherently I/O
#[allow(clippy::disallowed_types)]
pub fn register_keys_with_macos_agent_with_handle(
    handle: &AgentHandle,
    ssh_agent_socket: Option<&std::path::Path>,
    ssh_agent: &dyn crate::ports::ssh_agent::SshAgentPort,
) -> Result<Vec<KeyRegistrationStatus>, AgentError> {
    info!("Attempting to register keys from agent handle with system ssh-agent...");
    if ssh_agent_socket.is_none() {
        warn!("SSH_AUTH_SOCK not configured. System ssh-agent may not be running or configured.");
    }

    let keys_to_register: Vec<(Vec<u8>, auths_crypto::CurveType, Zeroizing<Vec<u8>>)> = {
        let agent_guard = handle.lock()?;
        agent_guard
            .keys
            .iter()
            .filter_map(|(pubkey, stored)| {
                let typed_seed = match stored.curve {
                    auths_crypto::CurveType::Ed25519 => {
                        auths_crypto::TypedSeed::Ed25519(*stored.seed.as_bytes())
                    }
                    auths_crypto::CurveType::P256 => {
                        auths_crypto::TypedSeed::P256(*stored.seed.as_bytes())
                    }
                };
                let signer = auths_crypto::TypedSignerKey::from_seed(typed_seed).ok()?;
                let pkcs8 = signer.to_pkcs8().ok()?;
                Some((
                    pubkey.clone(),
                    stored.curve,
                    Zeroizing::new(pkcs8.as_ref().to_vec()),
                ))
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
    keys_to_register: Vec<(Vec<u8>, auths_crypto::CurveType, Zeroizing<Vec<u8>>)>,
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

    for (pubkey_bytes, curve, pkcs8_bytes_zeroizing) in keys_to_register.into_iter() {
        let fingerprint_str = compute_ssh_fingerprint(&pubkey_bytes, curve);

        let mut status = KeyRegistrationStatus {
            fingerprint: fingerprint_str.clone(),
            status: RegistrationOutcome::InternalError,
            message: None,
        };

        let result: Result<(), SshRegError> = (|| {
            let pkcs8_bytes = pkcs8_bytes_zeroizing.as_ref();
            let keypair_data = build_ssh_keypair_data(pkcs8_bytes, curve)?;
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

/// Ensures the directory that holds the agent socket is restricted to the owner.
///
/// If the directory does not exist it is created (with parents) and locked to `0o700`.
/// If it already exists it is accepted only when it is already owner-only (no group or
/// other access) and owned by this user; otherwise it is refused (fail closed) rather
/// than silently widening or narrowing a directory the agent did not create. A
/// non-directory or a symlink at the path is also refused.
///
/// Args:
/// * `dir`: The directory the socket lives in.
///
/// Usage:
/// ```ignore
/// harden_socket_dir(socket_path.parent().expect("socket has a parent"))?;
/// ```
#[cfg(unix)]
fn harden_socket_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_dir() => {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "socket directory {dir:?} is group/other-accessible (mode {mode:o}); refusing"
                    ),
                ));
            }
            if meta.uid() != current_euid() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("socket directory {dir:?} is not owned by this user; refusing"),
                ));
            }
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("socket directory path {dir:?} exists but is not a directory; refusing"),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        }
        Err(e) => Err(e),
    }
}

/// Restricts a bound agent socket to owner-only read/write (`0o600`) so only the
/// owning user can connect and request signatures.
///
/// This is best-effort defense-in-depth: there is a brief window between `bind` and
/// this call. The authoritative, race-free control is the owner-only (`0o700`) socket
/// directory established by [`harden_socket_dir`] — no other user can traverse into it
/// to reach the socket regardless of the socket file's own mode.
///
/// Args:
/// * `socket_path`: The path of the already-bound Unix-domain socket.
///
/// Usage:
/// ```ignore
/// harden_socket_file(socket_path)?;
/// ```
#[cfg(unix)]
fn harden_socket_file(socket_path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
}

/// Returns the directory that must be restricted to the owner for a given socket
/// path, refusing a path that has no such directory (a bare relative name) rather
/// than leaving the socket in an unrestricted location.
///
/// Args:
/// * `socket_path`: The socket path whose containing directory will be locked down.
///
/// Usage:
/// ```ignore
/// let dir = socket_dir_to_harden(socket_path)?;
/// ```
#[cfg(unix)]
fn socket_dir_to_harden(socket_path: &std::path::Path) -> Result<&std::path::Path, AgentError> {
    match socket_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Ok(parent),
        _ => Err(AgentError::IO(io::Error::new(
            io::ErrorKind::InvalidInput,
            "agent socket path must include a directory that can be restricted to the owner",
        ))),
    }
}

/// Returns the effective user id of the current process — the only user permitted
/// to connect to the agent socket.
#[cfg(unix)]
fn current_euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, has no preconditions, and always succeeds.
    unsafe { libc::geteuid() }
}

/// Chooses how often to check the agent for auto-lock, bounded to a sensible range.
/// Returns `None` when both the idle timeout and the absolute unlock cap are disabled.
#[cfg(unix)]
fn idle_monitor_interval(
    idle_timeout: std::time::Duration,
    max_unlock_ttl: std::time::Duration,
) -> Option<std::time::Duration> {
    use std::time::Duration;
    let shortest = [idle_timeout, max_unlock_ttl]
        .into_iter()
        .filter(|d| !d.is_zero())
        .min()?;
    Some((shortest / 4).clamp(Duration::from_secs(1), Duration::from_secs(60)))
}

/// Locks the agent once it has been idle past its timeout, clearing its keys, so a
/// single unlock does not leave signing capability available indefinitely.
///
/// Runs until the agent stops; intended to be spawned in the background.
///
/// Args:
/// * `handle`: The agent handle to monitor and lock when idle.
/// * `interval`: How often to check for idle timeout.
///
/// Usage:
/// ```ignore
/// tokio::spawn(run_idle_monitor(handle.clone(), interval));
/// ```
#[cfg(unix)]
async fn run_idle_monitor(handle: Arc<AgentHandle>, interval: std::time::Duration) {
    loop {
        tokio::time::sleep(interval).await;
        if !handle.is_running() {
            break;
        }
        if let Err(e) = handle.check_idle_timeout() {
            warn!("Idle timeout check failed: {e}");
        }
    }
}

/// Starts the SSH agent listener using the provided `AgentHandle`.
///
/// Binds to the socket path from the handle, restricts the socket and its directory
/// to the owner, and enters an asynchronous loop (`ssh_agent_lib::listen`) that
/// authorizes each connection by peer UID before serving it.
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
#[allow(clippy::disallowed_methods)] // INVARIANT: Unix socket lifecycle — socket dir creation and cleanup is inherently I/O
pub async fn start_agent_listener_with_handle(handle: Arc<AgentHandle>) -> Result<(), AgentError> {
    let socket_path = handle.socket_path();
    info!("Attempting to start agent listener at {:?}", socket_path);

    // --- Ensure the socket lives in an owner-only directory ---
    let socket_dir = socket_dir_to_harden(socket_path)?;
    if let Err(e) = harden_socket_dir(socket_dir) {
        error!(
            "Failed to prepare owner-only socket directory {:?}: {}",
            socket_dir, e
        );
        return Err(AgentError::IO(e));
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

    // --- Restrict the socket to the owner before serving any request ---
    if let Err(e) = harden_socket_file(socket_path) {
        error!(
            "Failed to restrict agent socket {:?} to owner-only: {}",
            socket_path, e
        );
        return Err(AgentError::IO(e));
    }

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

    // --- Auto-lock the agent after it has been idle, or unlocked past its cap ---
    if let Some(interval) = idle_monitor_interval(handle.idle_timeout(), handle.max_unlock_ttl()) {
        tokio::spawn(run_idle_monitor(handle.clone(), interval));
    }

    // --- Create the peer-authorizing session factory ---
    // Per-request signing is gated by an injected SignAuthorizer. The default is
    // permissive (preserves existing behavior); a host enables per-caller approval by
    // injecting a PerCallerAuthorizer backed by a platform biometric / approval prompt.
    let authorizer: Arc<dyn crate::agent::SignAuthorizer> = Arc::new(crate::agent::AllowAllSigning);
    let agent = PeerAuthorizedAgent::new(handle.clone(), current_euid(), authorizer);

    // --- Start the main listener loop from ssh_agent_lib ---
    let result = listen(listener, agent).await;

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

#[cfg(all(test, unix))]
mod hardening_tests {
    use super::{
        AgentHandle, harden_socket_dir, harden_socket_file, idle_monitor_interval,
        run_idle_monitor, socket_dir_to_harden,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    fn mode_of(path: &std::path::Path) -> u32 {
        match std::fs::metadata(path) {
            Ok(meta) => meta.permissions().mode() & 0o777,
            Err(e) => panic!("metadata({path:?}): {e}"),
        }
    }

    #[test]
    fn socket_dir_is_owner_only_after_harden() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("auths-agent");
        harden_socket_dir(&dir).expect("harden dir");
        assert!(dir.is_dir(), "directory must be created");
        assert_eq!(
            mode_of(&dir),
            0o700,
            "agent socket directory must be owner-only (0o700)"
        );
    }

    #[test]
    fn socket_file_is_owner_only_after_harden() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind socket");
        harden_socket_file(&sock).expect("harden socket");
        assert_eq!(
            mode_of(&sock),
            0o600,
            "agent socket must be owner-only (0o600) so no other process can connect"
        );
    }

    #[test]
    fn refuses_preexisting_group_accessible_socket_dir() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("loose");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A pre-existing directory we did not lock down must be refused, not narrowed.
        assert!(harden_socket_dir(&dir).is_err());
        assert_eq!(
            mode_of(&dir),
            0o755,
            "must not silently chmod a directory it does not own"
        );
    }

    #[test]
    fn accepts_preexisting_owner_only_socket_dir() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("tight");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(harden_socket_dir(&dir).is_ok());
    }

    #[test]
    fn socket_with_no_restrictable_directory_is_rejected() {
        // A bare/relative socket name has no directory we can lock down to 0o700,
        // so the listener must refuse it rather than skip directory hardening.
        assert!(socket_dir_to_harden(std::path::Path::new("agent.sock")).is_err());
        assert!(socket_dir_to_harden(std::path::Path::new("")).is_err());
        let dir = socket_dir_to_harden(std::path::Path::new("/home/u/.auths/agent.sock"))
            .expect("an absolute socket path has a directory to harden");
        assert_eq!(dir, std::path::Path::new("/home/u/.auths"));
    }

    #[test]
    fn idle_monitor_disabled_when_timeout_is_zero() {
        assert!(idle_monitor_interval(Duration::ZERO, Duration::ZERO).is_none());
    }

    #[test]
    fn idle_monitor_interval_is_bounded() {
        let interval = idle_monitor_interval(
            Duration::from_secs(30 * 60),
            Duration::from_secs(8 * 60 * 60),
        )
        .expect("some interval");
        assert!(interval >= Duration::from_secs(1));
        assert!(interval <= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn idle_monitor_locks_idle_agent() {
        let handle = Arc::new(AgentHandle::with_timeout(
            PathBuf::from("/tmp/idle-monitor.sock"),
            Duration::from_millis(80),
        ));
        handle.set_running(true);
        assert!(!handle.is_agent_locked());

        tokio::spawn(run_idle_monitor(handle.clone(), Duration::from_millis(20)));
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(
            handle.is_agent_locked(),
            "an agent left idle past its timeout must auto-lock"
        );
    }
}
