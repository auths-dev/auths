use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use der::{
    Encode,
    asn1::{ObjectIdentifier, OctetStringRef},
};
use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo};
use serde::Serialize;
use std::ffi::CString;
use std::fs;
use std::path::PathBuf;

use auths_core::api::ffi;
use auths_core::crypto::signer::encrypt_keypair;
use auths_core::error::AgentError;
use auths_core::storage::encrypted_file::EncryptedFileStorage;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage, get_platform_keychain};
use zeroize::{Zeroize, Zeroizing};

use crate::core::types::ExportFormat;
use crate::ux::format::{JsonResponse, is_json_mode};

// Standard Object Identifier (OID) for the Ed25519 signature algorithm (RFC 8410),
// required for standards-compliant structures like PKCS#8 PrivateKeyInfo.
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[derive(Parser, Debug, Clone)]
#[command(
    name = "key",
    about = "Manage local cryptographic keys in secure storage (list, import, export, delete)."
)]
pub struct KeyCommand {
    #[command(subcommand)]
    pub command: KeySubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum KeySubcommand {
    /// List aliases of all keys stored in the platform's secure storage.
    List,

    /// Export a stored key in various formats (requires passphrase for some formats).
    Export {
        /// Local alias of the key to export.
        #[arg(long, help = "Local alias of the key to export.")]
        alias: String,

        /// Passphrase to decrypt the key (needed for 'pem'/'pub' formats).
        #[arg(
            long,
            help = "Passphrase to decrypt the key (needed for 'pem'/'pub' formats)."
        )]
        passphrase: String,

        /// Export format: pem (OpenSSH private), pub (OpenSSH public), enc (raw encrypted bytes).
        #[arg(
            long,
            help = "Export format: pem (OpenSSH private), pub (OpenSSH public), enc (raw encrypted bytes)."
        )]
        format: ExportFormat,
    },

    /// Remove a key from the platform's secure storage by alias.
    Delete {
        /// Local alias of the key to remove.
        #[arg(long, help = "Local alias of the key to remove.")]
        alias: String,
    },

    /// Import an Ed25519 key from a 32-byte seed file and store it encrypted.
    Import {
        /// Local alias to assign to the imported key.
        #[arg(long, help = "Local alias to assign to the imported key.")]
        alias: String,

        /// Path to the file containing the raw 32-byte Ed25519 seed.
        #[arg(
            long,
            value_parser, // Add value_parser for PathBuf
            help = "Path to the file containing the raw 32-byte Ed25519 seed."
        )]
        seed_file: PathBuf,

        /// Controller DID (e.g., did:key:...) to associate with the imported key.
        #[arg(
            long,
            help = "Controller DID (e.g., did:key:...) to associate with the imported key."
        )]
        controller_did: String,
    },

    /// Copy a key from the current keychain backend to a different backend.
    ///
    /// Useful for creating a file-based keychain for headless CI environments without
    /// exposing the raw key material. The encrypted key bytes are copied as-is; the
    /// same passphrase used to store the key in the source backend must be used when
    /// loading it from the destination.
    ///
    /// Examples:
    ///   # Copy to file keychain (passphrase from env var)
    ///   AUTHS_PASSPHRASE="$CI_PASS" auths key copy-backend \
    ///     --alias ci-release-device --dst-backend file --dst-file /tmp/ci-keychain.enc
    ///
    ///   # Copy to file keychain (passphrase from flag)
    ///   auths key copy-backend --alias ci-release-device \
    ///     --dst-backend file --dst-file /tmp/ci-keychain.enc --dst-passphrase "$CI_PASS"
    CopyBackend {
        /// Alias of the key to copy from the current (source) keychain.
        #[arg(long)]
        alias: String,

        /// Destination backend type. Currently supported: "file".
        #[arg(long)]
        dst_backend: String,

        /// Path for the destination file keychain (required when --dst-backend is "file").
        #[arg(long)]
        dst_file: Option<PathBuf>,

        /// Passphrase for the destination file keychain.
        /// If omitted, the AUTHS_PASSPHRASE environment variable is used.
        #[arg(long)]
        dst_passphrase: Option<String>,
    },
}

pub fn handle_key(cmd: KeyCommand) -> Result<()> {
    match cmd.command {
        KeySubcommand::List => key_list(),
        KeySubcommand::Export {
            alias,
            passphrase,
            format,
        } => key_export(&alias, &passphrase, format),
        KeySubcommand::Delete { alias } => key_delete(&alias),
        KeySubcommand::Import {
            alias,
            seed_file,
            controller_did,
        } => {
            let identity_did = IdentityDID::new(controller_did);
            key_import(&alias, &seed_file, &identity_did)
        }
        KeySubcommand::CopyBackend {
            alias,
            dst_backend,
            dst_file,
            dst_passphrase,
        } => key_copy_backend(
            &alias,
            &dst_backend,
            dst_file.as_ref(),
            dst_passphrase.as_deref(),
        ),
    }
}

/// JSON response for key list command.
#[derive(Debug, Serialize)]
struct KeyListResponse {
    backend: String,
    aliases: Vec<String>,
    count: usize,
}

/// Lists all key aliases stored in the platform's secure storage.
fn key_list() -> Result<()> {
    let keychain: Box<dyn KeyStorage> = get_platform_keychain()?;
    let backend_name = keychain.backend_name().to_string();

    let aliases = match keychain.list_aliases() {
        Ok(a) => a,
        Err(AgentError::SecurityError(msg))
            if cfg!(target_os = "macos") && msg.contains("-25300") =>
        {
            // Handle macOS 'item not found' gracefully
            Vec::new()
        }
        Err(e) => return Err(e.into()),
    };

    if is_json_mode() {
        let alias_strings: Vec<String> = aliases.iter().map(|a| a.to_string()).collect();
        let count = alias_strings.len();
        let response = JsonResponse::success(
            "key list",
            KeyListResponse {
                backend: backend_name,
                aliases: alias_strings,
                count,
            },
        );
        response.print()?;
    } else {
        // Use eprintln for status messages to not interfere with potential stdout parsing
        eprintln!("Using keychain backend: {}", backend_name);

        if aliases.is_empty() {
            println!("No keys found in keychain for this application.");
        } else {
            println!("Stored keys:");
            for alias in aliases {
                println!("- {}", alias);
            }
        }
    }

    Ok(())
}

/// Exports a stored key in one of several formats using FFI calls.
#[inline]
fn key_export(alias: &str, passphrase: &str, format: ExportFormat) -> Result<()> {
    let c_alias = CString::new(alias).context("Alias contains null byte")?;
    let c_passphrase = CString::new(passphrase).context("Passphrase contains null byte")?;

    match format {
        ExportFormat::Pem => {
            let ptr = unsafe {
                ffi::ffi_export_private_key_openssh(c_alias.as_ptr(), c_passphrase.as_ptr())
            };
            if ptr.is_null() {
                anyhow::bail!(
                    "❌ Failed to export PEM private key (check alias/passphrase or logs)"
                );
            }
            let pem_string = unsafe {
                // Safety: ptr is not null and points to a C string allocated by FFI
                let c_str = std::ffi::CStr::from_ptr(ptr);
                let rust_str = c_str
                    .to_str()
                    .context("Failed to convert PEM FFI string to UTF-8")?
                    .to_owned(); // Own the string before freeing ptr
                ffi::ffi_free_str(ptr); // Free immediately after copying
                rust_str
            };
            println!("{}", pem_string); // Print the owned Rust string
        }
        ExportFormat::Pub => {
            let ptr = unsafe {
                ffi::ffi_export_public_key_openssh(c_alias.as_ptr(), c_passphrase.as_ptr())
            };
            if ptr.is_null() {
                anyhow::bail!("❌ Failed to export public key (check alias/passphrase or logs)");
            }
            let pub_string = unsafe {
                // Safety: ptr is not null and points to a C string allocated by FFI
                let c_str = std::ffi::CStr::from_ptr(ptr);
                let rust_str = c_str
                    .to_str()
                    .context("Failed to convert Pubkey FFI string to UTF-8")?
                    .to_owned();
                ffi::ffi_free_str(ptr);
                rust_str
            };
            println!("{}", pub_string);
        }
        ExportFormat::Enc => {
            let mut out_len: usize = 0;
            let buf_ptr = unsafe { ffi::ffi_export_encrypted_key(c_alias.as_ptr(), &mut out_len) };
            if buf_ptr.is_null() {
                anyhow::bail!(
                    "❌ Failed to export encrypted private key (key not found or FFI error)"
                );
            }
            let slice_data = unsafe {
                // Safety: buf_ptr is not null and out_len is set by FFI
                let slice = std::slice::from_raw_parts(buf_ptr, out_len);
                let data = slice.to_vec(); // Copy data before freeing
                ffi::ffi_free_bytes(buf_ptr, out_len); // Free immediately
                data
            };
            println!("{}", hex::encode(slice_data)); // Print hex of copied data
        }
    }

    Ok(())
}

/// Deletes a key from the platform's secure storage by its alias.
fn key_delete(alias: &str) -> Result<()> {
    let keychain: Box<dyn KeyStorage> = get_platform_keychain()?;
    eprintln!("🔍 Using keychain backend: {}", keychain.backend_name());

    match keychain.delete_key(&KeyAlias::new_unchecked(alias)) {
        Ok(_) => {
            println!("🗑️ Removed key alias '{}'", alias); // Print confirmation to stdout
            Ok(())
        }
        Err(AgentError::KeyNotFound) => {
            eprintln!("ℹ️ Key alias '{}' not found, nothing to remove.", alias);
            Ok(()) // Treat 'not found' as success for delete idempotency
        }
        Err(err) => {
            // Propagate other errors
            Err(anyhow!(err)).context(format!("Failed to remove key '{}'", alias))
        }
    }
}

/// Imports an Ed25519 key from a 32-byte seed file, encrypts, and stores it.
fn key_import(alias: &str, seed_file_path: &PathBuf, controller_did: &IdentityDID) -> Result<()> {
    println!("🔑 Importing key...");
    println!("   Local Keychain Alias: {}", alias);
    println!("   Seed File:           {:?}", seed_file_path);
    println!("   Controller DID:      {}", controller_did);

    // Input validation
    if alias.trim().is_empty() {
        return Err(anyhow!("Key alias cannot be empty."));
    }
    if !controller_did.as_str().starts_with("did:") {
        return Err(anyhow!("Invalid Controller DID format: {}", controller_did));
    }

    // Read and validate seed file
    if !seed_file_path.exists() {
        return Err(anyhow!("Seed file not found: {:?}", seed_file_path));
    }
    let seed_bytes = fs::read(seed_file_path)
        .with_context(|| format!("Failed to read seed file: {:?}", seed_file_path))?;
    if seed_bytes.len() != 32 {
        return Err(anyhow!(
            "Seed file must contain exactly 32 bytes, found {}.",
            seed_bytes.len()
        ));
    }

    println!("   Generating standard PKCS#8 v1 DER representation from seed...");

    // Generate PKCS#8 DER from Seed
    let key_algo = AlgorithmIdentifierRef {
        oid: OID_ED25519,
        parameters: None,
    };
    let private_key_octet_string_ref = OctetStringRef::new(&seed_bytes)?;
    let pkcs8_info_to_encode = PrivateKeyInfo {
        algorithm: key_algo,
        private_key: private_key_octet_string_ref.as_bytes(),
        public_key: None,
    };
    let pkcs8_bytes = pkcs8_info_to_encode
        .to_der()
        .map_err(|e| anyhow!("Failed to encode PKCS#8 structure to DER: {}", e))?;

    let passphrase = if let Ok(env_pass) = std::env::var("AUTHS_PASSPHRASE") {
        env_pass
    } else {
        rpassword::prompt_password(format!("Enter passphrase to encrypt the key '{}': ", alias))
            .context("Failed to read passphrase")?
    };
    if passphrase.is_empty() {
        return Err(anyhow!("Passphrase cannot be empty."));
    }

    // Encrypt Private Key (PKCS#8 bytes)
    println!("   Encrypting private key...");
    let encrypted_private_key =
        encrypt_keypair(&pkcs8_bytes, &passphrase).context("Failed to encrypt private key")?;

    // Store Encrypted Key
    let keychain = get_platform_keychain()?;
    println!(
        "   Storing encrypted key in platform Keychain/secure storage ({})",
        keychain.backend_name()
    );
    match keychain.store_key(
        &KeyAlias::new_unchecked(alias),
        controller_did,
        &encrypted_private_key,
    ) {
        Ok(_) => {
            println!(
                "\n✅ Successfully imported and stored key with alias '{}'",
                alias
            );
            println!("   Associated with Controller DID: {}", controller_did);
            Ok(())
        }
        Err(e) => Err(anyhow!("Failed to store imported key: {}", e)),
    }
}

/// Copies a key from the current (source) keychain to a different destination backend.
///
/// The encrypted key bytes are transferred as-is — no re-encryption occurs. The same
/// passphrase used when the key was originally stored must be used to load it later.
///
/// For the file backend, the destination file keychain is protected by an additional
/// file-level passphrase supplied via `--dst-passphrase` or `AUTHS_PASSPHRASE`.
fn key_copy_backend(
    alias: &str,
    dst_backend: &str,
    dst_file: Option<&PathBuf>,
    dst_passphrase: Option<&str>,
) -> Result<()> {
    // Load the encrypted key bytes from the source keychain (no decryption).
    let src_keychain = get_platform_keychain()?;
    eprintln!("Source backend: {}", src_keychain.backend_name());

    let key_alias = KeyAlias::new_unchecked(alias);
    let (identity_did, mut encrypted_key_data) = src_keychain
        .load_key(&key_alias)
        .with_context(|| format!("Key '{}' not found in source keychain", alias))?;

    // Build destination storage.
    let dst_storage: Box<dyn KeyStorage> = match dst_backend.to_lowercase().as_str() {
        "file" => {
            let path = dst_file
                .ok_or_else(|| anyhow!("--dst-file is required when --dst-backend is 'file'"))?;
            let storage = EncryptedFileStorage::with_path(path.clone())
                .context("Failed to create destination file storage")?;
            // Passphrase priority: explicit flag > AUTHS_PASSPHRASE env var > error.
            // Wrap immediately in Zeroizing so the heap allocation is cleared on drop.
            let password: Zeroizing<String> = dst_passphrase
                .map(|s| Zeroizing::new(s.to_string()))
                .or_else(|| std::env::var("AUTHS_PASSPHRASE").ok().map(Zeroizing::new))
                .ok_or_else(|| {
                    anyhow!(
                        "Passphrase required for file backend. \
                        Use --dst-passphrase or set the AUTHS_PASSPHRASE env var."
                    )
                })?;
            storage.set_password(password);
            Box::new(storage)
        }
        other => {
            encrypted_key_data.zeroize();
            return Err(anyhow!(
                "Unknown destination backend '{}'. Supported values: file",
                other
            ));
        }
    };

    eprintln!("Destination backend: {}", dst_storage.backend_name());

    let result = dst_storage
        .store_key(&key_alias, &identity_did, &encrypted_key_data)
        .with_context(|| format!("Failed to store key '{}' in destination backend", alias));

    // Zeroize the encrypted key bytes regardless of whether store succeeded.
    encrypted_key_data.zeroize();

    result?;
    eprintln!(
        "✓ Copied key '{}' ({}) to {}",
        alias, identity_did, dst_backend
    );
    Ok(())
}

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for KeyCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        handle_key(self.clone())
    }
}
