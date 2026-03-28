use anyhow::{Context, Result, anyhow};
use clap::{ArgAction, Parser, Subcommand};
use ring::signature::KeyPair;
use serde::Serialize;
use serde_json;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use auths_core::{
    config::EnvironmentConfig,
    signing::PassphraseProvider,
    storage::keychain::{KeyAlias, get_platform_keychain},
};
use auths_verifier::{IdentityBundle, IdentityDID, Prefix};
use clap::ValueEnum;

use crate::commands::registry_overrides::RegistryOverrides;
use crate::ux::format::{JsonResponse, is_json_mode};

/// JSON response for id show command.
#[derive(Debug, Serialize)]
struct IdShowResponse {
    controller_did: String,
    storage_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}

use auths_id::{
    identity::initialize::initialize_registry_identity,
    ports::registry::RegistryBackend,
    storage::{
        attestation::AttestationSource,
        identity::IdentityStorage,
        layout::{self, StorageLayoutConfig},
    },
};
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};

/// Storage layout presets for different ecosystems.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum LayoutPreset {
    /// Standard Auths layout (refs/auths/identity, refs/auths/keys)
    #[default]
    Default,
    /// Radicle-compatible layout (refs/rad/id, refs/keys)
    Radicle,
    /// Gitoxide-compatible layout (refs/auths/id, refs/auths/devices)
    Gitoxide,
}

impl LayoutPreset {
    /// Convert the preset to a StorageLayoutConfig.
    pub fn to_config(self) -> StorageLayoutConfig {
        match self {
            LayoutPreset::Default => StorageLayoutConfig::default(),
            LayoutPreset::Radicle => StorageLayoutConfig::radicle(),
            LayoutPreset::Gitoxide => StorageLayoutConfig::gitoxide(),
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    about = "Manage identities stored in Git repositories.",
    after_help = "Examples:
  auths id show             # Show current identity details
  auths id list             # List identities (same as show)
  auths id create           # Create a new identity
  auths id export-bundle    # Export identity bundle for verification

Related:
  auths init    — Initialize identity with setup wizard
  auths device  — Manage linked devices
  auths key     — Manage cryptographic keys"
)]
pub struct IdCommand {
    #[clap(subcommand)]
    pub subcommand: IdSubcommand,

    #[command(flatten)]
    pub overrides: RegistryOverrides,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IdSubcommand {
    /// Create a new cryptographic identity with secure key storage.
    #[command(name = "create")]
    Create {
        /// Path to JSON file with arbitrary identity metadata.
        #[arg(
            long,
            value_parser,
            help = "Path to JSON file with arbitrary identity metadata."
        )]
        metadata_file: PathBuf,

        /// Alias for storing the NEWLY generated private key in the secure keychain.
        #[arg(
            long,
            help = "Alias for storing the NEWLY generated private key in the secure keychain."
        )]
        local_key_alias: String,

        /// Storage layout preset for ecosystem compatibility.
        /// Use 'radicle' for Radicle repositories, 'gitoxide' for gitoxide,
        /// or 'default' for standard Auths layout.
        #[arg(
            long,
            value_enum,
            default_value = "default",
            help = "Storage layout preset (default, radicle, gitoxide)"
        )]
        preset: LayoutPreset,
    },

    /// Show primary identity details (identity ID, metadata) from the Git repository.
    Show,

    /// List identities (currently same as show, forward-compatible for future multi-identity support).
    List,

    /// Rotate identity keys. Stores the new key under a new alias.
    Rotate {
        /// Alias of the identity key to rotate. If provided alone, next-key-alias defaults to <alias>-rotated-<timestamp>.
        #[arg(long, help = "Alias of the identity key to rotate.")]
        alias: Option<String>,

        /// Alias of the CURRENT private key controlling the identity (alternative to --alias).
        #[arg(
            long,
            help = "Alias of the CURRENT private key controlling the identity.",
            conflicts_with = "alias"
        )]
        current_key_alias: Option<String>,

        /// Alias to store the NEWLY generated private key under.
        #[arg(long, help = "Alias to store the NEWLY generated private key under.")]
        next_key_alias: Option<String>,

        /// Verification server prefix to add (e.g., B...). Can be specified multiple times.
        #[arg(
            long,
            action = ArgAction::Append,
            help = "Verification server prefix to add (e.g., B...). Can be specified multiple times."
        )]
        add_witness: Vec<String>,

        /// Verification server prefix to remove (e.g., B...). Can be specified multiple times.
        #[arg(
            long,
            action = ArgAction::Append,
            help = "Verification server prefix to remove (e.g., B...). Can be specified multiple times."
        )]
        remove_witness: Vec<String>,

        /// New simple verification threshold count (e.g., 1 for 1-of-N). If omitted, the existing simple count is reused if possible.
        #[arg(
            long,
            help = "New simple verification threshold count (e.g., 1 for 1-of-N)."
        )]
        witness_threshold: Option<u64>,

        /// Preview actions without making changes.
        #[arg(long)]
        dry_run: bool,
    },

    /// Export an identity bundle for stateless CI/CD verification.
    ///
    /// Creates a portable JSON bundle containing the identity ID, public key,
    /// and authorization chain. This bundle can be used in CI pipelines to verify
    /// commit signatures without requiring access to the identity repository.
    ExportBundle {
        /// Key alias to include in the bundle.
        #[arg(long, help = "Key alias to include in bundle")]
        alias: String,

        /// Output file path for the JSON bundle.
        #[arg(long = "output", short = 'o')]
        output_file: PathBuf,

        /// TTL in seconds. The bundle will fail verification after this many seconds.
        #[arg(
            long,
            help = "Maximum bundle age in seconds before it is considered stale"
        )]
        max_age_secs: u64,
    },

    /// Publish this identity to a public registry for discovery.
    Register {
        /// Registry URL to publish to.
        #[arg(long, default_value = "https://auths-registry.fly.dev")]
        registry: String,
    },

    /// Add a platform claim to an already-registered identity.
    Claim(super::claim::ClaimCommand),

    /// Import existing GPG or SSH keys into Auths.
    Migrate(super::migrate::MigrateCommand),

    /// Bind this identity to an enterprise IdP (Okta, Entra ID, Google Workspace, SAML).
    ///
    /// Requires the `auths-cloud` binary on $PATH. If not installed,
    /// prints information about Auths Cloud.
    BindIdp(super::bind_idp::BindIdpStubCommand),
}

fn display_dry_run_rotate(
    repo_path: &std::path::Path,
    current_alias: Option<&str>,
    next_alias: Option<&str>,
) -> Result<()> {
    if is_json_mode() {
        JsonResponse::success(
            "id rotate",
            &serde_json::json!({
                "dry_run": true,
                "repo_path": repo_path.display().to_string(),
                "current_key_alias": current_alias,
                "next_key_alias": next_alias,
                "actions": [
                    "Generate new Ed25519 keypair",
                    "Create rotation event in KERI event log",
                    "Update key alias mappings",
                    "All devices will need to re-authorize"
                ]
            }),
        )
        .print()
        .map_err(|e| anyhow!("{e}"))
    } else {
        let out = crate::ux::format::Output::new();
        out.print_info("Dry run mode — no changes will be made");
        out.newline();
        out.println(&format!("   Repository: {:?}", repo_path));
        if let Some(alias) = current_alias {
            out.println(&format!("   Current Key Alias: {}", alias));
        }
        if let Some(alias) = next_alias {
            out.println(&format!("   New Key Alias: {}", alias));
        }
        out.newline();
        out.println("Would perform the following actions:");
        out.println("  1. Generate new Ed25519 keypair");
        out.println("  2. Create rotation event in KERI event log");
        out.println("  3. Update key alias mappings");
        out.println("  4. All devices will need to re-authorize");
        Ok(())
    }
}

// --- Command Handler ---

/// Handles the `id` subcommand, accepting the specific subcommand details
/// and the global configuration overrides passed from `main`.
#[allow(clippy::too_many_arguments)]
pub fn handle_id(
    cmd: IdCommand,
    repo_opt: Option<PathBuf>,
    identity_ref_override: Option<String>,
    identity_blob_name_override: Option<String>,
    attestation_prefix_override: Option<String>,
    attestation_blob_name_override: Option<String>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    // Determine repo path using the passed Option
    let repo_path = layout::resolve_repo_path(repo_opt)?;

    // Build StorageLayoutConfig from defaults and function arguments
    // Used by non-Init subcommands
    let mut config = StorageLayoutConfig::default();
    if let Some(ref identity_ref) = identity_ref_override {
        config.identity_ref = identity_ref.clone().into();
    }
    if let Some(ref blob_name) = identity_blob_name_override {
        config.identity_blob_name = blob_name.clone().into();
    }
    if let Some(ref prefix) = attestation_prefix_override {
        config.device_attestation_prefix = prefix.clone().into();
    }
    if let Some(ref blob_name) = attestation_blob_name_override {
        config.attestation_blob_name = blob_name.clone().into();
    }

    match cmd.subcommand {
        IdSubcommand::Create {
            metadata_file,
            local_key_alias,
            preset,
        } => {
            // Apply preset first, then override with explicit flags
            let mut config = preset.to_config();
            if let Some(ref identity_ref) = identity_ref_override {
                config.identity_ref = identity_ref.clone().into();
            }
            if let Some(ref blob_name) = identity_blob_name_override {
                config.identity_blob_name = blob_name.clone().into();
            }
            if let Some(ref prefix) = attestation_prefix_override {
                config.device_attestation_prefix = prefix.clone().into();
            }
            if let Some(ref blob_name) = attestation_blob_name_override {
                config.attestation_blob_name = blob_name.clone().into();
            }
            let metadata_file_path = metadata_file;

            // --- Common Setup: Repo Init Check & Metadata Loading ---
            println!("🔐 Creating new cryptographic identity...");
            println!("   Repository path:   {:?}", repo_path);
            println!("   Local Key Alias:   {}", local_key_alias);
            println!("   Metadata File:     {:?}", metadata_file_path);
            println!("   Using Identity Ref: '{}'", config.identity_ref);
            println!("   Using Identity Blob: '{}'", config.identity_blob_name);

            // Ensure Git Repository Exists and is Initialized
            use crate::factories::storage::{ensure_git_repo, open_git_repo};

            let identity_storage_check = RegistryIdentityStorage::new(repo_path.clone());
            if repo_path.exists() {
                match open_git_repo(&repo_path) {
                    Ok(_repo) => {
                        println!("   Git repository found at {:?}.", repo_path);
                        if identity_storage_check.load_identity().is_ok() {
                            eprintln!(
                                "⚠️ Primary identity already initialized and loadable at {:?} using ref '{}'. Aborting.",
                                repo_path,
                                identity_storage_check.get_identity_ref()?
                            );
                            return Err(anyhow!("Identity already exists in this repository"));
                        } else {
                            println!(
                                "   Repository exists, but primary identity ref/data is missing or invalid. Proceeding..."
                            );
                        }
                    }
                    Err(_) => {
                        println!(
                            "   Path {:?} exists but is not a Git repository. Initializing...",
                            repo_path
                        );
                        ensure_git_repo(&repo_path).map_err(|e| {
                            anyhow!(
                                "Path {:?} exists but failed to initialize as Git repository: {}",
                                repo_path,
                                e
                            )
                        })?;
                        println!("   Successfully initialized Git repository.");
                    }
                }
            } else {
                println!("   Initializing Git repository at {:?}...", repo_path);
                ensure_git_repo(&repo_path).map_err(|e| {
                    anyhow!(
                        "Failed to initialize Git repository at {:?}: {}",
                        repo_path,
                        e
                    )
                })?;
                println!("   Successfully initialized Git repository.");
            }

            // Load and Parse Metadata File (common logic)
            if !metadata_file_path.exists() {
                return Err(anyhow!("Metadata file not found: {:?}", metadata_file_path));
            }
            let metadata_content = fs::read_to_string(&metadata_file_path).with_context(|| {
                format!("Failed to read metadata file: {:?}", metadata_file_path)
            })?;
            let metadata_value: serde_json::Value = serde_json::from_str(&metadata_content)
                .with_context(|| {
                    format!(
                        "Failed to parse JSON from metadata file: {:?}",
                        metadata_file_path
                    )
                })?;
            println!("   Metadata loaded successfully from file.");

            // --- Always Use KERI Initialization Logic ---
            println!("   Initializing using did:keri method (default)...");

            // Call the initialize_registry_identity function from auths_id
            let _metadata_value = metadata_value; // metadata stored separately if needed
            let backend: Arc<dyn RegistryBackend + Send + Sync> =
                Arc::new(GitRegistryBackend::from_config_unchecked(
                    RegistryConfig::single_tenant(&repo_path),
                ));
            let local_key_alias = KeyAlias::new_unchecked(local_key_alias);
            match initialize_registry_identity(
                backend,
                &local_key_alias,
                passphrase_provider.as_ref(),
                &get_platform_keychain()?,
                None,
            ) {
                Ok((controller_did_keri, alias)) => {
                    println!("\n✅ Identity (did:keri) initialized successfully!");
                    println!(
                        "   Repository:         {:?}",
                        repo_path
                            .canonicalize()
                            .unwrap_or_else(|_| repo_path.clone())
                    );
                    println!("   Controller DID:     {}", controller_did_keri);
                    println!(
                        "   Local Key Alias:  {} (Use this for local signing/rotations)",
                        alias
                    );
                    let did_prefix = controller_did_keri
                        .as_str()
                        .strip_prefix("did:keri:")
                        .unwrap_or("");
                    if !did_prefix.is_empty() {
                        println!(
                            "   KEL Ref Used:       '{}'",
                            layout::keri_kel_ref(&Prefix::new_unchecked(did_prefix.to_string()))
                        );
                    }
                    println!("   Identity Ref Used:  '{}'", config.identity_ref);
                    println!(
                        "   Identity Blob Used: '{}'",
                        layout::identity_blob_name(&config)
                    );
                    println!("   Metadata stored from: {:?}", metadata_file_path);
                    println!("🔑 Keep your passphrase secure!");
                    Ok(())
                }
                Err(e) => Err(e).context("Failed to initialize KERI identity"),
            }
        }

        IdSubcommand::Show | IdSubcommand::List => {
            let identity_storage = RegistryIdentityStorage::new(repo_path.clone());

            let identity = identity_storage
                .load_identity()
                .with_context(|| format!("Failed to load identity from {:?}", repo_path))?;

            let cmd_name = match cmd.subcommand {
                IdSubcommand::List => "id list",
                _ => "id show",
            };

            if is_json_mode() {
                let response = JsonResponse::success(
                    cmd_name,
                    IdShowResponse {
                        controller_did: identity.controller_did.to_string(),
                        storage_id: identity.storage_id.clone(),
                        metadata: identity.metadata.clone(),
                    },
                );
                response.print()?;
            } else {
                println!("Showing identity details...");
                println!("   Using Repository:    {:?}", repo_path);
                println!("   Using Identity Ref:  '{}'", config.identity_ref);
                println!("   Using Identity Blob: '{}'", config.identity_blob_name);

                println!("Controller DID: {}", identity.controller_did);
                println!("Storage ID (RID): {}", identity.storage_id);
                println!("Metadata (raw JSON, interpretation depends on convention):");
                if let Some(meta) = &identity.metadata {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(meta)
                            .unwrap_or_else(|_| "  <Error serializing metadata>".to_string())
                    );
                } else {
                    println!("  (None)");
                }

                println!("\nUse 'auths device list' to see authorized devices");
            }
            Ok(())
        }

        IdSubcommand::Rotate {
            alias,
            current_key_alias,
            next_key_alias,
            add_witness,
            remove_witness,
            witness_threshold,
            dry_run,
        } => {
            let identity_key_alias = alias.or(current_key_alias);

            if dry_run {
                return display_dry_run_rotate(
                    &repo_path,
                    identity_key_alias.as_deref(),
                    next_key_alias.as_deref(),
                );
            }

            println!("🔄 Rotating KERI identity keys...");
            println!("   Using Repository: {:?}", repo_path);
            if let Some(ref a) = identity_key_alias {
                println!("   Current Key Alias: {}", a);
            }
            if let Some(ref a) = next_key_alias {
                println!("   New Key Alias: {}", a);
            }
            if !add_witness.is_empty() {
                println!("   Witnesses to Add: {:?}", add_witness);
            }
            if !remove_witness.is_empty() {
                println!("   Witnesses to Remove: {:?}", remove_witness);
            }
            if let Some(thresh) = witness_threshold {
                println!("   New Witness Threshold: {}", thresh);
            }

            let rotation_config = auths_sdk::types::IdentityRotationConfig {
                repo_path: repo_path.clone(),
                identity_key_alias: identity_key_alias.map(KeyAlias::new_unchecked),
                next_key_alias: next_key_alias.map(KeyAlias::new_unchecked),
            };
            let rotation_ctx = {
                use auths_core::storage::keychain::get_platform_keychain_with_config;
                use auths_id::attestation::export::AttestationSink;
                use auths_id::storage::attestation::AttestationSource;
                use auths_id::storage::identity::IdentityStorage;
                use auths_sdk::context::AuthsContext;
                use auths_storage::git::{
                    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig,
                    RegistryIdentityStorage,
                };
                let backend: Arc<dyn auths_id::ports::registry::RegistryBackend + Send + Sync> =
                    Arc::new(GitRegistryBackend::from_config_unchecked(
                        RegistryConfig::single_tenant(&repo_path),
                    ));
                let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
                    Arc::new(RegistryIdentityStorage::new(repo_path.clone()));
                let attestation_store = Arc::new(RegistryAttestationStorage::new(&repo_path));
                let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
                    Arc::clone(&attestation_store) as Arc<dyn AttestationSink + Send + Sync>;
                let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
                    attestation_store as Arc<dyn AttestationSource + Send + Sync>;
                let key_storage: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
                    Arc::from(
                        get_platform_keychain_with_config(env_config)
                            .context("Failed to access keychain")?,
                    );
                AuthsContext::builder()
                    .registry(backend)
                    .key_storage(key_storage)
                    .clock(Arc::new(auths_core::ports::clock::SystemClock))
                    .identity_storage(identity_storage)
                    .attestation_sink(attestation_sink)
                    .attestation_source(attestation_source)
                    .passphrase_provider(Arc::clone(&passphrase_provider))
                    .build()
            };
            let result = auths_sdk::workflows::rotation::rotate_identity(
                rotation_config,
                &rotation_ctx,
                &auths_core::ports::clock::SystemClock,
            )
            .with_context(|| "Failed to rotate KERI identity keys")?;

            println!("\n✅ KERI identity keys rotated successfully!");
            println!("   Identity DID: {}", result.controller_did);
            println!(
                "   Old key fingerprint: {}...",
                result.previous_key_fingerprint
            );
            println!("   New key fingerprint: {}...", result.new_key_fingerprint);
            println!(
                "⚠️ The previous key alias is no longer the active signing key for this identity."
            );

            log::info!(
                "Key rotation completed: old_key={}, new_key={}",
                result.previous_key_fingerprint,
                result.new_key_fingerprint,
            );

            Ok(())
        }

        IdSubcommand::ExportBundle {
            alias,
            output_file,
            max_age_secs,
        } => {
            println!("📦 Exporting identity bundle...");
            println!("   Using Repository:  {:?}", repo_path);
            println!("   Key Alias:         {}", alias);
            println!("   Output File:       {:?}", output_file);

            // Load identity
            let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
            let identity = identity_storage
                .load_identity()
                .with_context(|| format!("Failed to load identity from {:?}", repo_path))?;

            println!("   Identity DID:      {}", identity.controller_did);

            // Load attestations
            let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
            let attestations = attestation_storage
                .load_all_attestations()
                .unwrap_or_default();

            // Load the public key from keychain
            let keychain = get_platform_keychain()?;
            let (_, _role, encrypted_key) = keychain
                .load_key(&KeyAlias::new_unchecked(&alias))
                .with_context(|| format!("Key '{}' not found in keychain", alias))?;

            // Decrypt to get public key
            let pass = passphrase_provider
                .get_passphrase(&format!("Enter passphrase for key '{}':", alias))?;
            let pkcs8_bytes = auths_core::crypto::signer::decrypt_keypair(&encrypted_key, &pass)
                .context("Failed to decrypt key")?;
            let keypair = auths_id::identity::helpers::load_keypair_from_der_or_seed(&pkcs8_bytes)?;
            #[allow(clippy::disallowed_methods)]
            // INVARIANT: hex::encode of Ed25519 pubkey always produces valid hex
            let public_key_hex = auths_verifier::PublicKeyHex::new_unchecked(hex::encode(
                keypair.public_key().as_ref(),
            ));

            // Create the bundle
            let bundle = IdentityBundle {
                #[allow(clippy::disallowed_methods)] // INVARIANT: controller_did from storage
                identity_did: IdentityDID::new_unchecked(identity.controller_did.to_string()),
                public_key_hex,
                attestation_chain: attestations,
                bundle_timestamp: now,
                max_valid_for_secs: max_age_secs,
            };

            // Write to output file
            let json = serde_json::to_string_pretty(&bundle)
                .context("Failed to serialize identity bundle")?;
            fs::write(&output_file, &json)
                .with_context(|| format!("Failed to write bundle to {:?}", output_file))?;

            println!("\n✅ Identity bundle exported successfully!");
            println!("   Output:            {:?}", output_file);
            println!("   Attestations:      {}", bundle.attestation_chain.len());
            println!("\nUsage in CI:");
            println!(
                "   auths verify-commit --identity-bundle {:?} HEAD",
                output_file
            );

            Ok(())
        }

        IdSubcommand::Register { registry } => {
            super::register::handle_register(&repo_path, &registry)
        }

        IdSubcommand::Claim(claim_cmd) => {
            super::claim::handle_claim(&claim_cmd, &repo_path, passphrase_provider, env_config, now)
        }

        IdSubcommand::Migrate(migrate_cmd) => super::migrate::handle_migrate(migrate_cmd, now),

        IdSubcommand::BindIdp(bind_cmd) => super::bind_idp::handle_bind_idp(bind_cmd),
    }
}
