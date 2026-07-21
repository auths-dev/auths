use anyhow::{Context, Result, anyhow};
use clap::{ArgAction, Parser, Subcommand};
use serde::Serialize;
use serde_json;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use auths_sdk::{
    core_config::EnvironmentConfig,
    keychain::{KeyAlias, get_platform_keychain},
    signing::PassphraseProvider,
};
use auths_verifier::{IdentityBundle, IdentityDID};
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

use auths_sdk::storage::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_sdk::{
    identity::initialize_registry_identity,
    ports::{AttestationSource, IdentityStorage, RegistryBackend},
    storage_layout::{StorageLayoutConfig, layout},
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
    about = "Manage your signing identity.",
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
    /// Create a new signing identity.
    #[command(name = "create")]
    Create {
        /// Path to JSON file with arbitrary identity metadata.
        #[arg(
            long,
            value_parser,
            help = "Path to JSON file with arbitrary identity metadata."
        )]
        metadata_file: PathBuf,

        /// Name for the new signing key in secure storage.
        #[arg(long, help = "Name for the new signing key in secure storage.")]
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
        /// Name of the key to rotate. Defaults to the next rotation key automatically.
        #[arg(long, help = "Name of the key to rotate.")]
        alias: Option<String>,

        /// Current signing key name (alternative to --alias).
        #[arg(
            long,
            help = "Current signing key name (alternative to --alias).",
            conflicts_with = "alias"
        )]
        current_key_alias: Option<String>,

        /// Name for the new signing key after rotation.
        #[arg(long, help = "Name for the new signing key after rotation.")]
        next_key_alias: Option<String>,

        /// Add a witness server address (repeatable).
        #[arg(
            long,
            action = ArgAction::Append,
            help = "Add a witness server address (repeatable)."
        )]
        add_witness: Vec<String>,

        /// Remove a witness server address (repeatable).
        #[arg(
            long,
            action = ArgAction::Append,
            help = "Remove a witness server address (repeatable)."
        )]
        remove_witness: Vec<String>,

        /// Number of witnesses required to accept this rotation (e.g., 1).
        #[arg(
            long,
            help = "Number of witnesses required to accept this rotation (e.g., 1)."
        )]
        witness_threshold: Option<u64>,

        /// Preview actions without making changes.
        #[arg(long)]
        dry_run: bool,

        /// Add a device slot on this rotation (repeatable). Value is the
        /// curve for the new slot (`P256` or `Ed25519`).
        #[arg(long, action = ArgAction::Append, value_name = "CURVE")]
        add_device: Vec<String>,

        /// Remove a device slot by index on this rotation (repeatable).
        /// Currently rejected — requires CESR indexed-signature support.
        #[arg(long, action = ArgAction::Append, value_name = "INDEX")]
        remove_device: Vec<u32>,

        /// New signing threshold (scalar like `"2"` or fractions like
        /// `"1/2,1/2,1/2"`). Omit to keep the prior `kt`.
        #[arg(long)]
        signing_threshold: Option<String>,

        /// New rotation (next) threshold, same format as
        /// `--signing-threshold`. Omit to keep the prior `nt`.
        #[arg(long)]
        rotation_threshold: Option<String>,

        /// Receive the rotation from a paired device over LAN instead of
        /// authoring it locally. The device builds and co-signs the
        /// shared-KEL rotation; this host only validates it against the
        /// registry's prior key state and appends it. No local key
        /// material is touched.
        #[cfg(feature = "lan-pairing")]
        #[arg(long, conflicts_with_all = ["alias", "current_key_alias", "next_key_alias", "add_witness", "remove_witness", "witness_threshold", "dry_run"])]
        from_device: bool,

        /// Don't display the QR code for `--from-device` (only the short code).
        #[cfg(feature = "lan-pairing")]
        #[arg(long = "no-qr", requires = "from_device", hide_short_help = true)]
        no_qr: bool,

        /// Print the session token URI for `--from-device` so scripts can
        /// deliver it to the device out of band.
        #[cfg(feature = "lan-pairing")]
        #[arg(long = "print-uri", requires = "from_device", hide_short_help = true)]
        print_uri: bool,

        /// Disable mDNS advertisement for `--from-device`.
        #[cfg(feature = "lan-pairing")]
        #[arg(long = "no-mdns", requires = "from_device", hide_short_help = true)]
        no_mdns: bool,

        /// Session lifetime in seconds for `--from-device`.
        #[cfg(feature = "lan-pairing")]
        #[arg(
            long = "timeout",
            requires = "from_device",
            default_value = "300",
            hide_short_help = true
        )]
        timeout: u64,
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

    /// Export a KEL-derived `allowed_signers` file so plain `git` / `ssh` can
    /// verify this identity's signatures on machines without auths installed.
    ///
    /// Point git at it with:
    ///   git config gpg.ssh.allowedSignersFile <file>
    AllowedSigners {
        /// Key alias whose current public key to export.
        #[arg(long, help = "Key alias to export the signing key for")]
        alias: String,

        /// Principal to bind the key to (usually the committer email). Defaults
        /// to the identity DID. Must match the signer identity git checks.
        #[arg(
            long,
            help = "Principal for the allowed_signers line (default: identity DID)"
        )]
        principal: Option<String>,

        /// Write to this file instead of stdout.
        #[arg(long = "output", short = 'o', help = "Output file (default: stdout)")]
        output_file: Option<PathBuf>,
    },

    /// Publish this identity to a public registry for discovery.
    Register {
        /// Registry URL to publish to.
        #[arg(long, env = "AUTHS_REGISTRY_URL")]
        registry: Option<String>,
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

    /// Re-authorize with a platform and optionally upload SSH signing key.
    ///
    /// Use this when you need to update OAuth scopes or re-authenticate
    /// with a platform (e.g., GitHub). Automatically uploads the SSH signing key
    /// if the `write:ssh_signing_key` scope is included.
    #[command(name = "update-scope")]
    UpdateScope {
        /// Platform to re-authorize with (e.g., github).
        #[arg(help = "Platform name (currently supports 'github')")]
        platform: String,
    },

    /// Manage AI agents delegated by this identity (KERI delegated identifiers).
    Agent(super::agent::AgentCommand),
}

/// `auths id rotate --from-device`: apply a rotation a paired device
/// authored, instead of authoring one locally.
///
/// The device builds and co-signs the shared-KEL rotation (proving
/// controllership by revealing a pre-committed key); this host receives the
/// envelope over an ephemeral LAN session, validates it against the
/// registry's prior key state, and appends it. No local key material is
/// read or written — the host contributes only its registry.
#[cfg(feature = "lan-pairing")]
fn handle_rotate_from_device(
    repo_path: &std::path::Path,
    no_qr: bool,
    print_uri: bool,
    no_mdns: bool,
    timeout: u64,
    now: chrono::DateTime<chrono::Utc>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    use auths_sdk::domains::identity::shared_rot::apply_shared_kel_rot;

    let rt = tokio::runtime::Runtime::new()?;
    let envelope = rt.block_on(crate::commands::device::pair::handle_receive_shared_rot(
        now, repo_path, no_qr, print_uri, no_mdns, timeout,
    ))?;

    let identity_storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let controller_did =
        auths_sdk::pairing::load_controller_did(&identity_storage).map_err(anyhow::Error::from)?;
    let prefix_str = controller_did
        .strip_prefix("did:keri:")
        .ok_or_else(|| anyhow!("invalid DID format, expected 'did:keri:': {controller_did}"))?;
    let prefix = auths_keri::Prefix::new_unchecked(prefix_str.to_string());

    let ctx = crate::factories::storage::build_auths_context(repo_path, env_config, None)?;
    let applied = apply_shared_kel_rot(&envelope, &prefix, ctx.registry.as_ref())
        .with_context(|| "Failed to apply the device-authored rotation")?;

    if is_json_mode() {
        JsonResponse::success(
            "id rotate",
            &serde_json::json!({
                "from_device": true,
                "controller_did": controller_did,
                "sequence": applied.sequence.to_string(),
                "event_said": applied.said.as_str(),
                "controller_count": applied.controller_count,
            }),
        )
        .print()
        .map_err(anyhow::Error::from)?;
    } else {
        println!("\n✅ Device-authored rotation applied.");
        println!("   Identity:    {}", controller_did);
        println!("   KEL advanced to seq {}", applied.sequence);
        println!("   Controllers in force: {}", applied.controller_count);
    }

    // The rotation advanced the KEL — restamp the commit-trailers file so
    // hook-stamped commits carry the new anchor position.
    if let Err(e) = auths_sdk::workflows::commit_hooks::refresh_commit_trailers(&ctx, repo_path) {
        println!("⚠️  Could not refresh commit trailers ({e}); run `auths doctor`.");
    }
    Ok(())
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
                    "Generate new signing key",
                    "Record rotation in identity log",
                    "Update key name mappings",
                    "All devices will need to re-authorize"
                ]
            }),
        )
        .print()
        .map_err(anyhow::Error::from)
    } else {
        let out = crate::ux::format::Output::new();
        out.print_info("Dry run mode — no changes will be made");
        out.newline();
        out.println(&format!("   Repository: {:?}", repo_path));
        if let Some(alias) = current_alias {
            out.println(&format!("   Current key name: {}", alias));
        }
        if let Some(alias) = next_alias {
            out.println(&format!("   New key name: {}", alias));
        }
        out.newline();
        out.println("Would perform the following actions:");
        out.println("  1. Generate new signing key");
        out.println("  2. Record rotation in identity log");
        out.println("  3. Update key name mappings");
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
            println!("🔐 Creating identity...");
            println!("   Repository path:   {:?}", repo_path);
            println!("   Key name:          {}", local_key_alias);
            println!("   Metadata File:     {:?}", metadata_file_path);

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
                auths_sdk::witness::WitnessParams::Disabled,
                auths_crypto::CurveType::default(),
                chrono::Utc::now(),
            ) {
                Ok((controller_did_keri, alias)) => {
                    println!("\n✅ Identity created.");
                    println!(
                        "   Repository:         {:?}",
                        repo_path
                            .canonicalize()
                            .unwrap_or_else(|_| repo_path.clone())
                    );
                    println!("   Identity:           {}", controller_did_keri);
                    println!(
                        "   Key name:         {} (use this for signing and rotations)",
                        alias
                    );
                    println!("   Metadata stored from: {:?}", metadata_file_path);
                    println!("🔑 Keep your passphrase secure!");
                    Ok(())
                }
                Err(e) => Err(e).context("Failed to create identity"),
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
                println!("Identity:   {}", identity.controller_did);
                println!("Storage ID: {}", identity.storage_id);
                println!("Metadata:");
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
            add_device,
            remove_device,
            signing_threshold,
            rotation_threshold,
            #[cfg(feature = "lan-pairing")]
            from_device,
            #[cfg(feature = "lan-pairing")]
            no_qr,
            #[cfg(feature = "lan-pairing")]
            print_uri,
            #[cfg(feature = "lan-pairing")]
            no_mdns,
            #[cfg(feature = "lan-pairing")]
            timeout,
        } => {
            #[cfg(feature = "lan-pairing")]
            if from_device {
                return handle_rotate_from_device(
                    &repo_path, no_qr, print_uri, no_mdns, timeout, now, env_config,
                );
            }
            if !add_device.is_empty()
                || !remove_device.is_empty()
                || signing_threshold.is_some()
                || rotation_threshold.is_some()
            {
                return Err(anyhow!(
                    "multi-device rotation (--add-device / --remove-device / --signing-threshold / \
                     --rotation-threshold) is not wired through `auths id rotate`. Add a device \
                     with `auths device pair` (each device is a delegated identity under your \
                     root), or omit these flags for a standard rotation."
                ));
            }
            let identity_key_alias = alias.or(current_key_alias);

            if dry_run {
                return display_dry_run_rotate(
                    &repo_path,
                    identity_key_alias.as_deref(),
                    next_key_alias.as_deref(),
                );
            }

            println!("🔄 Rotating keys...");
            println!("   Using Repository: {:?}", repo_path);
            if let Some(ref a) = identity_key_alias {
                println!("   Current key name: {}", a);
            }
            if let Some(ref a) = next_key_alias {
                println!("   New key name: {}", a);
            }
            if !add_witness.is_empty() {
                println!("   Adding witnesses: {:?}", add_witness);
            }
            if !remove_witness.is_empty() {
                println!("   Removing witnesses: {:?}", remove_witness);
            }
            if let Some(thresh) = witness_threshold {
                println!("   Witnesses required: {}", thresh);
            }

            let rotation_config_next_alias = next_key_alias.clone();
            let rotation_config = auths_sdk::types::IdentityRotationConfig {
                repo_path: repo_path.clone(),
                identity_key_alias: identity_key_alias.map(KeyAlias::new_unchecked),
                next_key_alias: next_key_alias.map(KeyAlias::new_unchecked),
            };
            let rotation_ctx = {
                use auths_sdk::attestation::AttestationSink;
                use auths_sdk::context::AuthsContext;
                use auths_sdk::keychain::get_platform_keychain_with_config;
                use auths_sdk::ports::IdentityStorage;
                use auths_sdk::storage::{
                    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig,
                    RegistryIdentityStorage,
                };
                let backend: Arc<dyn auths_sdk::ports::RegistryBackend + Send + Sync> =
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
                let key_storage: Arc<dyn auths_sdk::keychain::KeyStorage + Send + Sync> = Arc::from(
                    get_platform_keychain_with_config(env_config)
                        .context("Failed to access keychain")?,
                );
                AuthsContext::builder()
                    .registry(backend)
                    .key_storage(key_storage)
                    .clock(Arc::new(auths_sdk::ports::SystemClock))
                    .identity_storage(identity_storage)
                    .attestation_sink(attestation_sink)
                    .attestation_source(attestation_source)
                    .passphrase_provider(Arc::clone(&passphrase_provider))
                    .build()
            };
            let result = auths_sdk::workflows::rotation::rotate_identity(
                rotation_config,
                &rotation_ctx,
                &auths_sdk::ports::SystemClock,
            )
            .with_context(|| "Failed to rotate keys")?;

            println!("\n✅ Keys rotated.");
            println!("   Identity: {}", result.controller_did);
            println!(
                "   Old key fingerprint: {}...",
                result.previous_key_fingerprint
            );
            println!("   New key fingerprint: {}...", result.new_key_fingerprint);
            println!("   Key name: {} (unchanged)", result.new_key_alias);

            // The rotation advanced the KEL — restamp the commit-trailers file so
            // hook-stamped commits carry the new anchor position.
            if let Err(e) = auths_sdk::workflows::commit_hooks::refresh_commit_trailers(
                &rotation_ctx,
                &repo_path,
            ) {
                println!("⚠️  Could not refresh commit trailers ({e}); run `auths doctor`.");
            }

            // Stable alias keeps git signing working untouched. Only an explicit
            // --next-key-alias changes the name — repoint user.signingkey then.
            if let Some(ref explicit) = rotation_config_next_alias {
                let new_signing_key = format!("auths:{explicit}");
                let updated = crate::subprocess::git_command(&[
                    "config",
                    "--global",
                    "user.signingKey",
                    &new_signing_key,
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
                if updated {
                    println!("   Git signing key updated to {new_signing_key}");
                } else {
                    println!(
                        "⚠️  Could not update git user.signingKey — set it manually: \
                         git config --global user.signingKey {new_signing_key}"
                    );
                }
            }

            log::info!(
                "Key rotation completed: old_key={}, new_key={}, alias={}",
                result.previous_key_fingerprint,
                result.new_key_fingerprint,
                result.new_key_alias,
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
            println!("   Key name:          {}", alias);
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
                .load_all_enriched()
                .map(|v| v.into_iter().map(|e| e.attestation).collect::<Vec<_>>())
                .unwrap_or_default();

            // Load the public key from keychain (handles SE and software keys)
            let keychain = get_platform_keychain()?;
            let alias_typed = KeyAlias::new_unchecked(&alias);
            let (public_key_bytes, curve) = auths_sdk::keychain::extract_public_key_bytes(
                keychain.as_ref(),
                &alias_typed,
                passphrase_provider.as_ref(),
            )
            .with_context(|| format!("Failed to extract public key for '{}'", alias))?;
            #[allow(clippy::disallowed_methods)]
            // INVARIANT: hex::encode of pubkey bytes always produces valid hex
            let public_key_hex =
                auths_verifier::PublicKeyHex::new_unchecked(hex::encode(&public_key_bytes));

            // Embed the identity's KEL so verifiers stay stateless: KEL-native
            // commit verification on a CI runner has no identity store to
            // resolve the signer from.
            let registry = auths_sdk::storage::GitRegistryBackend::from_config_unchecked(
                auths_sdk::storage::RegistryConfig::single_tenant(&repo_path),
            );
            let prefix = auths_sdk::keri::parse_did_keri(identity.controller_did.as_str())
                .context("identity DID is not did:keri")?;
            // Collect the KEL events, then their stored CESR signature
            // attachments (seq-indexed), so the exported bundle can be
            // AUTHENTICATED by a stateless verifier — not just replayed
            // structurally (RT-002).
            let mut events = Vec::new();
            let _ = registry.visit_events(&prefix, 0, &mut |e| {
                events.push(e.clone());
                std::ops::ControlFlow::Continue(())
            });
            if events.is_empty() {
                return Err(anyhow::anyhow!(
                    "no KEL events found for {} — cannot export a verifiable bundle",
                    identity.controller_did
                ));
            }
            let mut kel: Vec<auths_keri::Event> = Vec::with_capacity(events.len());
            let mut kel_attachments: Vec<String> = Vec::with_capacity(events.len());
            for e in &events {
                let seq = e.sequence().value();
                let att = registry
                    .get_attachment(&prefix, seq)
                    .map_err(|err| anyhow::anyhow!("failed to read KEL signature: {err}"))?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "KEL event at seq {seq} has no stored signature attachment; \
                             cannot export a verifiable bundle (re-initialize this identity)"
                        )
                    })?;
                kel.push(e.clone());
                kel_attachments.push(hex::encode(att));
            }

            // Delegated device KELs: commits are signed by a DEVICE AID, so a
            // stateless verifier needs each device KEL the root anchored — not
            // only the root's. Enumerate the registry for dip-rooted KELs whose
            // delegator is this identity, exporting each with its attachments.
            let root_prefix_str = prefix.as_str().to_string();
            let mut device_prefixes: Vec<String> = Vec::new();
            let _ = registry.visit_identities(&mut |candidate| {
                if candidate != root_prefix_str {
                    device_prefixes.push(candidate.to_string());
                }
                std::ops::ControlFlow::Continue(())
            });
            let mut device_kels = Vec::new();
            for device in device_prefixes {
                let device_prefix = auths_keri::Prefix::new_unchecked(device.clone());
                let mut device_events: Vec<auths_keri::Event> = Vec::new();
                let _ = registry.visit_events(&device_prefix, 0, &mut |e| {
                    device_events.push(e.clone());
                    std::ops::ControlFlow::Continue(())
                });
                let delegated_by_this_root = device_events
                    .first()
                    .and_then(|e| e.delegator())
                    .is_some_and(|d| d.as_str() == root_prefix_str);
                if !delegated_by_this_root {
                    continue;
                }
                let mut device_attachments = Vec::with_capacity(device_events.len());
                for e in &device_events {
                    let seq = e.sequence().value();
                    let att = registry
                        .get_attachment(&device_prefix, seq)
                        .map_err(|err| anyhow::anyhow!("failed to read device KEL signature: {err}"))?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "device {device} KEL event at seq {seq} has no stored signature                                  attachment; cannot export a verifiable bundle"
                            )
                        })?;
                    device_attachments.push(hex::encode(att));
                }
                device_kels.push(auths_verifier::BundleDeviceKel {
                    did: format!("did:keri:{device}"),
                    kel: device_events,
                    kel_attachments: device_attachments,
                });
            }

            // Create the bundle. Curve flows in-band from the typed keychain
            // extraction so verifiers never re-derive it from byte length.
            let bundle = IdentityBundle {
                identity_did: identity.controller_did.clone(),
                public_key_hex,
                curve,
                attestation_chain: attestations,
                kel,
                kel_attachments,
                device_kels,
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
            println!("   auths verify --identity-bundle {:?} HEAD", output_file);

            Ok(())
        }

        IdSubcommand::AllowedSigners {
            alias,
            principal,
            output_file,
        } => {
            let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
            let identity = identity_storage
                .load_identity()
                .with_context(|| format!("Failed to load identity from {:?}", repo_path))?;
            let principal =
                principal.unwrap_or_else(|| identity.controller_did.as_str().to_string());

            let keychain = get_platform_keychain()?;
            let alias_typed = KeyAlias::new_unchecked(&alias);
            let (public_key_bytes, curve) = auths_sdk::keychain::extract_public_key_bytes(
                keychain.as_ref(),
                &alias_typed,
                passphrase_provider.as_ref(),
            )
            .with_context(|| format!("Failed to extract public key for '{}'", alias))?;

            let device_pk = auths_verifier::DevicePublicKey::try_new(curve, &public_key_bytes)
                .with_context(|| format!("'{}' is not a valid signing key", alias))?;
            let openssh = auths_sdk::workflows::git_integration::public_key_to_ssh(&device_pk)
                .context("Failed to encode signing key as OpenSSH")?;
            // allowed_signers line: `<principal> <keytype> <base64>`. The OpenSSH
            // encoding already carries `<keytype> <base64>`; trim any trailing
            // comment so the line is exactly the two fields ssh expects.
            let key_field = openssh
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ");
            let line = format!("{principal} {key_field}\n");

            match &output_file {
                Some(path) => {
                    fs::write(path, &line).with_context(|| {
                        format!("Failed to write allowed_signers to {:?}", path)
                    })?;
                    println!("✅ Wrote allowed_signers for {} to {:?}", principal, path);
                    println!("   git config gpg.ssh.allowedSignersFile {:?}", path);
                }
                None => print!("{line}"),
            }
            Ok(())
        }

        IdSubcommand::Register { registry } => super::register::handle_register(
            &repo_path,
            &crate::commands::verify_helpers::require_registry(registry.clone())?,
        ),

        IdSubcommand::Claim(claim_cmd) => {
            super::claim::handle_claim(&claim_cmd, &repo_path, passphrase_provider, env_config, now)
        }

        IdSubcommand::Migrate(migrate_cmd) => super::migrate::handle_migrate(migrate_cmd, now),

        IdSubcommand::BindIdp(bind_cmd) => super::bind_idp::handle_bind_idp(bind_cmd),

        IdSubcommand::UpdateScope { platform } => {
            if platform.to_lowercase() != "github" {
                return Err(anyhow!(
                    "Platform '{}' is not supported yet. Currently only 'github' is available.",
                    platform
                ));
            }

            use crate::constants::GITHUB_SSH_UPLOAD_SCOPES;
            use auths_infra_http::{HttpGitHubOAuthProvider, HttpGitHubSshKeyUploader};
            use auths_sdk::keychain::extract_public_key_bytes;
            use auths_sdk::ports::platform::OAuthDeviceFlowProvider;
            use std::time::Duration;

            const GITHUB_CLIENT_ID: &str = "Ov23lio2CiTHBjM2uIL4";
            #[allow(clippy::disallowed_methods)]
            let client_id = std::env::var("AUTHS_GITHUB_CLIENT_ID")
                .unwrap_or_else(|_| GITHUB_CLIENT_ID.to_string());

            // Get ~/.auths directory
            let home =
                dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
            let auths_dir = home.join(".auths");
            let ctx = crate::factories::storage::build_auths_context(
                &auths_dir,
                env_config,
                Some(passphrase_provider.clone()),
            )?;

            let oauth = HttpGitHubOAuthProvider::new();
            let ssh_uploader = HttpGitHubSshKeyUploader::new();

            let rt = tokio::runtime::Runtime::new().context("failed to create async runtime")?;

            let out = crate::ux::format::Output::new();
            out.print_info(&format!("Re-authorizing with {}", platform));

            let device_code = rt
                .block_on(oauth.request_device_code(&client_id, GITHUB_SSH_UPLOAD_SCOPES))
                .map_err(anyhow::Error::from)?;

            out.println(&format!(
                "  Enter this code: {}",
                out.bold(&device_code.user_code)
            ));
            out.println(&format!(
                "  At: {}",
                out.info(&device_code.verification_uri)
            ));
            if let Err(e) = open::that(&device_code.verification_uri) {
                out.print_warn(&format!("Could not open browser automatically: {e}"));
                out.println("  Please open the URL above manually.");
            } else {
                out.println("  Browser opened — waiting for authorization...");
            }

            let expires_in = Duration::from_secs(device_code.expires_in);
            let interval = Duration::from_secs(device_code.interval);

            let access_token = rt
                .block_on(oauth.poll_for_token(
                    &client_id,
                    &device_code.device_code,
                    interval,
                    expires_in,
                ))
                .map_err(anyhow::Error::from)?;

            let profile = rt
                .block_on(oauth.fetch_user_profile(&access_token))
                .map_err(anyhow::Error::from)?;

            out.print_success(&format!("Re-authenticated as @{}", profile.login));

            // Try to get device public key and upload SSH key
            let controller_did =
                auths_sdk::pairing::load_controller_did(ctx.identity_storage.as_ref())
                    .map_err(anyhow::Error::from)?;

            let identity_did = IdentityDID::parse(&controller_did)
                .context("controller DID is not a valid did:keri identifier")?;
            let aliases = ctx
                .key_storage
                .list_aliases_for_identity(&identity_did)
                .context("failed to list key aliases")?;
            let key_alias = aliases
                .into_iter()
                .find(|a| !a.contains("--next-"))
                .ok_or_else(|| anyhow::anyhow!("no signing key found for {controller_did}"))?;

            // Get device public key and encode
            let device_key_result = extract_public_key_bytes(
                ctx.key_storage.as_ref(),
                &key_alias,
                passphrase_provider.as_ref(),
            );

            if let Ok((pk_bytes, curve)) = device_key_result {
                let device_pk = auths_verifier::DevicePublicKey::try_new(curve, &pk_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid device key: {e}"))?;
                let public_key =
                    auths_sdk::workflows::git_integration::public_key_to_ssh(&device_pk)
                        .map_err(|e| anyhow::anyhow!("Failed to encode SSH key: {e}"))?;

                out.println("  Uploading SSH signing key...");
                #[allow(clippy::disallowed_methods)]
                let now = chrono::Utc::now();
                #[allow(clippy::disallowed_methods)]
                let hostname = gethostname::gethostname();
                let hostname_str = hostname.to_string_lossy().to_string();
                let result = rt.block_on(
                    auths_sdk::workflows::platform::upload_github_ssh_signing_key(
                        &ssh_uploader,
                        &access_token,
                        &public_key,
                        &key_alias,
                        &hostname_str,
                        ctx.identity_storage.as_ref(),
                        now,
                    ),
                );

                match result {
                    Ok(()) => {
                        out.print_success("SSH signing key uploaded to GitHub");
                        out.println("  View at: https://github.com/settings/keys");
                    }
                    Err(e) => {
                        out.print_warn(&format!("SSH key upload failed: {e}"));
                        out.println(
                            "  You can upload manually at https://github.com/settings/keys",
                        );
                    }
                }
            } else {
                out.print_warn("Could not extract device public key for SSH upload");
            }

            out.print_success("Scope update complete");
            Ok(())
        }

        IdSubcommand::Agent(agent_cmd) => {
            super::agent::handle_agent(agent_cmd, repo_path, env_config, passphrase_provider)
        }
    }
}

#[cfg(all(test, feature = "lan-pairing"))]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Harness {
        #[command(subcommand)]
        sub: IdSubcommand,
    }

    #[test]
    fn rotate_from_device_parses() {
        let h = Harness::parse_from(["id", "rotate", "--from-device"]);
        match h.sub {
            IdSubcommand::Rotate { from_device, .. } => assert!(from_device),
            other => panic!("expected Rotate, got {other:?}"),
        }
    }

    #[test]
    fn rotate_from_device_conflicts_with_local_authoring_flags() {
        // The device authors the rotation — naming a local key is a
        // contradiction and must be refused at parse time.
        assert!(
            Harness::try_parse_from(["id", "rotate", "--from-device", "--alias", "main"]).is_err()
        );
        assert!(Harness::try_parse_from(["id", "rotate", "--from-device", "--dry-run"]).is_err());
    }

    #[test]
    fn rotate_session_toggles_require_from_device() {
        assert!(Harness::try_parse_from(["id", "rotate", "--no-qr"]).is_err());
        assert!(Harness::try_parse_from(["id", "rotate", "--print-uri"]).is_err());
        assert!(
            Harness::try_parse_from(["id", "rotate", "--from-device", "--no-qr", "--print-uri"])
                .is_ok()
        );
    }
}
