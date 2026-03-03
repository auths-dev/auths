use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use log::warn;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_core::config::EnvironmentConfig;
use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, UnifiedPassphraseProvider};
use auths_core::storage::keychain::{KeyAlias, get_platform_keychain_with_config};
use auths_id::attestation::export::AttestationSink;
use auths_id::attestation::group::AttestationGroup;
use auths_id::identity::helpers::ManagedIdentity;
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_id::storage::layout::{self, StorageLayoutConfig};
use auths_sdk::context::AuthsContext;
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use chrono::Utc;

use crate::commands::registry_overrides::RegistryOverrides;

fn build_device_context(
    repo_path: &Path,
    env_config: &EnvironmentConfig,
    passphrase_provider: Option<Arc<dyn PassphraseProvider + Send + Sync>>,
) -> Result<AuthsContext> {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(repo_path)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(repo_path.to_path_buf()));
    let attestation_store = Arc::new(RegistryAttestationStorage::new(repo_path));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&attestation_store) as Arc<dyn AttestationSink + Send + Sync>;
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        attestation_store as Arc<dyn AttestationSource + Send + Sync>;
    let key_storage =
        get_platform_keychain_with_config(env_config).context("Failed to initialize keychain")?;
    let mut builder = AuthsContext::builder()
        .registry(backend)
        .key_storage(Arc::from(key_storage))
        .clock(Arc::new(SystemClock))
        .identity_storage(identity_storage)
        .attestation_sink(attestation_sink)
        .attestation_source(attestation_source);
    if let Some(pp) = passphrase_provider {
        builder = builder.passphrase_provider(pp);
    }
    Ok(builder.build())
}

#[derive(Args, Debug, Clone)]
#[command(about = "Manage device authorizations within an identity repository.")]
pub struct DeviceCommand {
    #[command(subcommand)]
    pub command: DeviceSubcommand,

    #[command(flatten)]
    pub overrides: RegistryOverrides,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DeviceSubcommand {
    /// List all authorized devices for the current identity.
    List {
        /// Include devices with revoked or expired authorizations in the output.
        #[arg(
            long,
            help = "Include devices with revoked or expired authorizations in the output."
        )]
        include_revoked: bool,
    },

    /// Authorize a new device to act on behalf of the identity.
    #[command(visible_alias = "add")]
    Link {
        #[arg(long, help = "Local alias of the *identity's* key (used for signing).")]
        identity_key_alias: String,

        #[arg(
            long,
            help = "Local alias of the *new device's* key (must be imported first)."
        )]
        device_key_alias: String,

        #[arg(
            long,
            help = "Identity ID of the new device being authorized (must match device-key-alias)."
        )]
        device_did: String,

        #[arg(
            long,
            value_name = "PAYLOAD_PATH",
            help = "Optional path to a JSON file containing arbitrary payload data for the authorization."
        )]
        payload: Option<PathBuf>,

        #[arg(
            long,
            value_name = "SCHEMA_PATH",
            help = "Optional path to a JSON schema for validating the payload (experimental)."
        )]
        schema: Option<PathBuf>,

        #[arg(
            long,
            value_name = "DAYS",
            help = "Optional number of days until this device authorization expires."
        )]
        expires_in_days: Option<i64>,

        #[arg(
            long,
            help = "Optional description/note for this device authorization."
        )]
        note: Option<String>,

        #[arg(
            long,
            value_delimiter = ',',
            help = "Permissions to grant this device (comma-separated)"
        )]
        capabilities: Option<Vec<String>>,
    },

    /// Revoke an existing device authorization using the identity key.
    Revoke {
        #[arg(long, help = "Identity ID of the device authorization to revoke.")]
        device_did: String,

        #[arg(
            long,
            help = "Local alias of the *identity's* key (required to authorize revocation)."
        )]
        identity_key_alias: String,

        #[arg(long, help = "Optional note explaining the revocation.")]
        note: Option<String>,
    },

    /// Resolve a device DID to its controller identity DID.
    Resolve {
        #[arg(long, help = "The device DID to resolve (e.g. did:key:z6Mk...).")]
        device_did: String,
    },

    /// Link devices to your identity via QR code or short code.
    Pair(super::pair::PairCommand),

    /// Verify device authorization signatures (attestation).
    #[command(name = "verify")]
    VerifyAttestation(super::verify_attestation::VerifyCommand),

    /// Extend the expiration date of an existing device authorization.
    Extend {
        #[arg(long, help = "Identity ID of the device authorization to extend.")]
        device_did: String,

        #[arg(
            long,
            value_name = "DAYS",
            help = "Number of days to extend the expiration by (from now)."
        )]
        days: i64,

        #[arg(
            long = "identity-key-alias",
            help = "Local alias of the *identity's* key (required for re-signing)."
        )]
        identity_key_alias: String,

        #[arg(
            long = "device-key-alias",
            help = "Local alias of the *device's* key (required for re-signing)."
        )]
        device_key_alias: String,
    },
}

#[allow(clippy::too_many_arguments)]
pub fn handle_device(
    cmd: DeviceCommand,
    repo_opt: Option<PathBuf>,
    identity_ref_override: Option<String>,
    identity_blob_name_override: Option<String>,
    attestation_prefix_override: Option<String>,
    attestation_blob_name_override: Option<String>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    http_client: &reqwest::Client,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let repo_path = layout::resolve_repo_path(repo_opt)?;

    let mut config = StorageLayoutConfig::default();
    if let Some(identity_ref) = identity_ref_override {
        config.identity_ref = identity_ref.into();
    }
    if let Some(blob_name) = identity_blob_name_override {
        config.identity_blob_name = blob_name.into();
    }
    if let Some(prefix) = attestation_prefix_override {
        config.device_attestation_prefix = prefix.into();
    }
    if let Some(blob_name) = attestation_blob_name_override {
        config.attestation_blob_name = blob_name.into();
    }

    match cmd.command {
        DeviceSubcommand::List { include_revoked } => {
            list_devices(&repo_path, &config, include_revoked)
        }
        DeviceSubcommand::Resolve { device_did } => resolve_device(&repo_path, &device_did),
        DeviceSubcommand::Pair(pair_cmd) => {
            super::pair::handle_pair(pair_cmd, http_client, env_config)
        }
        DeviceSubcommand::VerifyAttestation(verify_cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(super::verify_attestation::handle_verify(verify_cmd))
        }
        DeviceSubcommand::Link {
            identity_key_alias,
            device_key_alias,
            device_did,
            payload: payload_path_opt,
            schema: schema_path_opt,
            expires_in_days,
            note,
            capabilities,
        } => {
            let payload = read_payload_file(payload_path_opt.as_deref())?;
            validate_payload_schema(schema_path_opt.as_deref(), &payload)?;

            let caps: Vec<auths_verifier::Capability> = capabilities
                .unwrap_or_default()
                .into_iter()
                .filter_map(|s| auths_verifier::Capability::parse(&s).ok())
                .collect();

            let link_config = auths_sdk::types::DeviceLinkConfig {
                identity_key_alias: KeyAlias::new_unchecked(identity_key_alias),
                device_key_alias: Some(KeyAlias::new_unchecked(device_key_alias)),
                device_did: Some(device_did.clone()),
                capabilities: caps,
                expires_in_days: expires_in_days.map(|d| d as u32),
                note,
                payload,
            };

            let passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync> =
                Arc::new(UnifiedPassphraseProvider::new(passphrase_provider));
            let ctx = build_device_context(
                &repo_path,
                env_config,
                Some(Arc::clone(&passphrase_provider)),
            )?;

            let result = auths_sdk::device::link_device(
                link_config,
                &ctx,
                &auths_core::ports::clock::SystemClock,
            )
            .map_err(|e| anyhow!("{e}"))?;

            display_link_result(&result, &device_did)
        }

        DeviceSubcommand::Revoke {
            device_did,
            identity_key_alias,
            note,
        } => {
            let ctx = build_device_context(
                &repo_path,
                env_config,
                Some(Arc::clone(&passphrase_provider)),
            )?;

            let identity_key_alias = KeyAlias::new_unchecked(identity_key_alias);
            auths_sdk::device::revoke_device(
                &device_did,
                &identity_key_alias,
                &ctx,
                note,
                &auths_core::ports::clock::SystemClock,
            )
            .map_err(|e| anyhow!("{e}"))?;

            display_revoke_result(&device_did, &repo_path)
        }

        DeviceSubcommand::Extend {
            device_did,
            days,
            identity_key_alias,
            device_key_alias,
        } => handle_extend(
            &repo_path,
            &config,
            &device_did,
            days,
            &identity_key_alias,
            &device_key_alias,
            passphrase_provider,
            env_config,
        ),
    }
}

fn display_link_result(
    result: &auths_sdk::result::DeviceLinkResult,
    device_did: &str,
) -> Result<()> {
    println!(
        "\n✅ Successfully linked device {} (attestation: {})",
        device_did, result.attestation_id
    );
    Ok(())
}

fn display_revoke_result(device_did: &str, repo_path: &Path) -> Result<()> {
    let identity_storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let identity: ManagedIdentity = identity_storage
        .load_identity()
        .context("Failed to load identity")?;

    println!(
        "\n✅ Successfully revoked device {} for identity {}",
        device_did, identity.controller_did
    );
    Ok(())
}

fn read_payload_file(path: Option<&Path>) -> Result<Option<Value>> {
    match path {
        Some(p) => {
            let content = fs::read_to_string(p)
                .with_context(|| format!("Failed to read payload file {:?}", p))?;
            let value: Value = serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse JSON from payload file {:?}", p))?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

fn validate_payload_schema(schema_path: Option<&Path>, payload: &Option<Value>) -> Result<()> {
    match (schema_path, payload) {
        (Some(schema_path), Some(payload_val)) => {
            let schema_content = fs::read_to_string(schema_path)
                .with_context(|| format!("Failed to read schema file {:?}", schema_path))?;
            let schema_json: serde_json::Value = serde_json::from_str(&schema_content)
                .with_context(|| format!("Failed to parse JSON schema from {:?}", schema_path))?;
            let validator = jsonschema::validator_for(&schema_json)
                .map_err(|e| anyhow!("Invalid JSON schema in {:?}: {}", schema_path, e))?;
            let errors: Vec<String> = validator
                .iter_errors(payload_val)
                .map(|e| format!("  - {}", e))
                .collect();
            if !errors.is_empty() {
                return Err(anyhow!(
                    "Payload does not conform to schema:\n{}",
                    errors.join("\n")
                ));
            }
            Ok(())
        }
        (Some(_), None) => {
            warn!("--schema specified but no --payload provided; skipping validation.");
            Ok(())
        }
        _ => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_extend(
    repo_path: &Path,
    _config: &StorageLayoutConfig,
    device_did: &str,
    days: i64,
    identity_key_alias: &str,
    device_key_alias: &str,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let config = auths_sdk::types::DeviceExtensionConfig {
        repo_path: repo_path.to_path_buf(),
        device_did: device_did.to_string(),
        days: days as u32,
        identity_key_alias: KeyAlias::new_unchecked(identity_key_alias),
        device_key_alias: KeyAlias::new_unchecked(device_key_alias),
    };
    let ctx = build_device_context(repo_path, env_config, Some(passphrase_provider))?;

    let result = auths_sdk::device::extend_device_authorization(
        config,
        &ctx,
        &auths_core::ports::clock::SystemClock,
    )
    .with_context(|| format!("Failed to extend device authorization for '{}'", device_did))?;

    println!(
        "Successfully extended expiration for {} to {}",
        result.device_did,
        result.new_expires_at.date_naive()
    );
    Ok(())
}

fn resolve_device(repo_path: &Path, device_did_str: &str) -> Result<()> {
    let attestation_storage = RegistryAttestationStorage::new(repo_path.to_path_buf());
    let device_did = auths_verifier::types::DeviceDID::new(device_did_str);
    let attestations = attestation_storage
        .load_attestations_for_device(&device_did)
        .with_context(|| format!("Failed to load attestations for device {device_did_str}"))?;

    let latest = attestations
        .last()
        .ok_or_else(|| anyhow!("No attestation found for device {device_did_str}"))?;

    println!("{}", latest.issuer);
    Ok(())
}

fn list_devices(
    repo_path: &Path,
    _config: &StorageLayoutConfig,
    include_revoked: bool,
) -> Result<()> {
    let identity_storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let attestation_storage = RegistryAttestationStorage::new(repo_path.to_path_buf());
    let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
        RegistryConfig::single_tenant(repo_path),
    )) as Arc<dyn auths_id::ports::registry::RegistryBackend + Send + Sync>;
    let resolver = auths_id::identity::resolve::RegistryDidResolver::new(backend);

    let identity: ManagedIdentity = identity_storage
        .load_identity()
        .with_context(|| format!("Failed to load identity from {:?}", repo_path))?;

    println!("Devices for identity: {}", identity.controller_did);

    let attestations = attestation_storage
        .load_all_attestations()
        .context("Could not load device attestations")?;

    let grouped = AttestationGroup::from_list(attestations);
    if grouped.device_count() == 0 {
        println!("  No authorized devices found.");
        return Ok(());
    }

    let mut device_count = 0;
    for (device_did_str, entries) in grouped.by_device.iter() {
        let latest = entries
            .last()
            .expect("Grouped attestations should not be empty");

        let verification_result = auths_id::attestation::verify::verify_with_resolver(
            chrono::Utc::now(),
            &resolver,
            latest,
        );

        let status_string = match verification_result {
            Ok(()) => {
                if latest.is_revoked() {
                    "revoked".to_string()
                } else if let Some(expiry) = latest.expires_at {
                    if Utc::now() > expiry {
                        "expired".to_string()
                    } else {
                        format!("active (expires {})", expiry.date_naive())
                    }
                } else {
                    "active".to_string()
                }
            }
            Err(err) => {
                let err_msg = err.to_string().to_lowercase();
                if err_msg.contains("revoked") {
                    format!(
                        "revoked{}",
                        latest
                            .timestamp
                            .map(|ts| format!(" ({})", ts.date_naive()))
                            .unwrap_or_default()
                    )
                } else if err_msg.contains("expired") {
                    format!(
                        "expired{}",
                        latest
                            .expires_at
                            .map(|ts| format!(" ({})", ts.date_naive()))
                            .unwrap_or_default()
                    )
                } else {
                    format!("invalid ({})", err)
                }
            }
        };

        let is_inactive = latest.is_revoked() || latest.expires_at.is_some_and(|e| Utc::now() > e);

        if !include_revoked && is_inactive {
            continue;
        }

        device_count += 1;
        println!(
            "{:>2}. {}   {}",
            device_count, device_did_str, status_string
        );
        if let Some(note) = &latest.note
            && !note.is_empty()
        {
            println!("    Note: {}", note);
        }
    }

    if device_count == 0 && !include_revoked {
        println!("  (No active devices. Use --include-revoked to see all.)");
    }

    Ok(())
}
