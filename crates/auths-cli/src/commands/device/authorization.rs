use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use log::warn;
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::identity::ManagedIdentity;
use auths_sdk::keychain::KeyAlias;
use auths_sdk::ports::{AttestationSource, IdentityStorage};
use auths_sdk::signing::{PassphraseProvider, UnifiedPassphraseProvider};
use auths_sdk::storage::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_sdk::storage_layout::{StorageLayoutConfig, layout};
use chrono::Utc;

use crate::commands::registry_overrides::RegistryOverrides;
use crate::factories::storage::build_auths_context;
use crate::ux::format::{JsonResponse, is_json_mode};

#[derive(Serialize)]
struct DeviceEntry {
    id: String,
    status: String,
    anchored: bool,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(
    about = "Manage which devices can sign with your identity.",
    after_help = "Examples:
  auths device list         # List authorized devices
  auths device link --key identity-key --device-key device-key --device did:key:...
                            # Authorize a new device
  auths device revoke       # Revoke a device
  auths device extend       # Extend device expiry

Related:
  auths status  — Show device status and expiry
  auths init    — Set up identity and signing"
)]
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
        #[arg(long, help = "Your identity's key name.")]
        key: String,

        #[arg(
            long,
            help = "The new device's key name (import first with: auths key import)."
        )]
        device_key: String,

        #[arg(
            long,
            visible_alias = "device",
            help = "The device's ID (must match --device-key)."
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

        /// Duration in seconds until expiration (per RFC 6749).
        #[arg(
            long = "expires-in",
            value_name = "SECS",
            help = "Optional number of seconds until this device authorization expires."
        )]
        expires_in: Option<u64>,

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
        #[arg(long, visible_alias = "device", help = "The device's ID to revoke.")]
        device_did: String,

        #[arg(long, help = "Your identity's key name.")]
        key: String,

        #[arg(long, help = "Optional note explaining the revocation.")]
        note: Option<String>,

        #[arg(long, help = "Preview actions without making changes.")]
        dry_run: bool,
    },

    /// Resolve a device to its owner identity.
    Resolve {
        #[arg(
            long,
            visible_alias = "device",
            help = "The device ID to resolve (e.g. did:key:z6Mk...)."
        )]
        device_did: String,
    },

    /// Link devices to your identity via QR code or short code.
    Pair(super::pair::PairCommand),

    /// Verify device authorization signatures (attestation).
    #[command(name = "verify")]
    VerifyAttestation(super::verify_attestation::VerifyCommand),

    /// Extend the expiration date of an existing device authorization.
    Extend {
        #[arg(long, visible_alias = "device", help = "The device's ID to extend.")]
        device_did: String,

        /// Duration in seconds until expiration (per RFC 6749).
        #[arg(
            long = "expires-in",
            value_name = "SECS",
            help = "Number of seconds to extend the expiration by (from now)."
        )]
        expires_in: u64,

        #[arg(long, help = "Your identity's key name.")]
        key: String,

        #[arg(long, help = "The device's key name.")]
        device_key: String,
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
    env_config: &EnvironmentConfig,
) -> Result<()> {
    #[allow(clippy::disallowed_methods)]
    let now = Utc::now();
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
            list_devices(now, &repo_path, &config, include_revoked)
        }
        DeviceSubcommand::Resolve { device_did } => resolve_device(&repo_path, &device_did),
        DeviceSubcommand::Pair(pair_cmd) => super::pair::handle_pair(pair_cmd, env_config),
        DeviceSubcommand::VerifyAttestation(verify_cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(super::verify_attestation::handle_verify(verify_cmd))
        }
        DeviceSubcommand::Link {
            key,
            device_key,
            device_did,
            payload: payload_path_opt,
            schema: schema_path_opt,
            expires_in,
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
                identity_key_alias: KeyAlias::new_unchecked(key),
                device_key_alias: Some(KeyAlias::new_unchecked(device_key)),
                device_did: Some(device_did.clone()),
                capabilities: caps,
                expires_in,
                note,
                payload,
            };

            let passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync> =
                Arc::new(UnifiedPassphraseProvider::new(passphrase_provider));
            let ctx = build_auths_context(
                &repo_path,
                env_config,
                Some(Arc::clone(&passphrase_provider)),
            )?;

            let result = auths_sdk::domains::device::service::link_device(
                link_config,
                &ctx,
                &auths_sdk::ports::SystemClock,
            )
            .map_err(anyhow::Error::new)?;

            display_link_result(&result, &device_did)
        }

        DeviceSubcommand::Revoke {
            device_did,
            key,
            note,
            dry_run,
        } => {
            if dry_run {
                return display_dry_run_revoke(&device_did, &key);
            }

            let ctx = build_auths_context(
                &repo_path,
                env_config,
                Some(Arc::clone(&passphrase_provider)),
            )?;

            let identity_key_alias = KeyAlias::new_unchecked(key);
            auths_sdk::domains::device::service::revoke_device(
                &device_did,
                &identity_key_alias,
                &ctx,
                note,
                &auths_sdk::ports::SystemClock,
            )
            .map_err(anyhow::Error::new)?;

            display_revoke_result(&device_did, &repo_path)
        }

        DeviceSubcommand::Extend {
            device_did,
            expires_in,
            key,
            device_key,
        } => handle_extend(
            &repo_path,
            &config,
            &device_did,
            expires_in,
            &key,
            &device_key,
            passphrase_provider,
            env_config,
        ),
    }
}

fn display_link_result(
    result: &auths_sdk::result::DeviceLinkResult,
    _device_did: &str,
) -> Result<()> {
    println!(
        "\n✅ Device authorized. (Attestation: {})",
        result.attestation_id
    );
    Ok(())
}

fn display_dry_run_revoke(device_did: &str, identity_key_alias: &str) -> Result<()> {
    if is_json_mode() {
        JsonResponse::success(
            "device revoke",
            &serde_json::json!({
                "dry_run": true,
                "device_did": device_did,
                "identity_key_alias": identity_key_alias,
                "actions": [
                    "Revoke device authorization",
                    "Create signed revocation attestation",
                    "Store revocation in Git repository"
                ]
            }),
        )
        .print()
        .map_err(anyhow::Error::from)
    } else {
        let out = crate::ux::format::Output::new();
        out.print_info("Dry run mode — no changes will be made");
        out.newline();
        out.println("Would perform the following actions:");
        out.println(&format!(
            "  1. Revoke device authorization for {}",
            device_did
        ));
        out.println("  2. Create signed revocation attestation");
        out.println("  3. Store revocation in Git repository");
        Ok(())
    }
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
    expires_in: u64,
    key: &str,
    device_key: &str,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let config = auths_sdk::types::DeviceExtensionConfig {
        repo_path: repo_path.to_path_buf(),
        #[allow(clippy::disallowed_methods)] // INVARIANT: device_did from CLI arg validated upstream
        device_did: auths_verifier::types::DeviceDID::new_unchecked(device_did),
        expires_in,
        identity_key_alias: KeyAlias::new_unchecked(key),
        device_key_alias: Some(KeyAlias::new_unchecked(device_key)),
    };
    let ctx = build_auths_context(repo_path, env_config, Some(passphrase_provider))?;

    let result = auths_sdk::domains::device::service::extend_device(
        config,
        &ctx,
        &auths_sdk::ports::SystemClock,
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
    #[allow(clippy::disallowed_methods)] // INVARIANT: device_did_str from attestation storage
    let device_did = auths_verifier::types::DeviceDID::new_unchecked(device_did_str);
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
    now: chrono::DateTime<Utc>,
    repo_path: &Path,
    _config: &StorageLayoutConfig,
    include_revoked: bool,
) -> Result<()> {
    let identity_storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let attestation_storage = RegistryAttestationStorage::new(repo_path.to_path_buf());
    let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
        RegistryConfig::single_tenant(repo_path),
    )) as Arc<dyn auths_sdk::ports::RegistryBackend + Send + Sync>;
    let resolver = auths_sdk::identity::RegistryDidResolver::new(backend);

    let identity: ManagedIdentity = identity_storage
        .load_identity()
        .with_context(|| format!("Failed to load identity from {:?}", repo_path))?;

    let enriched = attestation_storage
        .load_all_enriched()
        .context("Could not load device attestations")?;

    let grouped = auths_sdk::attestation::EnrichedAttestationGroup::from_enriched(enriched);

    let mut entries: Vec<DeviceEntry> = Vec::new();
    for (device_did_str, att_entries) in grouped.by_device.iter() {
        #[allow(clippy::expect_used)] // INVARIANT: BTreeMap groups are never empty by construction
        let enriched_latest = att_entries
            .last()
            .expect("Grouped attestations should not be empty");
        let latest = &enriched_latest.attestation;

        // single verifier path via auths_verifier::verify_with_keys.
        // Callers resolve the DID and pass the typed key directly.
        let verification_result: Result<(), auths_verifier::AttestationError> = {
            use auths_sdk::identity::DidResolver;
            use auths_verifier::AttestationError;
            match resolver.resolve(latest.issuer.as_str()) {
                Ok(resolved) => {
                    let pk_bytes: Vec<u8> = resolved.public_key_bytes().to_vec();
                    let resolved_curve = resolved.curve();
                    match auths_verifier::decode_public_key_bytes(&pk_bytes, resolved_curve) {
                        Ok(issuer_pk) => {
                            #[allow(clippy::expect_used)]
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("tokio runtime");
                            rt.block_on(auths_verifier::verify_with_keys(latest, &issuer_pk))
                                .map(|_| ())
                        }
                        Err(e) => Err(AttestationError::DidResolutionError(format!(
                            "invalid issuer key: {e}"
                        ))),
                    }
                }
                Err(e) => Err(AttestationError::DidResolutionError(format!(
                    "Resolver error for {}: {}",
                    latest.issuer, e
                ))),
            }
        };

        let status_string = match verification_result {
            Ok(()) => {
                if latest.is_revoked() {
                    "revoked".to_string()
                } else if let Some(expiry) = latest.expires_at {
                    if now > expiry {
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

        let is_inactive = latest.is_revoked() || latest.expires_at.is_some_and(|e| now > e);
        if !include_revoked && is_inactive {
            continue;
        }

        entries.push(DeviceEntry {
            id: device_did_str.clone(),
            status: status_string,
            anchored: enriched_latest.anchor == auths_keri::AnchorStatus::Anchored,
            public_key: hex::encode(latest.device_public_key.as_bytes()),
            created_at: latest.timestamp.map(|ts| ts.to_rfc3339()),
            expires_at: latest.expires_at.map(|ts| ts.to_rfc3339()),
            note: latest.note.clone().filter(|n| !n.is_empty()),
        });
    }

    if is_json_mode() {
        return JsonResponse::success(
            "device list",
            &serde_json::json!({
                "identity": identity.controller_did.to_string(),
                "devices": entries,
            }),
        )
        .print()
        .map_err(anyhow::Error::from);
    }

    println!("Authorized devices for: {}", identity.controller_did);
    if entries.is_empty() {
        if include_revoked {
            println!("  No authorized devices found.");
        } else {
            println!("  (No active devices. Use --include-revoked to see all.)");
        }
        return Ok(());
    }
    for (i, entry) in entries.iter().enumerate() {
        let anchor_indicator = if entry.anchored { "" } else { " (unanchored)" };
        println!(
            "{:>2}. {}   {}{}",
            i + 1,
            entry.id,
            entry.status,
            anchor_indicator
        );
        if let Some(note) = &entry.note {
            println!("    Note: {}", note);
        }
    }
    Ok(())
}
