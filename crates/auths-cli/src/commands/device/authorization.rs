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
use auths_sdk::storage::{RegistryAttestationStorage, RegistryIdentityStorage};
use auths_sdk::storage_layout::{StorageLayoutConfig, layout};

use crate::commands::registry_overrides::RegistryOverrides;
use crate::factories::storage::build_auths_context;
use crate::ux::format::{JsonResponse, is_json_mode};

#[derive(Serialize)]
struct DeviceEntry {
    id: String,
    /// `active` or `revoked` — a delegated device carries no expiry (KERI
    /// delegation has no timestamps).
    status: String,
    /// Always true for a delegated device: its `dip` is anchored by the root.
    anchored: bool,
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

    /// Add a device as a delegated identifier of the identity.
    ///
    /// The new device gets its own KERI KEL (a delegated inception) that the
    /// root identity anchors — the keripy-native, device-bound way to grant a
    /// device signing authority. (Use `link` for the legacy attestation flow.)
    Add {
        #[arg(long, help = "Your identity's signing key name.")]
        key: String,

        #[arg(long, help = "Keychain alias to store the new device's key under.")]
        device_key: String,

        #[arg(
            long,
            default_value = "p256",
            help = "Curve for the new device key (p256 or ed25519)."
        )]
        curve: String,
    },

    /// Authorize a new device to act on behalf of the identity (legacy attestation).
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
    },

    /// Remove a device from the shared identity's controller set by
    /// signing a rotation on the shared KEL.
    ///
    /// Semantically distinct from `revoke`: `remove` changes *who can
    /// sign for the identity* by producing a new `rot` event; `revoke`
    /// produces an attestation revocation that marks a specific
    /// attestation inactive without touching the controller set.
    ///
    /// Self-removal is rejected at the CLI with a pointer to
    /// `auths reset`. The authoritative guard lives in the
    /// SDK — even callers that bypass the CLI check hit
    /// `SharedKelError::WouldOrphanIdentity`.
    Remove {
        /// The controller DID (`did:keri:E…`) to drop.
        #[arg(long, visible_alias = "device", help = "The controller DID to remove.")]
        device_did: String,

        #[arg(long, help = "Your identity's signing key name.")]
        key: String,
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
            list_devices(&repo_path, env_config, include_revoked)
        }
        DeviceSubcommand::Resolve { device_did } => resolve_device(&repo_path, &device_did),
        DeviceSubcommand::Pair(pair_cmd) => {
            super::pair::handle_pair(pair_cmd, passphrase_provider.clone(), env_config)
        }
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
        } => {
            let payload = read_payload_file(payload_path_opt.as_deref())?;
            validate_payload_schema(schema_path_opt.as_deref(), &payload)?;

            let link_config = auths_sdk::types::DeviceLinkConfig {
                identity_key_alias: KeyAlias::new_unchecked(key),
                device_key_alias: Some(KeyAlias::new_unchecked(device_key)),
                device_did: Some(device_did.clone()),
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

        DeviceSubcommand::Add {
            key,
            device_key,
            curve,
        } => {
            let curve = parse_curve(&curve)?;
            let ctx = build_auths_context(
                &repo_path,
                env_config,
                Some(Arc::clone(&passphrase_provider)),
            )?;
            let root_alias = KeyAlias::new_unchecked(key);
            let device_alias = KeyAlias::new_unchecked(device_key);
            let result =
                auths_sdk::domains::device::add_device(&ctx, &root_alias, &device_alias, curve)
                    .map_err(anyhow::Error::new)?;
            display_add_result(&result.device_did, &repo_path)
        }

        DeviceSubcommand::Remove { device_did, key } => {
            // Remove = revoke the device's KERI delegation: the root anchors a
            // revocation marker so verifiers stop honouring the device. Single-
            // author (the root's key signs); the device's key is not needed.
            //
            // Self-removal pre-flight (UX only — the SDK is the authoritative
            // guard): reject removing the root identity itself; point the caller
            // at `auths reset` to wipe their own state.
            let ctx = build_auths_context(
                &repo_path,
                env_config,
                Some(Arc::clone(&passphrase_provider)),
            )?;
            let identity = ctx.identity_storage.load_identity().map_err(|e| {
                anyhow::anyhow!("failed to load identity for self-removal check: {e}")
            })?;
            if device_did == identity.controller_did.as_str() {
                return Err(anyhow::anyhow!(
                    "Cannot remove the root identity itself. \
                     Use `auths reset` to delete this device's copy of the identity."
                ));
            }
            let root_alias = KeyAlias::new_unchecked(key);
            auths_sdk::domains::device::remove_device(&ctx, &root_alias, &device_did)
                .map_err(anyhow::Error::new)?;
            display_revoke_result(&device_did, &repo_path)
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

fn parse_curve(s: &str) -> Result<auths_crypto::CurveType> {
    match s.to_ascii_lowercase().as_str() {
        "p256" | "p-256" => Ok(auths_crypto::CurveType::P256),
        "ed25519" => Ok(auths_crypto::CurveType::Ed25519),
        other => Err(anyhow::anyhow!(
            "unknown curve {:?}: expected p256 or ed25519",
            other
        )),
    }
}

fn display_add_result(device_did: &str, repo_path: &Path) -> Result<()> {
    let identity_storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let identity: ManagedIdentity = identity_storage
        .load_identity()
        .context("Failed to load identity")?;
    println!(
        "\n✅ Delegated device {} added to identity {}",
        device_did, identity.controller_did
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
    expires_in: u64,
    key: &str,
    device_key: &str,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let config = auths_sdk::types::DeviceExtensionConfig {
        repo_path: repo_path.to_path_buf(),
        #[allow(clippy::disallowed_methods)] // INVARIANT: device_did from CLI arg validated upstream
        device_did: auths_verifier::types::CanonicalDid::new_unchecked(device_did),
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
    let device_did = auths_verifier::types::CanonicalDid::new_unchecked(device_did_str);
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
    env_config: &EnvironmentConfig,
    include_revoked: bool,
) -> Result<()> {
    let ctx = build_auths_context(repo_path, env_config, None)
        .context("Failed to build auths context")?;

    let identity = ctx
        .identity_storage
        .load_identity()
        .with_context(|| format!("Failed to load identity from {:?}", repo_path))?;

    // The delegation set is the source of truth: live = delegated − revoked. A
    // delegated device is inherently anchored and carries no expiry.
    let devices = auths_sdk::domains::device::list_delegated_devices(&ctx)
        .map_err(anyhow::Error::from)
        .context("Could not list delegated devices")?;

    let mut entries: Vec<DeviceEntry> = Vec::new();
    for device in devices {
        if !include_revoked && device.revoked {
            continue;
        }
        entries.push(DeviceEntry {
            id: device.device_did,
            status: if device.revoked {
                "revoked".to_string()
            } else {
                "active".to_string()
            },
            anchored: true,
        });
    }

    let duplicity_warning = root_duplicity_warning(&ctx, identity.controller_did.as_str());

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

    if let Some(warning) = &duplicity_warning {
        println!("{warning}");
        println!();
    }

    println!("Authorized devices for: {}", identity.controller_did);
    if entries.is_empty() {
        if include_revoked {
            println!("  No delegated devices found.");
        } else {
            println!("  (No active devices. Use --include-revoked to see all.)");
        }
        return Ok(());
    }
    for (i, entry) in entries.iter().enumerate() {
        println!("{:>2}. {}   {}", i + 1, entry.id, entry.status);
    }
    Ok(())
}

/// Run duplicity detection over the root KEL and return a non-fatal warning if the
/// local registry has recorded a fork (concurrent rotations on different
/// controllers). A linear KEL reports `Clean` and yields `None`.
///
/// Args:
/// * `ctx`: Auths context (its registry holds the root KEL).
/// * `controller_did`: The root identity's `did:keri:`.
///
/// Usage:
/// ```ignore
/// if let Some(w) = root_duplicity_warning(&ctx, &controller_did) { println!("{w}"); }
/// ```
fn root_duplicity_warning(
    ctx: &auths_sdk::context::AuthsContext,
    controller_did: &str,
) -> Option<String> {
    use auths_sdk::verify::{DuplicityReport, KelEventRef, detect_duplicity};

    let prefix_str = controller_did.strip_prefix("did:keri:")?;
    let prefix = auths_keri::Prefix::new_unchecked(prefix_str.to_string());
    let tip = ctx.registry.get_tip(&prefix).ok()?;

    let mut events = Vec::new();
    for seq in 0..=tip.sequence {
        events.push(ctx.registry.get_event(&prefix, seq).ok()?);
    }
    let refs: Vec<KelEventRef> = events
        .iter()
        .enumerate()
        .map(|(seq, event)| KelEventRef {
            prefix: controller_did,
            seq: seq as u64,
            said: event.said().as_str(),
        })
        .collect();

    match detect_duplicity(&refs) {
        DuplicityReport::Diverging { seq, .. } => {
            Some(auths_sdk::keri::copy::format_duplicity_warning(seq))
        }
        _ => None,
    }
}
