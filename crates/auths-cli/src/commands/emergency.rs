//! Emergency response commands for incident handling.
//!
//! Commands:
//! - `auths emergency` - Interactive emergency response flow
//! - `auths emergency revoke-device` - Revoke a compromised device
//! - `auths emergency rotate-now` - Force key rotation
//! - `auths emergency freeze` - Freeze all operations
//! - `auths emergency report` - Generate incident report

use crate::ux::format::{Output, is_json_mode};
use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Input, Select};
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::PathBuf;

/// Emergency incident response commands.
#[derive(Parser, Debug, Clone)]
#[command(name = "emergency", about = "Emergency incident response commands")]
pub struct EmergencyCommand {
    #[command(subcommand)]
    pub command: Option<EmergencySubcommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum EmergencySubcommand {
    /// Revoke a compromised device immediately.
    #[command(name = "revoke-device")]
    RevokeDevice(RevokeDeviceCommand),

    /// Force immediate key rotation.
    #[command(name = "rotate-now")]
    RotateNow(RotateNowCommand),

    /// Freeze all signing operations.
    Freeze(FreezeCommand),

    /// Unfreeze (cancel an active freeze early).
    Unfreeze(UnfreezeCommand),

    /// Generate an incident report.
    Report(ReportCommand),
}

/// Revoke a compromised device.
#[derive(Parser, Debug, Clone)]
pub struct RevokeDeviceCommand {
    /// Device DID to revoke.
    #[arg(long)]
    pub device: Option<String>,

    /// Local alias of the identity's key (used for signing the revocation).
    #[arg(long)]
    pub identity_key_alias: Option<String>,

    /// Optional note explaining the revocation.
    #[arg(long)]
    pub note: Option<String>,

    /// Skip confirmation prompt.
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Preview actions without making changes.
    #[arg(long)]
    pub dry_run: bool,

    /// Path to the Auths repository.
    #[arg(long)]
    pub repo: Option<PathBuf>,
}

/// Force immediate key rotation.
#[derive(Parser, Debug, Clone)]
pub struct RotateNowCommand {
    /// Local alias of the current signing key.
    #[arg(long)]
    pub current_alias: Option<String>,

    /// Local alias for the new signing key after rotation.
    #[arg(long)]
    pub next_alias: Option<String>,

    /// Skip confirmation prompt (requires typing ROTATE).
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Preview actions without making changes.
    #[arg(long)]
    pub dry_run: bool,

    /// Reason for rotation.
    #[arg(long)]
    pub reason: Option<String>,

    /// Path to the Auths repository.
    #[arg(long)]
    pub repo: Option<PathBuf>,
}

/// Freeze all signing operations.
#[derive(Parser, Debug, Clone)]
pub struct FreezeCommand {
    /// Duration to freeze (e.g., "24h", "7d").
    #[arg(long, default_value = "24h")]
    pub duration: String,

    /// Skip confirmation prompt (requires typing identity name).
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Preview actions without making changes.
    #[arg(long)]
    pub dry_run: bool,

    /// Path to the Auths repository.
    #[arg(long)]
    pub repo: Option<PathBuf>,
}

/// Cancel an active freeze early.
#[derive(Parser, Debug, Clone)]
pub struct UnfreezeCommand {
    /// Skip confirmation prompt.
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Path to the Auths repository.
    #[arg(long)]
    pub repo: Option<PathBuf>,
}

/// Generate an incident report.
#[derive(Parser, Debug, Clone)]
pub struct ReportCommand {
    /// Include last N events in report.
    #[arg(long, default_value = "100")]
    pub events: usize,

    /// Output file path (defaults to stdout).
    #[arg(long = "output", visible_alias = "file", short = 'o')]
    pub output_file: Option<PathBuf>,

    /// Path to the Auths repository.
    #[arg(long)]
    pub repo: Option<PathBuf>,
}

/// Incident report output.
#[derive(Debug, Serialize, Deserialize)]
pub struct IncidentReport {
    pub generated_at: String,
    pub identity_did: Option<String>,
    pub devices: Vec<DeviceInfo>,
    pub recent_events: Vec<EventInfo>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub did: String,
    pub name: Option<String>,
    pub status: String,
    pub last_active: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventInfo {
    pub timestamp: String,
    pub event_type: String,
    pub details: String,
}

/// Handle the emergency command.
pub fn handle_emergency(
    cmd: EmergencyCommand,
    now: chrono::DateTime<chrono::Utc>,
    ctx: &crate::config::CliConfig,
) -> Result<()> {
    match cmd.command {
        Some(EmergencySubcommand::RevokeDevice(c)) => handle_revoke_device(c, now, ctx),
        Some(EmergencySubcommand::RotateNow(c)) => handle_rotate_now(c, now, ctx),
        Some(EmergencySubcommand::Freeze(c)) => handle_freeze(c, now),
        Some(EmergencySubcommand::Unfreeze(c)) => handle_unfreeze(c, now),
        Some(EmergencySubcommand::Report(c)) => handle_report(c, now),
        None => handle_interactive_flow(ctx),
    }
}

/// Handle interactive emergency flow.
fn handle_interactive_flow(ctx: &crate::config::CliConfig) -> Result<()> {
    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();
    let out = Output::new();

    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "Interactive mode requires a terminal. Use subcommands for non-interactive use."
        ));
    }

    out.newline();
    out.println(&format!(
        "  {} {}",
        out.error("🚨"),
        out.bold("Emergency Response")
    ));
    out.newline();

    let options = [
        "Device lost or stolen",
        "Key may have been exposed",
        "Freeze everything immediately",
        "Generate incident report",
        "Cancel",
    ];

    let selection = Select::new()
        .with_prompt("What happened?")
        .items(options)
        .default(0)
        .interact()?;

    match selection {
        0 => {
            // Device lost/stolen
            out.print_info("Starting device revocation flow...");
            handle_revoke_device(
                RevokeDeviceCommand {
                    device: None,
                    identity_key_alias: None,
                    note: None,
                    yes: false,
                    dry_run: false,
                    repo: None,
                },
                now,
                ctx,
            )
        }
        1 => {
            // Key exposed
            out.print_info("Starting key rotation flow...");
            handle_rotate_now(
                RotateNowCommand {
                    current_alias: None,
                    next_alias: None,
                    yes: false,
                    dry_run: false,
                    reason: Some("Potential key exposure".to_string()),
                    repo: None,
                },
                now,
                ctx,
            )
        }
        2 => {
            // Freeze everything
            out.print_warn("Starting freeze flow...");
            handle_freeze(
                FreezeCommand {
                    duration: "24h".to_string(),
                    yes: false,
                    dry_run: false,
                    repo: None,
                },
                now,
            )
        }
        3 => {
            // Generate report
            handle_report(
                ReportCommand {
                    events: 100,
                    output_file: None,
                    repo: None,
                },
                now,
            )
        }
        _ => {
            out.println("Cancelled.");
            Ok(())
        }
    }
}

/// Handle device revocation using the real revocation code path.
fn handle_revoke_device(
    cmd: RevokeDeviceCommand,
    now: chrono::DateTime<chrono::Utc>,
    ctx: &crate::config::CliConfig,
) -> Result<()> {
    use auths_core::signing::StorageSigner;
    use auths_core::storage::keychain::{KeyAlias, get_platform_keychain};
    use auths_id::attestation::export::AttestationSink;
    use auths_id::attestation::revoke::create_signed_revocation;
    use auths_id::identity::helpers::ManagedIdentity;
    use auths_id::storage::attestation::AttestationSource;
    use auths_id::storage::identity::IdentityStorage;
    use auths_id::storage::layout;
    use auths_storage::git::{RegistryAttestationStorage, RegistryIdentityStorage};
    use auths_verifier::Ed25519PublicKey;
    use auths_verifier::types::DeviceDID;

    let out = Output::new();

    out.print_heading("Device Revocation");
    out.newline();

    // Get device to revoke
    let device_did = if let Some(did) = cmd.device {
        did
    } else if std::io::stdin().is_terminal() {
        Input::new()
            .with_prompt("Enter device DID to revoke")
            .interact_text()?
    } else {
        return Err(anyhow!("--device is required in non-interactive mode"));
    };

    // Get identity key alias
    let identity_key_alias = if let Some(alias) = cmd.identity_key_alias {
        alias
    } else if std::io::stdin().is_terminal() {
        Input::new()
            .with_prompt("Enter identity key alias")
            .interact_text()?
    } else {
        return Err(anyhow!(
            "--identity-key-alias is required in non-interactive mode"
        ));
    };

    out.println(&format!("Device to revoke: {}", out.info(&device_did)));
    out.newline();

    if cmd.dry_run {
        out.print_info("Dry run mode - no changes will be made");
        out.newline();
        out.println("Would perform the following actions:");
        out.println(&format!(
            "  1. Revoke device authorization for {}",
            device_did
        ));
        out.println("  2. Create signed revocation attestation");
        out.println("  3. Store revocation in Git repository");
        return Ok(());
    }

    // Confirmation
    if !cmd.yes {
        let confirm = Confirm::new()
            .with_prompt(format!("Revoke device {}?", device_did))
            .default(false)
            .interact()?;

        if !confirm {
            out.println("Cancelled.");
            return Ok(());
        }
    }

    // Resolve repository and load identity
    let repo_path = layout::resolve_repo_path(cmd.repo)?;

    let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
    let managed_identity: ManagedIdentity = identity_storage
        .load_identity()
        .with_context(|| format!("Failed to load identity from repo {:?}", repo_path))?;

    let controller_did = managed_identity.controller_did;
    let rid = managed_identity.storage_id;

    #[allow(clippy::disallowed_methods)] // INVARIANT: device_did from managed identity storage
    let device_did_obj = DeviceDID::new_unchecked(device_did.clone());

    // Look up the device's public key from existing attestations
    let attestation_storage = RegistryAttestationStorage::new(repo_path.clone());
    let existing_attestations = attestation_storage
        .load_attestations_for_device(&device_did_obj)
        .with_context(|| format!("Failed to load attestations for device {}", device_did_obj))?;
    let device_public_key = existing_attestations
        .iter()
        .find(|a| !a.device_public_key.is_zero())
        .map(|a| a.device_public_key)
        .unwrap_or_else(|| Ed25519PublicKey::from_bytes([0u8; 32]));

    let secure_signer = StorageSigner::new(get_platform_keychain()?);

    let revocation_timestamp = now;

    out.print_info("Creating signed revocation attestation...");
    let identity_key_alias = KeyAlias::new_unchecked(identity_key_alias);
    let revocation_attestation = create_signed_revocation(
        &rid,
        &controller_did,
        &device_did_obj,
        device_public_key.as_bytes(),
        cmd.note,
        None,
        revocation_timestamp,
        &secure_signer,
        ctx.passphrase_provider.as_ref(),
        &identity_key_alias,
    )
    .map_err(anyhow::Error::from)
    .context("Failed to create revocation attestation")?;

    out.print_info("Saving revocation to Git repository...");
    let attestation_storage = RegistryAttestationStorage::new(repo_path);
    attestation_storage
        .export(
            &auths_verifier::VerifiedAttestation::dangerous_from_unchecked(revocation_attestation),
        )
        .context("Failed to save revocation attestation to Git repository")?;

    out.print_success(&format!("Device {} has been revoked", device_did));
    out.newline();
    out.println("The device can no longer sign on behalf of your identity.");

    Ok(())
}

/// Handle emergency key rotation using the real rotation code path.
fn handle_rotate_now(
    cmd: RotateNowCommand,
    now: chrono::DateTime<chrono::Utc>,
    ctx: &crate::config::CliConfig,
) -> Result<()> {
    use auths_core::storage::keychain::{KeyAlias, get_platform_keychain};
    use auths_id::identity::rotate::rotate_keri_identity;
    use auths_id::storage::layout::{self, StorageLayoutConfig};

    let out = Output::new();

    out.print_heading("Emergency Key Rotation");
    out.newline();

    let reason = cmd
        .reason
        .unwrap_or_else(|| "Manual emergency rotation".to_string());
    out.println(&format!("Reason: {}", out.info(&reason)));
    out.newline();

    // Get key aliases
    let current_alias = if let Some(alias) = cmd.current_alias {
        alias
    } else if std::io::stdin().is_terminal() {
        Input::new()
            .with_prompt("Enter current signing key alias")
            .interact_text()?
    } else {
        return Err(anyhow!(
            "--current-alias is required in non-interactive mode"
        ));
    };

    let next_alias = if let Some(alias) = cmd.next_alias {
        alias
    } else if std::io::stdin().is_terminal() {
        Input::new()
            .with_prompt("Enter alias for the new signing key")
            .interact_text()?
    } else {
        return Err(anyhow!("--next-alias is required in non-interactive mode"));
    };

    if cmd.dry_run {
        out.print_info("Dry run mode - no changes will be made");
        out.newline();
        out.println("Would perform the following actions:");
        out.println("  1. Generate new Ed25519 keypair");
        out.println("  2. Create rotation event in identity log");
        out.println("  3. Update key alias mappings");
        return Ok(());
    }

    // Extra confirmation for rotation
    if !cmd.yes {
        out.print_warn("Key rotation is a significant operation.");
        out.println("All devices will need to re-authorize.");
        out.newline();

        let confirmation: String = Input::new()
            .with_prompt("Type ROTATE to confirm")
            .interact_text()?;

        if confirmation != "ROTATE" {
            out.println("Cancelled - confirmation not matched.");
            return Ok(());
        }
    }

    // Resolve repository
    let repo_path = layout::resolve_repo_path(cmd.repo)?;
    let config = StorageLayoutConfig::default();

    let keychain = get_platform_keychain()?;

    out.print_info("Rotating key...");
    let current_alias = KeyAlias::new_unchecked(current_alias);
    let next_alias = KeyAlias::new_unchecked(next_alias);
    let rotation_info = rotate_keri_identity(
        &repo_path,
        &current_alias,
        &next_alias,
        ctx.passphrase_provider.as_ref(),
        &config,
        keychain.as_ref(),
        None,
        now,
    )
    .context("Key rotation failed")?;

    out.print_success(&format!(
        "Key rotation complete (new sequence: {})",
        rotation_info.sequence
    ));
    out.newline();
    out.println("Next steps:");
    out.println("  1. Re-authorize your devices: auths device link");
    out.println("  2. Update any CI/CD secrets");
    out.println("  3. Run `auths doctor` to verify setup");

    Ok(())
}

/// Handle freeze operation — temporarily disables all signing.
fn handle_freeze(cmd: FreezeCommand, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    use auths_id::freeze::{FreezeState, load_active_freeze, parse_duration, store_freeze};
    use auths_id::storage::layout;

    let out = Output::new();

    out.print_heading("Identity Freeze");
    out.newline();

    // Parse duration
    let duration = parse_duration(&cmd.duration)?;
    let frozen_at = now;
    let frozen_until = frozen_at + duration;

    out.println(&format!(
        "Duration: {} (until {})",
        out.info(&cmd.duration),
        out.info(&frozen_until.format("%Y-%m-%d %H:%M UTC").to_string())
    ));
    out.newline();

    // Resolve repository
    let repo_path = layout::resolve_repo_path(cmd.repo)?;

    // Check for existing freeze
    if let Some(existing) = load_active_freeze(&repo_path, now)? {
        let existing_until = existing.frozen_until;
        if frozen_until > existing_until {
            out.print_warn(&format!(
                "Existing freeze active until {}. Will extend to {}.",
                existing_until.format("%Y-%m-%d %H:%M UTC"),
                frozen_until.format("%Y-%m-%d %H:%M UTC"),
            ));
        } else {
            out.print_warn(&format!(
                "Existing freeze already active until {} (longer than requested).",
                existing_until.format("%Y-%m-%d %H:%M UTC"),
            ));
            out.println("Use a longer duration to extend, or unfreeze first.");
            return Ok(());
        }
        out.newline();
    }

    if cmd.dry_run {
        out.print_info("Dry run mode - no changes will be made");
        out.newline();
        out.println("Would perform the following actions:");
        out.println(&format!(
            "  1. Freeze all signing operations for {}",
            cmd.duration
        ));
        out.println(&format!(
            "  2. Write freeze state to {}",
            repo_path.join("freeze.json").display()
        ));
        out.println("  3. auths-sign will refuse to sign until freeze expires");
        return Ok(());
    }

    // Confirmation
    if !cmd.yes {
        let confirmation: String = dialoguer::Input::new()
            .with_prompt("Type FREEZE to confirm")
            .interact_text()?;

        if confirmation != "FREEZE" {
            out.println("Cancelled - confirmation not matched.");
            return Ok(());
        }
    }

    let state = FreezeState {
        frozen_at,
        frozen_until,
        reason: Some(format!("Emergency freeze for {}", cmd.duration)),
    };

    store_freeze(&repo_path, &state)?;

    out.print_success(&format!(
        "Identity frozen until {}",
        frozen_until.format("%Y-%m-%d %H:%M UTC")
    ));
    out.newline();
    out.println("All signing operations are disabled.");
    out.println(&format!(
        "Freeze expires in: {}",
        out.info(&state.expires_description(now))
    ));
    out.newline();
    out.println("To unfreeze early:");
    out.println(&format!("  {}", out.dim("auths emergency unfreeze")));

    Ok(())
}

/// Handle unfreeze — cancel an active freeze early.
fn handle_unfreeze(cmd: UnfreezeCommand, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    use auths_id::freeze::{load_active_freeze, remove_freeze};
    use auths_id::storage::layout;

    let out = Output::new();

    let repo_path = layout::resolve_repo_path(cmd.repo)?;

    match load_active_freeze(&repo_path, now)? {
        Some(state) => {
            out.println(&format!(
                "Active freeze until {}",
                out.info(&state.frozen_until.format("%Y-%m-%d %H:%M UTC").to_string())
            ));
            out.newline();

            if !cmd.yes {
                let confirm = Confirm::new()
                    .with_prompt("Remove freeze and restore signing?")
                    .default(false)
                    .interact()?;

                if !confirm {
                    out.println("Cancelled.");
                    return Ok(());
                }
            }

            remove_freeze(&repo_path)?;
            out.print_success("Freeze removed. Signing operations are restored.");
        }
        None => {
            out.print_info("No active freeze found.");
        }
    }

    Ok(())
}

/// Handle incident report generation.
fn handle_report(cmd: ReportCommand, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    use auths_id::identity::helpers::ManagedIdentity;
    use auths_id::storage::attestation::AttestationSource;
    use auths_id::storage::identity::IdentityStorage;
    use auths_id::storage::layout;
    use auths_storage::git::{RegistryAttestationStorage, RegistryIdentityStorage};

    let out = Output::new();

    let repo_path = layout::resolve_repo_path(cmd.repo.clone())?;

    // Load real identity
    let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
    let identity_did = match identity_storage.load_identity() {
        Ok(ManagedIdentity { controller_did, .. }) => Some(controller_did),
        Err(_) => None,
    };

    // Load real device attestations
    let attestation_storage = RegistryAttestationStorage::new(repo_path);
    let all_attestations = attestation_storage
        .load_all_attestations()
        .unwrap_or_default();

    // Build device list from attestations (deduplicate by subject DID)
    let mut seen_devices = std::collections::HashSet::new();
    let mut devices = Vec::new();
    for att in &all_attestations {
        let did_str = att.subject.to_string();
        if seen_devices.insert(did_str.clone()) {
            let status = if att.is_revoked() {
                "revoked"
            } else if att.expires_at.is_some_and(|exp| exp <= now) {
                "expired"
            } else {
                "active"
            };
            devices.push(DeviceInfo {
                did: did_str,
                name: att.note.clone(),
                status: status.to_string(),
                last_active: att.timestamp.map(|t| t.to_rfc3339()),
            });
        }
    }

    // Build recent events from attestation history (most recent first, capped)
    let mut events: Vec<&auths_verifier::core::Attestation> = all_attestations.iter().collect();
    events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    let recent_events: Vec<EventInfo> = events
        .iter()
        .take(cmd.events)
        .map(|att| {
            let event_type = if att.is_revoked() {
                "device_revocation"
            } else {
                "device_authorization"
            };
            EventInfo {
                timestamp: att.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
                event_type: event_type.to_string(),
                details: format!("{} for {}", event_type, att.subject),
            }
        })
        .collect();

    // Generate recommendations based on actual state
    let mut recommendations = Vec::new();
    let active_count = devices.iter().filter(|d| d.status == "active").count();
    let revoked_count = devices.iter().filter(|d| d.status == "revoked").count();
    let expired_count = devices.iter().filter(|d| d.status == "expired").count();

    if active_count > 0 {
        recommendations.push(format!(
            "Review all {} active device authorizations",
            active_count
        ));
    }
    if expired_count > 0 {
        recommendations.push(format!(
            "Clean up {} expired device authorizations",
            expired_count
        ));
    }
    if revoked_count > 0 {
        recommendations.push(format!(
            "{} device(s) already revoked — verify these were intentional",
            revoked_count
        ));
    }
    recommendations.push("Check for any unexpected signing activity".to_string());

    let report = IncidentReport {
        generated_at: now.to_rfc3339(),
        identity_did: identity_did.map(|d| d.to_string()),
        devices,
        recent_events,
        recommendations,
    };

    if is_json_mode() {
        let json = serde_json::to_string_pretty(&report)?;
        if let Some(output_path) = &cmd.output_file {
            std::fs::write(output_path, &json)
                .with_context(|| format!("Failed to write report to {:?}", output_path))?;
            out.print_success(&format!("Report saved to {}", output_path.display()));
        } else {
            println!("{}", json);
        }
        return Ok(());
    }

    // Text output
    out.print_heading("Incident Report");
    out.newline();

    out.println(&format!("Generated: {}", out.info(&report.generated_at)));
    if let Some(did) = &report.identity_did {
        out.println(&format!("Identity: {}", out.info(did)));
    }
    out.newline();

    out.print_heading("  Devices");
    for device in &report.devices {
        let status_icon = if device.status == "active" {
            out.success("●")
        } else {
            out.error("○")
        };
        out.println(&format!(
            "    {} {} ({}) - {}",
            status_icon,
            device.did,
            device.name.as_deref().unwrap_or("unnamed"),
            device.status
        ));
    }
    out.newline();

    out.print_heading("  Recent Events");
    for event in &report.recent_events {
        out.println(&format!(
            "    {} [{}] {}",
            out.dim(&event.timestamp[..19]),
            event.event_type,
            event.details
        ));
    }
    out.newline();

    out.print_heading("  Recommendations");
    for (i, rec) in report.recommendations.iter().enumerate() {
        out.println(&format!("    {}. {}", i + 1, rec));
    }

    if let Some(output_path) = &cmd.output_file {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(output_path, json)
            .with_context(|| format!("Failed to write report to {:?}", output_path))?;
        out.newline();
        out.print_success(&format!("Report also saved to {}", output_path.display()));
    }

    Ok(())
}

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for EmergencyCommand {
    #[allow(clippy::disallowed_methods)]
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_emergency(self.clone(), chrono::Utc::now(), ctx)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_report_serialization() {
        let report = IncidentReport {
            generated_at: "2024-01-15T10:30:00Z".to_string(),
            identity_did: Some("did:keri:ETest".to_string()),
            devices: vec![],
            recent_events: vec![],
            recommendations: vec!["Test recommendation".to_string()],
        };

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("did:keri:ETest"));
        assert!(json.contains("Test recommendation"));
    }

    #[test]
    fn test_device_info_serialization() {
        let device = DeviceInfo {
            did: "did:key:z6MkTest".to_string(),
            name: Some("Test Device".to_string()),
            status: "active".to_string(),
            last_active: None,
        };

        let json = serde_json::to_string(&device).unwrap();
        assert!(json.contains("did:key:z6MkTest"));
        assert!(json.contains("Test Device"));
    }

    #[test]
    fn test_freeze_dry_run() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = handle_freeze(
            FreezeCommand {
                duration: "24h".to_string(),
                yes: true,
                dry_run: true,
                repo: Some(dir.path().to_path_buf()),
            },
            chrono::Utc::now(),
        );

        assert!(result.is_ok());
        // Dry run should NOT create the freeze file
        assert!(!dir.path().join("freeze.json").exists());
    }

    #[test]
    fn test_freeze_creates_freeze_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = handle_freeze(
            FreezeCommand {
                duration: "1h".to_string(),
                yes: true,
                dry_run: false,
                repo: Some(dir.path().to_path_buf()),
            },
            chrono::Utc::now(),
        );

        assert!(result.is_ok());
        assert!(dir.path().join("freeze.json").exists());

        // Verify the freeze is active
        let state = auths_id::freeze::load_active_freeze(dir.path(), chrono::Utc::now()).unwrap();
        assert!(state.is_some());
    }

    #[test]
    fn test_freeze_invalid_duration() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = handle_freeze(
            FreezeCommand {
                duration: "invalid".to_string(),
                yes: true,
                dry_run: false,
                repo: Some(dir.path().to_path_buf()),
            },
            chrono::Utc::now(),
        );

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid") || err_msg.contains("duration"),
            "Expected duration parse error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_unfreeze_removes_freeze() {
        let dir = tempfile::TempDir::new().unwrap();

        // Create a freeze
        handle_freeze(
            FreezeCommand {
                duration: "24h".to_string(),
                yes: true,
                dry_run: false,
                repo: Some(dir.path().to_path_buf()),
            },
            chrono::Utc::now(),
        )
        .unwrap();
        assert!(dir.path().join("freeze.json").exists());

        // Unfreeze
        handle_unfreeze(
            UnfreezeCommand {
                yes: true,
                repo: Some(dir.path().to_path_buf()),
            },
            chrono::Utc::now(),
        )
        .unwrap();
        assert!(!dir.path().join("freeze.json").exists());
    }
}
