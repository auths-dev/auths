//! Trust management commands for Auths.
//!
//! Manage pinned identity roots for trust-on-first-use (TOFU) and explicit trust.

use crate::ux::format::{JsonResponse, Output, is_json_mode};
use anyhow::{Context, Result, anyhow};
use auths_sdk::trust::{PinnedIdentity, PinnedIdentityStore, TrustLevel};
use auths_verifier::PublicKeyHex;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::PathBuf;

/// Manage trusted identity roots.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "trust",
    about = "Pin identities you trust for verification",
    after_help = "Examples:
  auths trust list          # Show all pinned trusted identities
  auths trust pin --did did:keri:EExample
                            # Pin an identity (key resolved from its local KEL)
  auths trust pin --did did:keri:EExample --bundle their-bundle.json
                            # Pin from an exported identity bundle
  auths trust remove did:keri:EExample
                            # Remove a pinned identity
  auths trust show did:keri:EExample
                            # Show details of a trusted identity

Related:
  auths verify  — Verify signatures (uses trust store)
  auths sign    — Create signatures
  auths error   — Troubleshoot trust policy errors"
)]
pub struct TrustCommand {
    #[command(subcommand)]
    pub command: TrustSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TrustSubcommand {
    /// List all pinned identities.
    List(TrustListCommand),

    /// Manually pin an identity as trusted.
    Pin(TrustPinCommand),

    /// Remove a pinned identity.
    Remove(TrustRemoveCommand),

    /// Show details of a pinned identity.
    Show(TrustShowCommand),
}

/// List all pinned identities.
#[derive(Parser, Debug, Clone)]
pub struct TrustListCommand {}

/// Manually pin an identity as trusted.
#[derive(Parser, Debug, Clone)]
pub struct TrustPinCommand {
    /// The DID of the identity to pin (e.g., did:keri:E...).
    #[clap(long, required = true)]
    pub did: String,

    /// The public key in hex format. Omit it to resolve the current key from
    /// the identity's locally-replayed KEL (air-gapped ceremony is the only
    /// case that needs the explicit hex).
    #[clap(long)]
    pub key: Option<String>,

    /// Path to an identity bundle JSON to resolve the key from (alternative to
    /// --key and to local KEL resolution).
    #[clap(long)]
    pub bundle: Option<std::path::PathBuf>,

    /// Identity log checkpoint for tracking key changes (optional, advanced).
    #[clap(long)]
    pub kel_tip: Option<String>,

    /// Optional note about this identity.
    #[clap(long)]
    pub note: Option<String>,
}

/// Remove a pinned identity.
#[derive(Parser, Debug, Clone)]
pub struct TrustRemoveCommand {
    /// The DID of the identity to remove.
    pub did: String,
}

/// Show details of a pinned identity.
#[derive(Parser, Debug, Clone)]
pub struct TrustShowCommand {
    /// The DID of the identity to show.
    pub did: String,
}

/// JSON output for pin/remove action result.
#[derive(Debug, Serialize)]
struct TrustActionResult {
    did: String,
}

/// JSON output for list command.
#[derive(Debug, Serialize)]
struct PinListOutput {
    pins: Vec<PinSummary>,
}

/// Summary of a pinned identity for list output.
#[derive(Debug, Serialize)]
struct PinSummary {
    did: String,
    trust_level: String,
    first_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kel_sequence: Option<u128>,
}

/// JSON output for show command.
#[derive(Debug, Serialize)]
struct PinDetails {
    did: String,
    public_key_hex: PublicKeyHex,
    trust_level: String,
    first_seen: String,
    origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kel_tip_said: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kel_sequence: Option<u128>,
}

/// Resolve the pinned-identity store for the active registry, honoring `--repo`.
///
/// Args:
/// * `repo`: The optional `--repo` override; `None` selects the default `~/.auths` registry.
///
/// Usage:
/// ```ignore
/// let store = pinned_store(ctx.repo_path.clone())?;
/// ```
fn pinned_store(repo: Option<PathBuf>) -> Result<PinnedIdentityStore> {
    let registry = auths_sdk::storage_layout::resolve_repo_path(repo)
        .context("Failed to resolve the repository path for the trust store")?;
    let default = PinnedIdentityStore::default_path();
    let file_name = default
        .file_name()
        .ok_or_else(|| anyhow!("pin store path has no file name"))?;
    Ok(PinnedIdentityStore::new(registry.join(file_name)))
}

/// Handle trust subcommands.
#[allow(clippy::disallowed_methods)]
pub fn handle_trust(cmd: TrustCommand, repo: Option<PathBuf>) -> Result<()> {
    let store = pinned_store(repo)?;
    let now = Utc::now();
    match cmd.command {
        TrustSubcommand::List(list_cmd) => handle_list(list_cmd, &store),
        TrustSubcommand::Pin(pin_cmd) => handle_pin(pin_cmd, &store, now),
        TrustSubcommand::Remove(remove_cmd) => handle_remove(remove_cmd, &store),
        TrustSubcommand::Show(show_cmd) => handle_show(show_cmd, &store),
    }
}

fn handle_list(_cmd: TrustListCommand, store: &PinnedIdentityStore) -> Result<()> {
    let pins = store.list()?;

    if is_json_mode() {
        JsonResponse::success(
            "trust list",
            PinListOutput {
                pins: pins
                    .iter()
                    .map(|p| PinSummary {
                        did: p.did.clone(),
                        trust_level: format!("{:?}", p.trust_level),
                        first_seen: p.first_seen.to_rfc3339(),
                        kel_sequence: p.kel_sequence,
                    })
                    .collect(),
            },
        )
        .print()?;
    } else {
        let out = Output::new();
        if pins.is_empty() {
            out.println(&out.dim("No pinned identities."));
            out.println("");
            out.println("Use 'auths trust pin --did <DID> --key <HEX>' to pin an identity.");
        } else {
            out.println(&format!("{} pinned identities:", pins.len()));
            out.println("");
            for pin in &pins {
                let level = match pin.trust_level {
                    TrustLevel::Tofu => out.dim("TOFU"),
                    TrustLevel::Manual => out.info("Manual"),
                    TrustLevel::OrgPolicy => out.success("OrgPolicy"),
                };
                out.println(&format!("  {} [{}]", pin.did, level));
            }
        }
    }

    Ok(())
}

/// Resolve the key material for a pin: explicit `--key` hex, a `--bundle`
/// file, or the identity's locally-replayed KEL — in that order. Humans never
/// have to produce raw hex on the happy path.
fn resolve_pin_key(cmd: &TrustPinCommand) -> Result<(PublicKeyHex, auths_crypto::CurveType)> {
    if let Some(ref key_hex) = cmd.key {
        let public_key_hex = PublicKeyHex::parse(key_hex).context("Invalid public key hex")?;
        let curve = auths_crypto::did_key_decode(&cmd.did)
            .map(|d| d.curve())
            .unwrap_or_default();
        return Ok((public_key_hex, curve));
    }
    if let Some(ref bundle_path) = cmd.bundle {
        let content = std::fs::read_to_string(bundle_path)
            .with_context(|| format!("Failed to read identity bundle: {bundle_path:?}"))?;
        let bundle: auths_verifier::IdentityBundle = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse identity bundle: {bundle_path:?}"))?;
        if bundle.identity_did.as_str() != cmd.did {
            anyhow::bail!(
                "Bundle is for {} but --did is {}",
                bundle.identity_did.as_str(),
                cmd.did
            );
        }
        return Ok((bundle.public_key_hex.clone(), bundle.curve));
    }
    let auths_home = auths_sdk::paths::auths_home().map_err(|e| anyhow!(e))?;
    let registry = auths_sdk::storage::GitRegistryBackend::from_config_unchecked(
        auths_sdk::storage::RegistryConfig::single_tenant(&auths_home),
    );
    let (pk, curve) = auths_sdk::keri::resolve_current_public_key(&registry, &cmd.did)
        .with_context(|| {
            format!(
                "Could not resolve {} from the local registry. Provide --bundle <file> \
                 (ask the identity owner for `auths id export-bundle`) or --key <hex>.",
                cmd.did
            )
        })?;
    #[allow(clippy::disallowed_methods)] // INVARIANT: hex::encode always produces valid hex
    Ok((PublicKeyHex::new_unchecked(hex::encode(pk)), curve))
}

fn handle_pin(cmd: TrustPinCommand, store: &PinnedIdentityStore, now: DateTime<Utc>) -> Result<()> {
    let (public_key_hex, curve) = resolve_pin_key(&cmd)?;

    // Check if already pinned
    if let Some(existing) = store.lookup(&cmd.did)? {
        anyhow::bail!(
            "Identity {} is already pinned (first seen: {}). Use 'auths trust remove {}' first.",
            cmd.did,
            existing.first_seen.format("%Y-%m-%d"),
            cmd.did
        );
    }

    let pin = PinnedIdentity {
        did: cmd.did.clone(),
        public_key_hex: public_key_hex.clone(),
        curve,
        kel_tip_said: cmd.kel_tip,
        kel_sequence: None,
        first_seen: now,
        origin: cmd.note.unwrap_or_else(|| "manual".to_string()),
        trust_level: TrustLevel::Manual,
    };

    store.pin(pin)?;

    if is_json_mode() {
        JsonResponse::success(
            "trust pin",
            TrustActionResult {
                did: cmd.did.clone(),
            },
        )
        .print()?;
    } else {
        let out = Output::new();
        out.println(&format!(
            "{} Pinned identity: {}",
            out.success("OK"),
            &cmd.did
        ));
    }

    Ok(())
}

fn handle_remove(cmd: TrustRemoveCommand, store: &PinnedIdentityStore) -> Result<()> {
    // Check if exists
    if store.lookup(&cmd.did)?.is_none() {
        anyhow::bail!(
            "Identity {} is not pinned. Pin it first with: auths trust pin {}",
            cmd.did,
            cmd.did
        );
    }

    store.remove(&cmd.did)?;

    if is_json_mode() {
        JsonResponse::success(
            "trust remove",
            TrustActionResult {
                did: cmd.did.clone(),
            },
        )
        .print()?;
    } else {
        let out = Output::new();
        out.println(&format!(
            "{} Removed pin for: {}",
            out.success("OK"),
            &cmd.did
        ));
    }

    Ok(())
}

fn handle_show(cmd: TrustShowCommand, store: &PinnedIdentityStore) -> Result<()> {
    let pin = store.lookup(&cmd.did)?.ok_or_else(|| {
        anyhow!(
            "Identity {} is not pinned. Pin it first with: auths trust pin {}",
            cmd.did,
            cmd.did
        )
    })?;

    if is_json_mode() {
        JsonResponse::success(
            "trust show",
            PinDetails {
                did: pin.did.clone(),
                public_key_hex: pin.public_key_hex.clone(),
                trust_level: format!("{:?}", pin.trust_level),
                first_seen: pin.first_seen.to_rfc3339(),
                origin: pin.origin.clone(),
                kel_tip_said: pin.kel_tip_said.clone(),
                kel_sequence: pin.kel_sequence,
            },
        )
        .print()?;
    } else {
        let out = Output::new();
        out.println(&format!("DID:          {}", pin.did));
        out.println(&format!("Public Key:   {}", pin.public_key_hex));
        out.println(&format!("Trust Level:  {:?}", pin.trust_level));
        out.println(&format!(
            "First Seen:   {}",
            pin.first_seen.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        out.println(&format!("Origin:       {}", pin.origin));
        if let Some(ref tip) = pin.kel_tip_said {
            out.println(&format!("Log checkpoint: {}", tip));
        }
        if let Some(seq) = pin.kel_sequence {
            out.println(&format!("Log sequence:   {}", seq));
        }
    }

    Ok(())
}

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for TrustCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_trust(self.clone(), ctx.repo_path.clone())
    }
}
