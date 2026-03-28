//! Trust management commands for Auths.
//!
//! Manage pinned identity roots for trust-on-first-use (TOFU) and explicit trust.

use crate::ux::format::{JsonResponse, Output, is_json_mode};
use anyhow::{Context, Result, anyhow};
use auths_core::trust::{PinnedIdentity, PinnedIdentityStore, TrustLevel};
use auths_verifier::PublicKeyHex;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::Serialize;

/// Manage trusted identity roots.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "trust",
    about = "Manage trusted identity roots",
    after_help = "Examples:
  auths trust list          # Show all pinned trusted identities
  auths trust pin --did did:keri:EExample --key 7f8c9d0e1a2b3c4d...
                            # Pin an identity as trusted
  auths trust remove --did did:keri:EExample
                            # Remove a pinned identity
  auths trust show --did did:keri:EExample
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

    /// The public key in hex format (64 chars for Ed25519).
    #[clap(long, required = true)]
    pub key: String,

    /// Optional KEL tip SAID for rotation tracking.
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
    kel_sequence: Option<u64>,
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
    kel_sequence: Option<u64>,
}

/// Handle trust subcommands.
#[allow(clippy::disallowed_methods)]
pub fn handle_trust(cmd: TrustCommand) -> Result<()> {
    let now = Utc::now();
    match cmd.command {
        TrustSubcommand::List(list_cmd) => handle_list(list_cmd),
        TrustSubcommand::Pin(pin_cmd) => handle_pin(pin_cmd, now),
        TrustSubcommand::Remove(remove_cmd) => handle_remove(remove_cmd),
        TrustSubcommand::Show(show_cmd) => handle_show(show_cmd),
    }
}

fn handle_list(_cmd: TrustListCommand) -> Result<()> {
    let store = PinnedIdentityStore::new(PinnedIdentityStore::default_path());
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

fn handle_pin(cmd: TrustPinCommand, now: DateTime<Utc>) -> Result<()> {
    let public_key_hex = PublicKeyHex::parse(&cmd.key).context("Invalid public key hex")?;

    let store = PinnedIdentityStore::new(PinnedIdentityStore::default_path());

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
        public_key_hex,
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

fn handle_remove(cmd: TrustRemoveCommand) -> Result<()> {
    let store = PinnedIdentityStore::new(PinnedIdentityStore::default_path());

    // Check if exists
    if store.lookup(&cmd.did)?.is_none() {
        anyhow::bail!("Identity {} is not pinned.", cmd.did);
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

fn handle_show(cmd: TrustShowCommand) -> Result<()> {
    let store = PinnedIdentityStore::new(PinnedIdentityStore::default_path());

    let pin = store
        .lookup(&cmd.did)?
        .ok_or_else(|| anyhow!("Identity {} is not pinned.", cmd.did))?;

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
            out.println(&format!("KEL Tip:      {}", tip));
        }
        if let Some(seq) = pin.kel_sequence {
            out.println(&format!("KEL Sequence: {}", seq));
        }
    }

    Ok(())
}

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for TrustCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        handle_trust(self.clone())
    }
}
