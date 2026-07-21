//! `auths witness-set` — declare the spend-anchor witness set in your KEL.
//!
//! A finalized spend anchor is only as trustworthy as the witness set it names,
//! and verifiers refuse a set the seller never committed to. `declare` computes
//! the set's content SAID and anchors it in the identity's KEL via one `ixn`
//! (the declaration verifiers resolve); `said` prints the SAID without touching
//! the KEL. Thin presentation layer over
//! [`auths_sdk::workflows::witness_set`] — no domain logic lives here.

use anyhow::{Context, Result};
use auths_sdk::workflows::witness_set::{
    build_witness_set, declare_witness_set, resolve_declaration_alias,
};
use clap::{Parser, Subcommand};

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::factories::storage::build_auths_context;
use crate::ux::format::{JsonResponse, is_json_mode};

/// Declare the witness set your spend anchors commit to.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Declare the spend-anchor witness set, anchored in your KEL",
    after_help = "Examples:
  auths witness-set said --member w1=<hex> --member w2=p256:<hex> --threshold 2
  auths witness-set declare --member network=did:key:z6Mk... --threshold 1

Member keys carry their curve in-band: a CESR verkey, a did:key, `<curve>:<hex>`,
or bare hex (Ed25519 — the checkpoint-signing curve)."
)]
pub struct WitnessSetCommand {
    #[command(subcommand)]
    pub subcommand: WitnessSetSubcommand,
}

/// Witness-set subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum WitnessSetSubcommand {
    /// Anchor the set's content SAID in your KEL via one `ixn`, so verifiers
    /// hold your anchors to exactly this set.
    Declare {
        /// A declared member as `NAME=KEY` (repeatable).
        #[clap(long = "member", value_name = "NAME=KEY", required = true)]
        members: Vec<String>,

        /// The finalization threshold `t` of the `t`-of-`N` set.
        #[clap(long, value_name = "T")]
        threshold: u32,

        /// Keychain alias of your identity signing key (defaults to the
        /// identity's primary key).
        #[clap(long, value_name = "ALIAS")]
        key: Option<String>,
    },

    /// Print the set's content SAID without touching the KEL (deterministic).
    Said {
        /// A declared member as `NAME=KEY` (repeatable).
        #[clap(long = "member", value_name = "NAME=KEY", required = true)]
        members: Vec<String>,

        /// The finalization threshold `t` of the `t`-of-`N` set.
        #[clap(long, value_name = "T")]
        threshold: u32,
    },
}

#[derive(serde::Serialize)]
struct DeclareResponse {
    set_said: String,
    ixn_said: String,
    sequence: u128,
}

impl ExecutableCommand for WitnessSetCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        match &self.subcommand {
            WitnessSetSubcommand::Said { members, threshold } => print_said(members, *threshold),
            WitnessSetSubcommand::Declare {
                members,
                threshold,
                key,
            } => declare(ctx, members, *threshold, key.clone()),
        }
    }
}

/// Compute and print the set's content SAID — no KEL, no keychain.
fn print_said(members: &[String], threshold: u32) -> Result<()> {
    let set = build_witness_set(members, threshold).map_err(anyhow::Error::new)?;
    if is_json_mode() {
        JsonResponse::success(
            "witness-set said",
            serde_json::json!({ "set_said": set.said }),
        )
        .print()?;
    } else {
        println!("{}", set.said);
    }
    Ok(())
}

/// Build the set and anchor its SAID in the identity's KEL via the SDK workflow.
fn declare(ctx: &CliConfig, members: &[String], threshold: u32, key: Option<String>) -> Result<()> {
    let set = build_witness_set(members, threshold).map_err(anyhow::Error::new)?;
    let repo_path = auths_sdk::storage_layout::layout::resolve_repo_path(ctx.repo_path.clone())?;
    let sdk_ctx = build_auths_context(
        &repo_path,
        &ctx.env_config,
        Some(ctx.passphrase_provider.clone()),
    )?;
    let alias = resolve_declaration_alias(&sdk_ctx, key).map_err(anyhow::Error::new)?;
    let declared = declare_witness_set(&sdk_ctx, &alias, &set)
        .with_context(|| format!("Failed to declare witness set {}", set.said))?;

    if is_json_mode() {
        JsonResponse::success(
            "witness-set declare",
            DeclareResponse {
                set_said: declared.set_said,
                ixn_said: declared.ixn_said,
                sequence: declared.sequence,
            },
        )
        .print()?;
    } else {
        println!("✓ Witness set declared in your KEL:");
        println!("  set SAID  {}", declared.set_said);
        println!(
            "  anchored  ixn {} (seq {})",
            declared.ixn_said, declared.sequence
        );
        println!("  verifiers now hold your anchors to exactly this set");
    }
    Ok(())
}
