//! `auths treasury …` — an aggregate cap across a manager's sub-delegated agents.
//!
//! `auths credential issue --cap calls:<N>` bounds **one** delegation. A fund-of-agents
//! needs the *aggregate* dimension: a manager holds a parent cap and allots bounded
//! **slices** to sub-agents, with `Σ slices ≤ parent_cap` enforced at every allotment,
//! and the budget **reallocatable** between sub-agents without ever exceeding the
//! parent. This is the thin presentation layer; all bookkeeping lives in
//! `auths_sdk::domains::treasury` (the aggregate analogue of the usage ledger).

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use auths_sdk::storage_layout::layout;

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::ux::format::{JsonResponse, is_json_mode};

/// Manage an aggregate treasury cap across a manager's sub-delegated agents.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Aggregate treasury cap: allot bounded slices across sub-agents, reallocatable, with Σ ≤ cap.",
    after_help = "Examples:
  auths treasury open       --manager my-key --cap calls:10
  auths treasury allot      --manager my-key --to did:keri:E… --amount 4
  auths treasury reallocate --manager my-key --from did:keri:E… --to did:keri:E… --amount 2
  auths treasury status     --manager my-key"
)]
pub struct TreasuryCommand {
    #[clap(subcommand)]
    pub subcommand: TreasurySubcommand,
}

/// Treasury subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum TreasurySubcommand {
    /// Establish a manager's aggregate cap.
    Open {
        #[arg(long, help = "Manager keychain alias (the ledger key).")]
        manager: String,
        #[arg(long, help = "Aggregate cap (calls:<N> or a plain integer).")]
        cap: String,
    },
    /// Commit a slice of the cap to a sub-agent (refused if Σ + amount > cap).
    Allot {
        #[arg(long)]
        manager: String,
        #[arg(long = "to", help = "Sub-agent did:keri: to allot to.")]
        to: String,
        #[arg(long)]
        amount: u64,
    },
    /// Move a slice from one sub-agent to another (constant-sum; refused on underflow).
    Reallocate {
        #[arg(long)]
        manager: String,
        #[arg(long, help = "Source sub-agent did:keri:.")]
        from: String,
        #[arg(long = "to", help = "Target sub-agent did:keri:.")]
        to: String,
        #[arg(long)]
        amount: u64,
    },
    /// Report parent cap, committed, free pool, slices, and the aggregate invariant.
    Status {
        #[arg(long)]
        manager: String,
    },
}

impl ExecutableCommand for TreasuryCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        let repo_path = layout::resolve_repo_path(ctx.repo_path.clone())?;
        handle_treasury(self.clone(), repo_path)
    }
}

/// Parse a cap predicate: `calls:<N>` (the AGT-4 grammar) or a plain integer.
fn parse_cap(s: &str) -> Result<u64> {
    let raw = s.strip_prefix("calls:").unwrap_or(s).trim();
    raw.parse::<u64>().map_err(|_| {
        anyhow::anyhow!("invalid cap {s:?}: expected calls:<N> or a non-negative integer")
    })
}

/// Dispatch an `auths treasury …` subcommand against the repo-rooted ledger.
pub fn handle_treasury(cmd: TreasuryCommand, repo_path: PathBuf) -> Result<()> {
    use auths_sdk::domains::treasury;
    match cmd.subcommand {
        TreasurySubcommand::Open { manager, cap } => {
            let parent_cap = parse_cap(&cap)?;
            let v = treasury::open(&repo_path, &manager, parent_cap).map_err(anyhow::Error::new)?;
            emit(
                "treasury open",
                serde_json::json!({ "status": v.status(), "manager": manager, "parent_cap": parent_cap }),
                &format!("treasury cap established for {manager}: {parent_cap}"),
            )
        }
        TreasurySubcommand::Allot { manager, to, amount } => {
            let v = treasury::allot(&repo_path, &manager, &to, amount).map_err(anyhow::Error::new)?;
            emit(
                "treasury allot",
                serde_json::json!({ "status": v.status(), "manager": manager, "to": to, "amount": amount }),
                &format!("allot {amount} → {to}: {}", v.status()),
            )
        }
        TreasurySubcommand::Reallocate { manager, from, to, amount } => {
            let v = treasury::reallocate(&repo_path, &manager, &from, &to, amount)
                .map_err(anyhow::Error::new)?;
            emit(
                "treasury reallocate",
                serde_json::json!({ "status": v.status(), "manager": manager, "from": from, "to": to, "amount": amount }),
                &format!("reallocate {amount} {from}→{to}: {}", v.status()),
            )
        }
        TreasurySubcommand::Status { manager } => {
            let st = treasury::status(&repo_path, &manager).map_err(anyhow::Error::new)?;
            if is_json_mode() {
                JsonResponse::success("treasury status", &st).print()?;
            } else {
                println!(
                    "treasury {manager}: cap {} · committed {} · free {} · {}",
                    st.parent_cap, st.committed, st.free_pool, st.status
                );
                for s in &st.slices {
                    println!("  slice {} = {}", s.agent_did, s.amount);
                }
            }
            Ok(())
        }
    }
}

/// Print a mutation outcome — the verdict JSON under `--json`, else a human line.
fn emit(command: &str, data: serde_json::Value, human: &str) -> Result<()> {
    if is_json_mode() {
        JsonResponse::success(command, data).print()?;
    } else {
        println!("✓ {human}");
    }
    Ok(())
}
