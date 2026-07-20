//! Offline verification of witness-network anchor artifacts.
//!
//! The witness returns a portable, self-contained duplicity proof when a party
//! equivocates. This command re-checks such a proof with no witness contacted
//! and no registry consulted — the artifact a counterparty or a regulator can
//! verify for themselves.

use std::path::PathBuf;

use anyhow::{Result, anyhow};
use auths_anchor::DuplicityProof;
use clap::{Parser, Subcommand};

use crate::config::CliConfig;

/// Verify witness-network anchor evidence, offline.
#[derive(Parser, Debug, Clone)]
pub struct AnchorCommand {
    #[command(subcommand)]
    pub subcommand: AnchorSubcommand,
}

/// Anchor subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum AnchorSubcommand {
    /// Verify a duplicity proof offline — no witness contacted, no registry.
    ///
    /// Re-checks that one party key signed two different heads at one
    /// `(seed, index)`. Exits non-zero with a named verdict if the proof is
    /// forged or tampered — the artifact you hand a counterparty or a court.
    Verify {
        /// Path to the duplicity-proof JSON (`-` reads stdin).
        #[clap(long)]
        proof: PathBuf,
    },
}

/// Dispatch an `auths anchor` subcommand.
///
/// Args:
/// * `cmd`: the parsed anchor command.
///
/// Usage:
/// ```ignore
/// handle_anchor(cmd)?;
/// ```
pub fn handle_anchor(cmd: AnchorCommand) -> Result<()> {
    match cmd.subcommand {
        AnchorSubcommand::Verify { proof } => verify_duplicity(proof),
    }
}

/// Read a duplicity proof (file path or `-` for stdin) and re-verify it offline.
fn verify_duplicity(path: PathBuf) -> Result<()> {
    let bytes = if path.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)
            .map_err(|e| anyhow!("could not read the proof from stdin: {e}"))?;
        buf
    } else {
        std::fs::read(&path).map_err(|e| anyhow!("could not read {}: {e}", path.display()))?
    };
    let proof: DuplicityProof = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow!("not a readable duplicity proof: {e}"))?;
    match proof.verify() {
        Ok(()) => {
            println!(
                "DUPLICITY PROVEN (offline, no witness contacted)\n  \
                 seed  {}\n  index {}\n  heads {} / {}\n  \
                 => one party key signed two heads at one index. CHEAT PROVEN.",
                proof.seed_id.to_hex(),
                proof.index,
                proof.anchor_a.head.to_hex(),
                proof.anchor_b.head.to_hex(),
            );
            Ok(())
        }
        Err(e) => Err(anyhow!("INVALID duplicity proof: {e}")),
    }
}

impl crate::commands::executable::ExecutableCommand for AnchorCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        handle_anchor(self.clone())
    }
}
