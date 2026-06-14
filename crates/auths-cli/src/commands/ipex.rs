//! `auths ipex` — IPEX (Issuance & Presentation EXchange) credential handover.
//!
//! IPEX is KERI's standard peer-to-peer handshake for moving an ACDC credential
//! between two controllers: the discloser sends a `grant` `exn` carrying the
//! credential, and the holder answers with an `admit` `exn` that references the
//! grant's SAID. It is the interoperable alternative to a bespoke presentation
//! wire — a credential exchanged this way is one keripy/KERIA can ingest, and a
//! grant a keripy peer sends is one auths can parse.
//!
//! Two directions, mirroring the two roles in a disclosure:
//!
//! * `auths ipex grant` — discloser → holder: read a saidified ACDC, embed it in
//!   a `/ipex/grant` `exn` addressed to the recipient, and print the `exn`.
//! * `auths ipex admit` — holder → discloser: read a peer's grant `exn`, verify
//!   it (and the credential inside it), and print an `/ipex/admit` `exn` whose
//!   prior is the grant's SAID.
//!
//! The wire definitions (the `exn` records, their SAIDs, the embeds block) live
//! in `auths-keri::ipex` and are byte-exact with keripy 1.3.4; this is a thin
//! file-based CLI adapter over them. Signing the `exn` and putting it on a
//! transport are the caller's concern — this surface produces the canonical
//! bytes to sign and send.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use auths_keri::{Acdc, IpexAdmit, IpexGrant, Prefix};
use auths_utils::path::expand_tilde;
use clap::{Parser, Subcommand};

use crate::config::CliConfig;

/// Default datetime stamp — the epoch, so output is deterministic unless the
/// operator passes a real `now`. Matches the OOBI command's convention.
const DEFAULT_DT: &str = "1970-01-01T00:00:00.000000+00:00";

/// Exchange an ACDC credential over IPEX (grant/admit), interoperable with keripy/KERIA.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Exchange a credential over IPEX (grant/admit) — interoperable with keripy/KERIA",
    after_help = "Examples:
  auths ipex grant --acdc cred.json --sender EOoC... --recipient EBHn...
  auths ipex admit --grant grant.json --sender EBHn..."
)]
pub struct IpexCommand {
    /// The IPEX direction to run.
    #[command(subcommand)]
    pub action: IpexAction,
}

/// The two IPEX directions: grant a credential, or admit a received grant.
#[derive(Subcommand, Debug, Clone)]
pub enum IpexAction {
    /// Grant (disclose) a credential: embed an ACDC in a `/ipex/grant` `exn`.
    Grant(GrantArgs),
    /// Admit (accept) a received grant: emit an `/ipex/admit` `exn` for it.
    Admit(AdmitArgs),
}

/// `auths ipex grant` — disclose a credential to a holder.
#[derive(Parser, Debug, Clone)]
pub struct GrantArgs {
    /// The saidified ACDC credential to disclose (its JSON body, `{v,d,i,ri,s,a}`).
    #[clap(long, value_name = "ACDC.json")]
    pub acdc: PathBuf,

    /// The discloser (sender) AID granting the credential.
    #[clap(long, value_name = "AID")]
    pub sender: String,

    /// The recipient (holder) AID the credential is granted to.
    #[clap(long, value_name = "AID")]
    pub recipient: String,

    /// Optional human-readable disclosure message (`a.m`).
    #[clap(long, default_value = "")]
    pub message: String,

    /// Timestamp (RFC 3339) to stamp the `exn` with. Defaults to the epoch so
    /// output stays deterministic; pass the real `now` to send.
    #[clap(long, default_value = DEFAULT_DT)]
    pub dt: String,
}

/// `auths ipex admit` — accept a credential a peer granted.
#[derive(Parser, Debug, Clone)]
pub struct AdmitArgs {
    /// The peer's grant `exn` to admit (its JSON body).
    #[clap(long, value_name = "GRANT.json")]
    pub grant: PathBuf,

    /// The holder (sender) AID admitting the disclosure.
    #[clap(long, value_name = "AID")]
    pub sender: String,

    /// Optional human-readable admission message (`a.m`).
    #[clap(long, default_value = "")]
    pub message: String,

    /// Timestamp (RFC 3339) to stamp the `exn` with. Defaults to the epoch so
    /// output stays deterministic; pass the real `now` to send.
    #[clap(long, default_value = DEFAULT_DT)]
    pub dt: String,
}

impl IpexCommand {
    /// Run the command (grant a credential or admit a received grant).
    pub fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        match &self.action {
            IpexAction::Grant(args) => args.run(),
            IpexAction::Admit(args) => args.run(),
        }
    }
}

impl GrantArgs {
    fn run(&self) -> Result<()> {
        // Parse the AIDs at the boundary — an invalid prefix never reaches the
        // grant builder.
        let sender = Prefix::new(self.sender.clone())
            .map_err(|e| anyhow!("parse sender AID {:?}: {e}", self.sender))?;
        let recipient = Prefix::new(self.recipient.clone())
            .map_err(|e| anyhow!("parse recipient AID {:?}: {e}", self.recipient))?;

        let acdc = read_acdc(&self.acdc)?;

        let grant = IpexGrant::new(
            sender,
            recipient,
            acdc,
            self.message.clone(),
            self.dt.clone(),
        )
        .map_err(|e| anyhow!("build IPEX grant: {e}"))?;
        println!("{}", serde_json::to_string(&grant)?);
        Ok(())
    }
}

impl AdmitArgs {
    fn run(&self) -> Result<()> {
        let sender = Prefix::new(self.sender.clone())
            .map_err(|e| anyhow!("parse sender AID {:?}: {e}", self.sender))?;

        // Parse the peer's grant — its `exn` SAID and the embedded ACDC are both
        // verified by `IpexGrant::parse`, so we never admit a tampered grant.
        let path = expand_tilde(&self.grant)?;
        let json = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("read grant {}: {e}", path.display()))?;
        let grant = IpexGrant::parse(&json).map_err(|e| anyhow!("parse IPEX grant: {e}"))?;

        let admit = IpexAdmit::new(
            sender,
            grant.d.clone(),
            self.message.clone(),
            self.dt.clone(),
        )
        .map_err(|e| anyhow!("build IPEX admit: {e}"))?;
        println!("{}", serde_json::to_string(&admit)?);
        Ok(())
    }
}

/// Reads a saidified ACDC from a JSON file, verifying its SAID at the boundary —
/// a grant cannot disclose a credential that doesn't stand on its own digest.
fn read_acdc(acdc_path: &Path) -> Result<Acdc> {
    let path = expand_tilde(acdc_path)?;
    let json =
        std::fs::read_to_string(&path).map_err(|e| anyhow!("read ACDC {}: {e}", path.display()))?;
    let acdc: Acdc =
        serde_json::from_str(&json).map_err(|e| anyhow!("parse ACDC {}: {e}", path.display()))?;
    acdc.verify_said()
        .map_err(|e| anyhow!("verify ACDC SAID {}: {e}", path.display()))?;
    Ok(acdc)
}
