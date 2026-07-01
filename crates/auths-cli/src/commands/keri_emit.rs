//! `auths keri-emit` — emit a raw KERI event (JSON) from deterministic inputs.
//!
//! A hidden interop surface, like `did-webs` / `key-state`: it takes fixed,
//! caller-supplied inputs (keys, delegator, seals) and prints the canonical event
//! JSON the auths KERI builders produce, so the conformance suite can diff it
//! byte-for-byte against the keripy reference (`eventing.incept(delpre=...)` /
//! `eventing.interact(data=[seal])`). It builds nothing new — it calls the same
//! `auths_keri` finalizers the real delegation path uses.
//!
//! It never touches a KEL or the keychain; it is a pure event serializer.

use anyhow::{Result, anyhow};
use auths_keri::{
    CesrKey, DipEvent, DipEventInit, Event, IxnEvent, KeriSequence, Prefix, Said, Seal, Threshold,
    VersionString, finalize_dip_event, finalize_ixn_event,
};
use clap::Parser;

use crate::config::CliConfig;

/// Emit a raw KERI event as canonical JSON (interop / conformance surface).
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Emit a raw KERI event (dip/ixn) as JSON from deterministic inputs (interop surface)",
    after_help = "Examples:
  auths keri-emit dip --key DA... --delegator EAbc... [--next EN...]
  auths keri-emit ixn --pre EAbc... --sn 1 --prev EPrev... --seal-digest EDev..."
)]
pub struct KeriEmitCommand {
    #[command(subcommand)]
    pub kind: KeriEmitKind,
}

/// Which event to emit.
#[derive(clap::Subcommand, Debug, Clone)]
pub enum KeriEmitKind {
    /// Delegated inception (`dip`): the delegate self-signs; `di` names the delegator.
    Dip(DipArgs),
    /// Interaction (`ixn`): anchors one seal in the KEL (e.g. a delegator-side revocation).
    Ixn(IxnArgs),
}

/// Inputs for a delegated inception.
#[derive(Parser, Debug, Clone)]
pub struct DipArgs {
    /// The delegate's current signing key, CESR-encoded (qb64) — the same form keripy's `verfer.qb64`.
    #[clap(long, value_name = "CESR")]
    pub key: String,
    /// The delegator's AID prefix (becomes the dip's `di`).
    #[clap(long, value_name = "PREFIX")]
    pub delegator: String,
    /// Optional next-key commitment (pre-rotation digest). Absent → `nt=0`, `n=[]`.
    #[clap(long, value_name = "SAID")]
    pub next: Option<String>,
}

/// Inputs for an interaction event.
#[derive(Parser, Debug, Clone)]
pub struct IxnArgs {
    /// The AID prefix authoring the interaction (the delegator, for a revocation).
    #[clap(long, value_name = "PREFIX")]
    pub pre: String,
    /// Sequence number of this interaction.
    #[clap(long)]
    pub sn: u64,
    /// Prior event SAID (`p`).
    #[clap(long, value_name = "SAID")]
    pub prev: String,
    /// A digest seal `{d}` to anchor (auths's delegator-side revocation marker: the device prefix).
    #[clap(long, value_name = "SAID")]
    pub seal_digest: String,
}

impl KeriEmitCommand {
    /// Build the requested event, finalize its SAID, and print the canonical JSON.
    pub fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        let json = match &self.kind {
            KeriEmitKind::Dip(args) => emit_dip(args)?,
            KeriEmitKind::Ixn(args) => emit_ixn(args)?,
        };
        println!("{json}");
        Ok(())
    }
}

/// Build + finalize a delegated inception and return its canonical JSON.
fn emit_dip(args: &DipArgs) -> Result<String> {
    let (nt, n) = match &args.next {
        Some(next) => (
            Threshold::Simple(1),
            vec![Said::new_unchecked(next.clone())],
        ),
        None => (Threshold::Simple(0), vec![]),
    };
    let dip = finalize_dip_event(DipEvent::new(DipEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(args.key.clone())],
        nt,
        n,
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
        di: Prefix::new_unchecked(args.delegator.clone()),
    }))
    .map_err(|e| anyhow!("finalize dip: {e}"))?;
    serde_json::to_string(&Event::Dip(dip)).map_err(|e| anyhow!("serialize dip: {e}"))
}

/// Build + finalize an interaction anchoring a single digest seal; return its canonical JSON.
fn emit_ixn(args: &IxnArgs) -> Result<String> {
    let ixn = finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::new_unchecked(args.pre.clone()),
        s: KeriSequence::new(args.sn as u128),
        p: Said::new_unchecked(args.prev.clone()),
        a: vec![Seal::Digest {
            d: Said::new_unchecked(args.seal_digest.clone()),
        }],
    })
    .map_err(|e| anyhow!("finalize ixn: {e}"))?;
    serde_json::to_string(&Event::Ixn(ixn)).map_err(|e| anyhow!("serialize ixn: {e}"))
}
