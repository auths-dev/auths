//! `auths did-webs` — emit a `did:webs` DID document for an AID.
//!
//! `did:webs` anchors a KERI AID into a **web-resolvable** DID document so a
//! standard DID resolver verifies the identifier without speaking KERI. The
//! document is derived by replaying the AID's KEL into its current key-state, so
//! the verification material is exactly the AID's current signing keys — the KEL
//! stays the source of truth. The document auths emits is byte-compatible with
//! the ToIP did:webs reference resolver's `didDocument`
//! (`{id, verificationMethod, service, alsoKnownAs}`). The crypto/wire definition
//! lives in `auths-keri::did_webs`; this is a thin CLI adapter over it.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use auths_keri::{DidWebsDocument, TrustedKel, parse_kel_json};
use auths_utils::path::expand_tilde;
use clap::Parser;

use crate::config::CliConfig;

/// Emit a `did:webs` DID document for an AID (KEL-anchored).
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Emit a did:webs DID document for an AID — resolvable under a standard did:webs resolver",
    after_help = "Examples:
  auths did-webs --from-kel kel.json --domain example.com
  auths did-webs --from-kel kel.json --domain 'example.com%3A3901:dids'"
)]
pub struct DidWebsCommand {
    /// Replay this KEL file and project its current key-state into a `did:webs`
    /// DID document (the shape a did:webs/DID-core resolver reads).
    #[clap(long, value_name = "KEL.json")]
    pub from_kel: PathBuf,

    /// The web domain the `did:webs` is anchored at — the host (optionally
    /// `host%3Aport` and path segments) before the AID in `did:webs:<domain>:<aid>`.
    #[clap(long, value_name = "DOMAIN")]
    pub domain: String,
}

impl DidWebsCommand {
    /// Run the command: replay the KEL and print the `did:webs` DID document.
    pub fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        self.emit(&self.from_kel)
    }

    /// Replay a KEL file and print the projected `did:webs` DID document.
    fn emit(&self, kel_path: &Path) -> Result<()> {
        let path = expand_tilde(kel_path)?;
        let json = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("read KEL {}: {e}", path.display()))?;
        let events = parse_kel_json(&json).map_err(|e| anyhow!("parse KEL: {e}"))?;
        // A KEL file the operator hands us is a local, self-owned artifact — the
        // reviewable trust assertion that structural replay requires.
        let state = TrustedKel::from_trusted_source(&events)
            .replay()
            .map_err(|e| anyhow!("replay KEL: {e}"))?;
        let doc = DidWebsDocument::from_key_state(&state, &self.domain)
            .map_err(|e| anyhow!("project key-state into a did:webs document: {e}"))?;
        println!("{}", serde_json::to_string_pretty(&doc)?);
        Ok(())
    }
}
