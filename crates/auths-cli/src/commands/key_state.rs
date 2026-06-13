//! `auths key-state` — emit or ingest a KERI-conformant key-state notice (`ksn`).
//!
//! A key-state notice lets a thin client trust an identity's current key-state
//! without replaying its whole KEL. This command speaks the **KERI wire shape**
//! (`KeyStateRecord`: `{vn,i,s,p,d,f,dt,et,kt,k,nt,n,bt,b,c,ee,di}`), so a record
//! auths emits reads in keripy/keriox and a record those peers publish ingests
//! here. The crypto/wire definition lives in `auths-keri::ksn`; this is a thin
//! CLI adapter over it.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use auths_keri::{KeyStateRecord, TrustedKel, parse_kel_json};
use auths_utils::path::expand_tilde;
use clap::Parser;

use crate::config::CliConfig;

/// Emit or ingest a KERI-conformant key-state notice (`ksn`).
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Emit or ingest a KERI key-state notice (ksn) — interoperable with keripy/keriox",
    visible_alias = "ksn",
    after_help = "Examples:
  auths key-state --from-kel kel.json   # emit a KERI ksn a peer can read
  auths key-state --ingest ksn.json     # consume a keripy/keriox ksn"
)]
pub struct KeyStateCommand {
    /// Replay this KEL file and emit its current key-state as a KERI `ksn` record
    /// (the shape a keripy/keriox peer can read).
    #[clap(long, value_name = "KEL.json")]
    pub from_kel: Option<PathBuf>,

    /// Ingest a KERI `ksn` record from this file (the shape a keripy/keriox peer
    /// publishes) and print the resolved key-state.
    #[clap(long, value_name = "KSN.json", conflicts_with = "from_kel")]
    pub ingest: Option<PathBuf>,

    /// Timestamp (RFC 3339) to stamp an emitted notice with. Defaults to the
    /// epoch so emission stays deterministic; pass the real `now` to publish.
    #[clap(long, default_value = "1970-01-01T00:00:00+00:00")]
    pub dt: String,
}

impl KeyStateCommand {
    /// Run the command (emit or ingest).
    pub fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        match (&self.from_kel, &self.ingest) {
            (Some(kel_path), None) => self.emit(kel_path),
            (None, Some(ksn_path)) => self.ingest_record(ksn_path),
            (Some(_), Some(_)) => {
                unreachable!("clap conflicts_with guarantees mutual exclusion")
            }
            (None, None) => Err(anyhow!(
                "key-state needs --from-kel <KEL.json> (emit) or --ingest <KSN.json> (consume)"
            )),
        }
    }

    /// Replay a KEL file and print its current key-state as a KERI `ksn` record.
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
        let record = KeyStateRecord::from_kel(&events, &state, self.dt.clone())
            .ok_or_else(|| anyhow!("KEL is empty — no key-state to notice"))?;
        println!("{}", serde_json::to_string_pretty(&record)?);
        Ok(())
    }

    /// Ingest a KERI `ksn` record and print the resolved auths key-state.
    fn ingest_record(&self, ksn_path: &Path) -> Result<()> {
        let path = expand_tilde(ksn_path)?;
        let json = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("read ksn {}: {e}", path.display()))?;
        let record: KeyStateRecord =
            serde_json::from_str(&json).map_err(|e| anyhow!("parse KERI ksn: {e}"))?;
        let state = record.into_key_state();
        println!("{}", serde_json::to_string_pretty(&state)?);
        Ok(())
    }
}
