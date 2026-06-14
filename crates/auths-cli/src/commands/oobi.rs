//! `auths oobi` — KERI Out-Of-Band Introduction (discovery).
//!
//! An OOBI is how KERI controllers discover each other: a URL that says *"here
//! is my AID, and here is where to fetch its key event log and endpoints."* It
//! is the bootstrap of every live KERI exchange (witnessing, credential
//! presentation, key-state resolution) — before a peer can talk to an AID it
//! must first discover *where* that AID lives, out of band. The KEL fetched
//! through an OOBI is still verified by replay, so the URL is only a location
//! hint, never a root of trust.
//!
//! Two directions, mirroring discovery itself:
//!
//! * `auths oobi resolve` — peer → us: parse a peer's OOBI URL, fetch the bytes
//!   it points at, replay the embedded KEL into a verified key-state, and print
//!   it. `--from-file` resolves an already-fetched stream offline.
//! * `auths oobi endpoint` — us → peer: from one of our KELs and the URL we host
//!   it at, emit the OOBI URL to publish plus the `rpy` reply stream
//!   (`/loc/scheme` + `/end/role/add`) a peer fetches when it resolves us.
//!
//! The wire definitions (URL grammar, reply records, KEL ingest) live in
//! `auths-keri::oobi`; this is a thin CLI adapter. The HTTP fetch sits behind a
//! port here so the discovery logic never imports a transport.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, anyhow};
use auths_keri::{Oobi, OobiEndpoint, TrustedKel, ingest_oobi_stream, parse_kel_json};
use auths_utils::path::expand_tilde;
use clap::{Parser, Subcommand};

use crate::config::CliConfig;

/// Resolve or serve a KERI OOBI (Out-Of-Band Introduction) for discovery.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Resolve or serve a KERI OOBI — discovery, interoperable with keripy/KERIA",
    after_help = "Examples:
  auths oobi resolve --url http://peer:5642/oobi/EOoC.../controller
  auths oobi resolve --url http://peer/oobi/EOoC.../witness --from-file stream.cesr
  auths oobi endpoint --from-kel kel.json --authority 127.0.0.1:5642 --url http://127.0.0.1:5642/"
)]
pub struct OobiCommand {
    /// The OOBI direction to run.
    #[command(subcommand)]
    pub action: OobiAction,
}

/// The two OOBI directions: resolve a peer's, or serve our own.
#[derive(Subcommand, Debug, Clone)]
pub enum OobiAction {
    /// Resolve a peer's OOBI URL → fetch + replay its KEL → print the key-state.
    Resolve(ResolveArgs),
    /// Serve an AID: emit its OOBI URL + the `rpy` reply stream a peer fetches.
    Endpoint(EndpointArgs),
}

/// `auths oobi resolve` — discover a peer by resolving its OOBI URL.
#[derive(Parser, Debug, Clone)]
pub struct ResolveArgs {
    /// The peer's OOBI URL: `<scheme>://<authority>/oobi/<cid>/<role>[/<eid>]`.
    #[clap(long, value_name = "OOBI_URL")]
    pub url: String,

    /// Resolve an already-fetched stream from this file instead of an HTTP
    /// fetch — the offline/hermetic path (the bytes a live endpoint would
    /// return). The KEL is still replayed and verified.
    #[clap(long, value_name = "STREAM.json")]
    pub from_file: Option<PathBuf>,

    /// HTTP fetch timeout in seconds (live resolve only).
    #[clap(long, default_value_t = 30)]
    pub timeout: u64,
}

/// `auths oobi endpoint` — serve an AID's introduction.
#[derive(Parser, Debug, Clone)]
pub struct EndpointArgs {
    /// Replay this KEL and serve its controller as a discoverable AID.
    #[clap(long, value_name = "KEL.json")]
    pub from_kel: PathBuf,

    /// URL scheme to publish the endpoint under (`http`/`https`/`tcp`).
    #[clap(long, default_value = "http")]
    pub scheme: String,

    /// Network authority (`host[:port]`) hosting the endpoint — the part of the
    /// OOBI URL before `/oobi`.
    #[clap(long, value_name = "HOST:PORT")]
    pub authority: String,

    /// Absolute endpoint URL embedded in the `/loc/scheme` reply. Defaults to
    /// `<scheme>://<authority>/` when omitted.
    #[clap(long, value_name = "URL")]
    pub url: Option<String>,

    /// Timestamp (RFC 3339) to stamp the `rpy` replies with. Defaults to the
    /// epoch so output stays deterministic; pass the real `now` to publish.
    #[clap(long, default_value = "1970-01-01T00:00:00.000000+00:00")]
    pub dt: String,
}

impl OobiCommand {
    /// Run the command (resolve a peer or serve an endpoint).
    pub fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        match &self.action {
            OobiAction::Resolve(args) => args.run(),
            OobiAction::Endpoint(args) => args.run(),
        }
    }
}

impl ResolveArgs {
    fn run(&self) -> Result<()> {
        // Parse the URL at the boundary — an invalid OOBI never reaches the
        // fetch. `cid` is the AID the URL claims to introduce; ingest binds the
        // replayed KEL to it.
        let oobi = Oobi::parse(&self.url).map_err(|e| anyhow!("parse OOBI URL: {e}"))?;

        let stream = match &self.from_file {
            Some(path) => {
                let path = expand_tilde(path)?;
                std::fs::read_to_string(&path)
                    .map_err(|e| anyhow!("read OOBI stream {}: {e}", path.display()))?
            }
            None => fetch_oobi(&oobi.url(), self.timeout)?,
        };

        let resolution = ingest_oobi_stream(&oobi.cid, &stream)
            .map_err(|e| anyhow!("resolve OOBI {}: {e}", oobi.url()))?;

        eprintln!(
            "resolved OOBI {} → {} ({} KEL event{}, seq {})",
            oobi.url(),
            resolution.cid,
            resolution.event_count,
            if resolution.event_count == 1 { "" } else { "s" },
            resolution.state.sequence,
        );
        println!("{}", serde_json::to_string_pretty(&resolution.state)?);
        Ok(())
    }
}

impl EndpointArgs {
    fn run(&self) -> Result<()> {
        let kel_path = expand_tilde(&self.from_kel)?;
        let json = std::fs::read_to_string(&kel_path)
            .map_err(|e| anyhow!("read KEL {}: {e}", kel_path.display()))?;
        let events = parse_kel_json(&json).map_err(|e| anyhow!("parse KEL: {e}"))?;
        // A KEL file the operator hands us is a local, self-owned artifact — the
        // reviewable trust assertion that structural replay requires.
        let state = TrustedKel::from_trusted_source(&events)
            .replay()
            .map_err(|e| anyhow!("replay KEL: {e}"))?;

        let url = self
            .url
            .clone()
            .unwrap_or_else(|| format!("{}://{}/", self.scheme, self.authority));
        let endpoint = OobiEndpoint::for_controller(
            &state,
            self.scheme.clone(),
            self.authority.clone(),
            url,
            self.dt.clone(),
        )
        .map_err(|e| anyhow!("derive OOBI endpoint: {e}"))?;

        // The OOBI URL a peer resolves to discover this AID, then the `rpy`
        // reply stream that resolution returns (the KEL is served separately by
        // the host endpoint; these are the endpoint-authorization records).
        println!("{}", endpoint.oobi.url());
        println!(
            "{}",
            endpoint
                .reply_stream()
                .map_err(|e| anyhow!("serialize OOBI reply stream: {e}"))?
        );
        Ok(())
    }
}

/// Fetch the bytes an OOBI URL points at over HTTP — the transport adapter for
/// the resolve port. Blocking, since the CLI is synchronous.
fn fetch_oobi(url: &str, timeout_secs: u64) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| anyhow!("build HTTP client: {e}"))?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| anyhow!("fetch OOBI {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("fetch OOBI {url}: HTTP {}", resp.status()));
    }
    resp.text()
        .map_err(|e| anyhow!("read OOBI response body from {url}: {e}"))
}
