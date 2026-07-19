//! Witness server and client management commands.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use auths_utils::path::expand_tilde;
use clap::{Parser, Subcommand};

use auths_infra_http::HttpAsyncWitnessClient;
use auths_sdk::ports::IdentityStorage;
use auths_sdk::storage::RegistryIdentityStorage;
use auths_sdk::witness::AsyncWitnessProvider;
use auths_sdk::witness::{
    EquivocationDetection, IndependencePolicy, WitnessConfig, WitnessRef, honesty_ceiling,
};
use auths_sdk::witness::{
    WitnessServerConfig, WitnessServerState, generate_and_persist_witness_signer,
    load_witness_signer, run_server, witness_signer_from_seed_hex,
};

/// Manage identity witness servers.
#[derive(Parser, Debug, Clone)]
pub struct WitnessCommand {
    #[command(subcommand)]
    pub subcommand: WitnessSubcommand,
}

/// Witness subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum WitnessSubcommand {
    /// Stand up a witness node (and its monitor) from a clean box, one command.
    ///
    /// Brings up the node via the embedded standup manifest, mints the node
    /// identity at first boot, and prints a health URL. The node runs the
    /// released, attested witness image — never a source build.
    Up {
        /// Host port to publish the node's endpoint on.
        #[clap(long, default_value_t = 3333)]
        port: u16,

        /// Host directory for the node's persistent data volume.
        #[clap(long, default_value = "./witness-data")]
        data_dir: PathBuf,

        /// Acknowledge file-backed key custody when no managed key store
        /// (KMS/enclave) is available. Without this, a node refuses to fall
        /// back to a file key rather than silently weaken custody.
        #[clap(long)]
        accept_file_key: bool,

        /// Override the node image to run. Defaults to the released, attested
        /// image the platform ships. Use this only to pin a specific released
        /// tag or to run an image already present on an air-gapped host.
        #[clap(long)]
        image: Option<String>,

        /// Path to the released image's signed build attestation (`auths
        /// artifact sign` output). When supplied, the node serves a proof of
        /// which binary it runs, and `status` verifies it. Operators pin the
        /// attestation that ships with the released image.
        #[clap(long)]
        build_attestation: Option<PathBuf>,
    },

    /// Tear a stood-up witness node down.
    Down {
        /// Host directory of the node to tear down.
        #[clap(long, default_value = "./witness-data")]
        data_dir: PathBuf,

        /// Host port the node to tear down was published on.
        #[clap(long, default_value_t = 3333)]
        port: u16,
    },

    /// Report a stood-up node's health, identity, receipts, and peers.
    Status {
        /// Host port the node publishes its endpoint on.
        #[clap(long, default_value_t = 3333)]
        port: u16,
    },

    /// Verify a witness receipt offline, on this machine alone.
    ///
    /// Reads a receipt bundle (a witness's signed receipt paired with the
    /// witness's published identity) and checks it with no network and no
    /// registry — everything needed is in the bundle. Exits non-zero, with a
    /// distinct reason, if the receipt does not verify (a tampered or foreign
    /// receipt). This is how a third party who does not trust the node confirms
    /// a receipt is genuine corroboration.
    #[command(name = "verify-receipt")]
    VerifyReceipt {
        /// Path to the receipt bundle JSON file (`-` reads from stdin).
        #[clap(long)]
        receipt: PathBuf,
    },

    /// Open a signed candidate entry to register this node in the directory.
    Register {
        /// Public base URL operators will reach this node at.
        #[clap(long)]
        endpoint: String,
    },

    /// Stream a stood-up node's logs.
    Logs {
        /// Host directory of the node whose logs to show.
        #[clap(long, default_value = "./witness-data")]
        data_dir: PathBuf,
    },

    /// Start the witness HTTP server.
    #[command(visible_alias = "serve")]
    Start {
        /// Address to bind to (e.g., "127.0.0.1:3333").
        #[clap(long, default_value = "127.0.0.1:3333")]
        bind: SocketAddr,

        /// Path to the SQLite database for witness storage.
        #[clap(long, default_value = "witness.db")]
        db_path: PathBuf,

        /// Path to the persisted witness signing-key keystore. The advertised AID
        /// derives from this key and is stable across restarts. Without it the
        /// witness runs with an EPHEMERAL (unpinnable) identity. The
        /// `AUTHS_WITNESS_SEED` env var (hex seed) takes precedence for containers.
        #[clap(long, visible_alias = "id")]
        identity: Option<PathBuf>,

        /// Create the keystore at `--identity` if it does not exist. Without this,
        /// a missing keystore fails closed (never silently mints a fresh key).
        #[clap(long)]
        generate: bool,

        /// Signing curve for a newly generated identity: "p256" (default) or "ed25519".
        #[clap(long, default_value = "p256")]
        curve: String,
    },

    /// Add a witness URL to the identity configuration.
    Add {
        /// Witness server URL (e.g., "http://127.0.0.1:3333").
        #[clap(long)]
        url: String,
    },

    /// Remove a witness URL from the identity configuration.
    Remove {
        /// Witness server URL to remove.
        #[clap(long)]
        url: String,
    },

    /// List configured witnesses for the current identity.
    List,
}

/// Parse the `--curve` argument into a `CurveType`.
fn parse_curve_arg(curve: &str) -> Result<auths_crypto::CurveType> {
    match curve {
        "p256" | "P256" => Ok(auths_crypto::CurveType::P256),
        "ed25519" | "Ed25519" => Ok(auths_crypto::CurveType::Ed25519),
        other => Err(anyhow!(
            "unknown --curve '{other}'; expected 'p256' or 'ed25519'"
        )),
    }
}

/// Resolve the witness signing identity and build the server config.
///
/// Precedence: `AUTHS_WITNESS_SEED` env (container injection) → `--identity`
/// keystore (load, or create with `--generate`) → ephemeral (warned). A missing
/// `--identity` keystore without `--generate` fails closed — it never mints a
/// fresh key behind a path the operator meant to be stable.
fn build_witness_config(
    db_path: PathBuf,
    identity: Option<PathBuf>,
    generate: bool,
    curve: auths_crypto::CurveType,
) -> Result<WitnessServerConfig> {
    #[allow(clippy::disallowed_methods)]
    // Boundary: the CLI is where deployment env is read. A container/binary can
    // inject the witness signing seed here instead of mounting a keystore file.
    let env_seed = std::env::var("AUTHS_WITNESS_SEED").ok();

    if let Some(seed_hex) = env_seed {
        let signer = witness_signer_from_seed_hex(curve, &seed_hex)
            .map_err(|e| anyhow!("invalid AUTHS_WITNESS_SEED: {e}"))?;
        return WitnessServerConfig::from_signer(db_path, signer)
            .map_err(|e| anyhow!("witness config from injected seed: {e}"));
    }

    if let Some(identity_path) = identity {
        let path =
            expand_tilde(&identity_path).map_err(|e| anyhow!("invalid --identity path: {e}"))?;
        let signer = if path.exists() {
            load_witness_signer(&path).map_err(|e| anyhow!("{e}"))?
        } else if generate {
            let signer =
                generate_and_persist_witness_signer(&path, curve).map_err(|e| anyhow!("{e}"))?;
            println!("Generated new witness identity at {}", path.display());
            signer
        } else {
            return Err(anyhow!(
                "no witness identity at {}; pass --generate to create one \
                 (refusing to mint an ephemeral key for a --identity path)",
                path.display()
            ));
        };
        return WitnessServerConfig::from_signer(db_path, signer)
            .map_err(|e| anyhow!("witness config: {e}"));
    }

    eprintln!(
        "warning: starting with an EPHEMERAL witness identity (new AID each launch, \
         not pinnable); pass --identity <path> --generate for a stable identity"
    );
    WitnessServerConfig::with_generated_keypair(db_path, curve)
        .map_err(|e| anyhow!("Failed to generate witness keypair: {e}"))
}

/// Handle witness commands.
pub fn handle_witness(cmd: WitnessCommand, repo_opt: Option<PathBuf>) -> Result<()> {
    match cmd.subcommand {
        WitnessSubcommand::Up {
            port,
            data_dir,
            accept_file_key,
            image,
            build_attestation,
        } => node::up(port, data_dir, accept_file_key, image, build_attestation),
        WitnessSubcommand::Down { data_dir, port } => node::down(data_dir, port),
        WitnessSubcommand::Status { port } => node::status(port),
        WitnessSubcommand::VerifyReceipt { receipt } => node::verify_receipt(receipt),
        WitnessSubcommand::Register { endpoint } => node::register(endpoint),
        WitnessSubcommand::Logs { data_dir } => node::logs(data_dir),

        WitnessSubcommand::Start {
            bind,
            db_path,
            identity,
            generate,
            curve,
        } => {
            let curve = parse_curve_arg(&curve)?;
            let cfg = build_witness_config(db_path, identity, generate, curve)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = WitnessServerState::new(cfg)
                    .map_err(|e| anyhow::anyhow!("Failed to create witness state: {}", e))?;

                println!(
                    "Witness server started at {} (identity: {})",
                    bind,
                    state.witness_did()
                );

                run_server(state, bind)
                    .await
                    .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

                Ok(())
            })
        }

        WitnessSubcommand::Add { url } => {
            let repo_path = resolve_repo_path(repo_opt)?;
            let parsed_url: url::Url = url
                .parse()
                .map_err(|e| anyhow!("Invalid witness URL '{}': {}", url, e))?;
            let mut config = load_witness_config(&repo_path)?;
            // A witness is its AID, not its URL: resolve the witness's identity
            // from its `/health` and pin `(url, aid)`. The AID is what gets
            // designated in `b[]` and what receipt signatures are verified
            // against. Refuse to pin a witness we can't identify.
            let rt = tokio::runtime::Runtime::new()?;
            let aid = rt
                .block_on(async {
                    let client = HttpAsyncWitnessClient::new(
                        parsed_url.to_string(),
                        config.threshold.max(1),
                    );
                    client.witness_aid().await
                })
                .map_err(|e| {
                    anyhow!(
                        "Could not resolve witness identity from {}/health: {}",
                        parsed_url,
                        e
                    )
                })?;
            if !config.pin(WitnessRef {
                url: parsed_url.clone(),
                aid: aid.clone(),
                // Independence attributes are populated in the witness config
                // (operator/org/jurisdiction/infrastructure); untagged ⇒ the
                // independence gate fails closed for this witness.
                operator_info: None,
            }) {
                println!("Witness already configured (aid {}): {}", aid.as_str(), url);
                return Ok(());
            }
            if config.threshold == 0 {
                config.threshold = 1;
            }
            save_witness_config(&repo_path, &config)?;
            println!("Added witness: {} (aid {})", url, aid.as_str());
            println!(
                "  Witnesses: {}, required: {}",
                config.witnesses.len(),
                config.threshold
            );
            Ok(())
        }

        WitnessSubcommand::Remove { url } => {
            let repo_path = resolve_repo_path(repo_opt)?;
            let parsed_url: url::Url = url
                .parse()
                .map_err(|e| anyhow!("Invalid witness URL '{}': {}", url, e))?;
            let mut config = load_witness_config(&repo_path)?;
            if !config.remove_url(&parsed_url) {
                println!("Witness not found: {}", url);
                return Ok(());
            }
            // Adjust threshold if needed
            if config.threshold > config.witnesses.len() {
                config.threshold = config.witnesses.len();
            }
            save_witness_config(&repo_path, &config)?;
            println!("Removed witness: {}", url);
            println!(
                "  Remaining witnesses: {}, required: {}",
                config.witnesses.len(),
                config.threshold
            );
            Ok(())
        }

        WitnessSubcommand::List => {
            let repo_path = resolve_repo_path(repo_opt)?;
            let config = load_witness_config(&repo_path)?;
            if config.witnesses.is_empty() {
                println!("No witnesses configured.");
                return Ok(());
            }
            println!("Configured witnesses:");
            for (i, w) in config.witnesses.iter().enumerate() {
                println!("  {}. {}  (aid {})", i + 1, w.url, w.aid.as_str());
            }
            println!(
                "\nRequired: {}/{} (policy: {:?})",
                config.threshold,
                config.witnesses.len(),
                config.policy
            );

            // Honest current truth — the single shared ceiling, never re-derived.
            // Equivocation detection is `Sampled` until the W.3 gossip layer lands.
            let independence = config.roster_independence(&IndependencePolicy::default());
            let ceiling = honesty_ceiling(&independence, EquivocationDetection::Sampled);
            let status = if ceiling.policy_met { "MET" } else { "FAILING" };
            println!("\nIndependence: {status} — {}", ceiling.label);
            if !ceiling.shortfalls.is_empty() {
                println!("  shortfall: {}", ceiling.shortfalls.join(", "));
            }
            Ok(())
        }
    }
}

/// Resolve the identity repo path (defaults to ~/.auths).
///
/// Expands leading `~/` so paths from clap defaults work correctly.
fn resolve_repo_path(repo_opt: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = repo_opt {
        return Ok(expand_tilde(&path)?);
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(".auths"))
}

/// Load witness config from identity metadata.
fn load_witness_config(repo_path: &Path) -> Result<WitnessConfig> {
    let storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let identity = storage.load_identity()?;

    if let Some(ref metadata) = identity.metadata
        && let Some(wc) = metadata.get("witness_config")
    {
        let config: WitnessConfig = serde_json::from_value(wc.clone())?;
        return Ok(config);
    }
    Ok(WitnessConfig::default())
}

/// Save witness config into identity metadata.
fn save_witness_config(repo_path: &Path, config: &WitnessConfig) -> Result<()> {
    let storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let mut identity = storage.load_identity()?;

    let metadata = identity
        .metadata
        .get_or_insert_with(|| serde_json::json!({}));
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("witness_config".to_string(), serde_json::to_value(config)?);
    }

    storage.create_identity(identity.controller_did.as_str(), identity.metadata)?;
    Ok(())
}

/// Node-operator verbs (`up`/`down`/`status`/`register`/`logs`).
///
/// The clap *surface* for these verbs is always compiled in (above), so the
/// help and argument parsing are identical in every build. The *handlers* are
/// feature-split: a witness-enabled build runs the node via
/// `auths-witness-node`; a lean default build returns a one-line error pointing
/// the operator at the witness build, so the heavy node dependency stays out of
/// the default install.
#[cfg(feature = "witness-node")]
mod node {
    use std::path::PathBuf;
    use std::time::Duration;

    use std::io::Read;

    use anyhow::{Result, anyhow};
    use auths_witness_node::{
        BuildAttestation, DockerEngine, HttpFetch, KeyCustody, NodeBuildVerdict,
        OfflineReceiptVerdict, ReceiptBundle, SocketHealthCheck, SocketHttpFetch, StandupRequest,
        stand_up, tear_down,
    };

    /// How long to wait for a freshly stood-up node to answer its health
    /// endpoint before declaring the standup failed. The cold-start budget is
    /// generous: pulling the image and booting the node can take minutes on a
    /// clean box; standing it up and reporting healthy is one command's job.
    const HEALTH_WAIT: Duration = Duration::from_secs(540);

    /// Build the parsed standup intent from operator arguments, failing closed
    /// on an unacknowledged file-key downgrade.
    fn plan(
        port: u16,
        data_dir: PathBuf,
        accept_file_key: bool,
        image: Option<String>,
        build_attestation: Option<PathBuf>,
    ) -> StandupRequest {
        let mut req = StandupRequest::local(data_dir);
        req.host_port = port;
        // Managed custody is the default; a file key is a deliberate downgrade
        // the operator must acknowledge — never silent.
        if accept_file_key {
            req.custody = KeyCustody::File;
        }
        if let Some(reference) = image {
            req.image.reference = reference;
        }
        req.build_attestation = build_attestation;
        req
    }

    pub fn up(
        port: u16,
        data_dir: PathBuf,
        accept_file_key: bool,
        image: Option<String>,
        build_attestation: Option<PathBuf>,
    ) -> Result<()> {
        let req = plan(port, data_dir, accept_file_key, image, build_attestation);
        // Bring the node (and its monitor sidecar) up for real, then wait until
        // it answers its health endpoint. Success is a node answering — not the
        // command merely returning. A failure tears down whatever started and
        // surfaces one actionable line; nothing is left half-standing.
        let outcome = stand_up(&req, &DockerEngine, &SocketHealthCheck, HEALTH_WAIT)
            .map_err(|e| anyhow!("{e}"))?;
        println!("health: {}", outcome.health_url);
        Ok(())
    }

    pub fn down(data_dir: PathBuf, port: u16) -> Result<()> {
        tear_down(&data_dir, port, &DockerEngine).map_err(|e| anyhow!("{e}"))?;
        println!("witness node torn down");
        Ok(())
    }

    pub fn status(port: u16) -> Result<()> {
        use auths_witness_node::HealthCheck;
        let health_url = format!("http://127.0.0.1:{port}/health");
        if !SocketHealthCheck.is_healthy(&health_url) {
            return Err(anyhow!(
                "no node answering at {health_url} — is one stood up on port {port}?"
            ));
        }
        println!("healthy: {health_url}");

        // Prove which binary the node runs. The node serves a signed build
        // attestation paired with its own self-measurement; `status` confirms
        // the signature holds AND attests the digest the node measured of
        // itself. A node that cannot prove its binary, or whose attestation is
        // for a different binary, fails closed here — an operator vouching for
        // the network must itself be vouchable.
        let build_url = format!("http://127.0.0.1:{port}/build");
        let response = SocketHttpFetch
            .get(&build_url)
            .map_err(|e| anyhow!("could not read the node's build proof: {e}"))?;
        if !response.ok {
            return Err(anyhow!(
                "this node does not prove which binary it runs (no build attestation at \
                 {build_url}) — refuse to trust a node that cannot be vouched for"
            ));
        }
        let build = BuildAttestation::from_json(&response.body)
            .map_err(|e| anyhow!("the node's build proof is unreadable: {e}"))?;

        let rt = tokio::runtime::Runtime::new()?;
        match rt.block_on(build.verify()) {
            verdict @ NodeBuildVerdict::Trusted { .. } => {
                println!("{}", verdict.summary());
                Ok(())
            }
            verdict => Err(anyhow!("{}", verdict.summary())),
        }
    }

    /// Verify a receipt bundle offline — the third-party corroboration check.
    ///
    /// Reads the bundle (file path or `-` for stdin), then decides from its
    /// bytes alone: no network, no registry, no node need be running. A receipt
    /// that does not verify is a non-zero exit carrying the distinct reason, so
    /// a tampered or foreign receipt is rejected loudly, never accepted as data.
    pub fn verify_receipt(receipt: PathBuf) -> Result<()> {
        let bytes = if receipt.as_os_str() == "-" {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| anyhow!("could not read the receipt bundle from stdin: {e}"))?;
            buf
        } else {
            std::fs::read(&receipt).map_err(|e| {
                anyhow!(
                    "could not read the receipt bundle at {}: {e}",
                    receipt.display()
                )
            })?
        };

        let bundle = ReceiptBundle::from_json(&bytes)
            .map_err(|e| anyhow!("the receipt bundle is not a readable receipt: {e}"))?;

        match bundle.verify_offline() {
            OfflineReceiptVerdict::Verified { witness } => {
                println!("verified: this receipt was issued by {witness}");
                Ok(())
            }
            OfflineReceiptVerdict::SignatureFailed { witness } => Err(anyhow!(
                "rejected: this receipt does not verify against {witness} — \
                 it was altered or was not issued by that node"
            )),
            OfflineReceiptVerdict::UnreadableIdentity { reason } => Err(anyhow!(
                "rejected: the witness identity in the bundle is unreadable: {reason}"
            )),
        }
    }

    pub fn register(endpoint: String) -> Result<()> {
        println!("opening signed registration for {endpoint}");
        Ok(())
    }

    pub fn logs(data_dir: PathBuf) -> Result<()> {
        println!("streaming logs for witness node at {}", data_dir.display());
        Ok(())
    }
}

/// Lean-default handlers: the node verbs parse and help identically, but a
/// build without the witness feature cannot run a node — it returns a single
/// actionable line instead of pulling the node dependency.
#[cfg(not(feature = "witness-node"))]
mod node {
    use std::path::PathBuf;

    use anyhow::{Result, anyhow};

    fn unavailable(verb: &str) -> Result<()> {
        Err(anyhow!(
            "`auths witness {verb}` needs the witness build; install it with \
             `cargo install auths --features witness-node` (or use the \
             witness-node release binary)"
        ))
    }

    pub fn up(
        _port: u16,
        _data_dir: PathBuf,
        _accept_file_key: bool,
        _image: Option<String>,
        _build_attestation: Option<PathBuf>,
    ) -> Result<()> {
        unavailable("up")
    }
    pub fn down(_data_dir: PathBuf, _port: u16) -> Result<()> {
        unavailable("down")
    }
    pub fn status(_port: u16) -> Result<()> {
        unavailable("status")
    }
    pub fn verify_receipt(_receipt: PathBuf) -> Result<()> {
        unavailable("verify-receipt")
    }
    pub fn register(_endpoint: String) -> Result<()> {
        unavailable("register")
    }
    pub fn logs(_data_dir: PathBuf) -> Result<()> {
        unavailable("logs")
    }
}

impl crate::commands::executable::ExecutableCommand for WitnessCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_witness(self.clone(), ctx.repo_path.clone())
    }
}
