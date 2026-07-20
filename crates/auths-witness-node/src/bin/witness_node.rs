// Service binary boundary: operator diagnostics go to stderr, and the wall
// clock is read here at the edge before being injected into the pure rule —
// the sanctioned allowances every auths binary takes.
#![allow(clippy::print_stderr, clippy::disallowed_methods)]

//! The witness node binary: one artifact an operator runs.
//!
//! `serve` hosts the requested roles behind one hardened HTTP surface: spend
//! anchors, KERI receipt witnessing, and checkpoint cosigning — one operator
//! artifact, one identity, one durable data dir. A role whose required
//! adapters are not configured refuses at startup with a named error — a
//! partially-configured witness never serves cosignatures. Role logic lives in
//! the platform crates; this binary only composes it.

use std::path::PathBuf;
use std::sync::Arc;

use auths_witness_node::anchor_role::{AnchorService, AppState, anchor_router};
use auths_witness_node::registry::registry_ready;
use auths_witness_node::signer::{FileSigner, Signer as _};
use auths_witness_node::sqlite_store::SqliteAnchorStore;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use clap::{Parser, Subcommand};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// A witness request body is one anchor plus the party naming — a few KiB at
/// most; anything larger is hostile.
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Parser)]
#[command(name = "witness-node", about = "Auths witness node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the configured witness roles over one HTTP surface.
    Serve(ServeArgs),
    /// Probe a node's /health endpoint (container healthcheck entrypoint).
    Healthcheck(HealthcheckArgs),
    /// Fetch the parties' public registry into `--registry` (the `refs/auths/*`
    /// namespace the anchor role resolves keys from). Run before `serve`, or as
    /// an init step — a plain `git clone` does NOT bring these refs.
    SyncRegistry(SyncRegistryArgs),
}

#[derive(Parser)]
struct SyncRegistryArgs {
    /// Registry git URL to fetch the parties' public KELs from (must expose
    /// `refs/auths/*`), e.g. the aggregated first-party registry.
    #[arg(long, value_name = "URL")]
    from: String,
    /// Local registry dir to populate — the same path passed to `serve --registry`.
    #[arg(long, value_name = "DIR")]
    registry: PathBuf,
}

#[derive(Parser)]
struct HealthcheckArgs {
    /// The health URL, e.g. `http://127.0.0.1:3333/health`.
    #[arg(long, value_name = "URL")]
    url: String,
}

/// A dependency-free liveness probe: one HTTP/1.0 GET over a plain socket,
/// healthy iff the response line is 200. Runs inside the container image where
/// no external HTTP tooling exists.
fn probe_health(url: &str) -> Result<(), String> {
    use std::io::{Read, Write};
    let stripped = url
        .strip_prefix("http://")
        .ok_or_else(|| "healthcheck url must be http://".to_string())?;
    let (host_port, path) = stripped.split_once('/').unwrap_or((stripped, "health"));
    let mut stream = std::net::TcpStream::connect(host_port).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    write!(stream, "GET /{path} HTTP/1.0\r\nHost: {host_port}\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut response = String::new();
    stream
        .take(256)
        .read_to_string(&mut response)
        .map_err(|e| e.to_string())?;
    if response.starts_with("HTTP/1.0 200") || response.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        Err(format!(
            "unhealthy: {}",
            response.lines().next().unwrap_or("(no response)")
        ))
    }
}

#[derive(Parser)]
struct ServeArgs {
    /// Roles to serve (comma-separated): `anchor` (spend anchors), `kel`
    /// (KERI receipt witnessing), `cosign` (checkpoint cosigning), `registry`
    /// (serve the held `refs/auths/*` read-only over git smart-HTTP, so the node
    /// is its own resolution surface). anchor/kel/cosign share one identity seed,
    /// one data dir, and one tight hardening envelope; `registry` carries its own
    /// (larger bodies, longer timeout) for git transfers.
    #[arg(long, value_delimiter = ',', default_value = "anchor,kel,cosign")]
    roles: Vec<String>,

    /// Bind address, e.g. `0.0.0.0:3333`.
    #[arg(long, default_value = "127.0.0.1:3333")]
    bind: String,

    /// Data directory: the durable anchor store and the witness's append-only
    /// log live here. Must be a persistent volume — the store is the node's
    /// anti-equivocation memory.
    #[arg(long, value_name = "DIR")]
    data_dir: PathBuf,

    /// Local copy of the parties' public identity registry (synced by the
    /// operator) used to resolve current keys for party signatures.
    #[arg(long, value_name = "DIR")]
    registry: PathBuf,

    /// The witness's public name, carried in cosignatures and checkpoints.
    #[arg(long, value_name = "NAME")]
    witness_name: String,

    /// 64-hex-char Ed25519 seed for the witness identity (cosignatures AND
    /// log checkpoints — one pinned member key). Keep stable across restarts.
    #[arg(long, env = "WITNESS_SEED", value_name = "HEX", hide_env_values = true)]
    seed: String,
}

fn parse_seed(hex_seed: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(hex_seed.trim()).map_err(|e| format!("seed is not hex: {e}"))?;
    raw.try_into()
        .map_err(|_| "seed must be exactly 32 bytes of hex".to_string())
}

/// The KEL-receipt role: the shared hardened witness server, keyed by the
/// node's identity seed, persisting receipts under the data dir. Absorbed from
/// the standalone server binary — same state, same routes, no forked logic.
fn build_kel_router(args: &ServeArgs) -> Result<Router, String> {
    use auths_core::witness::{
        WitnessServerConfig, WitnessServerState, witness_signer_from_seed_hex,
    };
    std::fs::create_dir_all(&args.data_dir)
        .map_err(|e| format!("data dir {}: {e}", args.data_dir.display()))?;
    let signer = witness_signer_from_seed_hex(auths_crypto::CurveType::Ed25519, args.seed.trim())
        .map_err(|e| format!("witness signer: {e}"))?;
    let config = WitnessServerConfig::from_signer(args.data_dir.join("receipts.db"), signer)
        .map_err(|e| format!("witness config: {e}"))?;
    let state = WitnessServerState::new(config).map_err(|e| format!("witness state: {e}"))?;
    eprintln!("witness-node: kel role up as {}", state.witness_did());
    Ok(auths_core::witness::witness_router(state))
}

/// The checkpoint-cosign role: the shared transparency-log cosigner, signing
/// with the node's one identity, persisting its last-seen checkpoint under the
/// data dir. Absorbed from the standalone server binary.
fn build_cosign_router(args: &ServeArgs) -> Result<Router, String> {
    std::fs::create_dir_all(&args.data_dir)
        .map_err(|e| format!("data dir {}: {e}", args.data_dir.display()))?;
    let seed = parse_seed(&args.seed)?;
    let log_key = auths_transparency::LogSigningKey::from_seed(seed)
        .map_err(|e| format!("cosign key: {e}"))?;
    let pkcs8_hex = hex::encode(
        log_key
            .to_pkcs8_der()
            .map_err(|e| format!("cosign key encoding: {e}"))?,
    );
    let config = auths_witness_node::cosign_role::WitnessConfig {
        signing_key_hex: pkcs8_hex,
        witness_name: args.witness_name.clone(),
        checkpoint_path: args.data_dir.join("cosign-checkpoint.json"),
    };
    let state = auths_witness_node::cosign_role::WitnessState::new(&config)
        .map_err(|e| format!("cosign state: {e}"))?;
    Ok(auths_witness_node::cosign_role::build_router(state))
}

fn build_state(args: &ServeArgs) -> Result<Arc<AppState>, String> {
    if let Err(e) = registry_ready(&args.registry) {
        return Err(format!("{e} (registry path: {})", args.registry.display()));
    }
    std::fs::create_dir_all(&args.data_dir)
        .map_err(|e| format!("data dir {}: {e}", args.data_dir.display()))?;

    let seed = parse_seed(&args.seed)?;
    let store = SqliteAnchorStore::open(&args.data_dir.join("anchors.db"))
        .map_err(|e| format!("anchor store: {e}"))?;
    let log_key =
        auths_transparency::LogSigningKey::from_seed(seed).map_err(|e| format!("log key: {e}"))?;
    let origin = auths_transparency::LogOrigin::new(&format!("awn/{}", args.witness_name))
        .map_err(|e| format!("log origin: {e}"))?;
    let log = auths_transparency::LogWriter::new(
        auths_transparency::FsTileStore::new(args.data_dir.join("log")),
        log_key,
        origin,
    );
    let signer = FileSigner::from_seed(args.witness_name.clone(), seed);
    let member_did =
        auths_crypto::did_key_encode(auths_crypto::CurveType::Ed25519, &signer.public_key());
    eprintln!(
        "witness-node: anchor role up as `{}` (member key {member_did})",
        args.witness_name,
    );
    Ok(Arc::new(AppState::new(
        AnchorService::new(signer, store, log),
        args.registry.clone(),
        args.data_dir.join("duplicity"),
        args.witness_name.clone(),
        args.roles.clone(),
    )))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Healthcheck(args) => match probe_health(&args.url) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("witness-node: {e}");
                std::process::ExitCode::FAILURE
            }
        },
        Command::SyncRegistry(args) => {
            match auths_witness_node::sync::sync_registry(&args.from, &args.registry) {
                Ok(()) => {
                    eprintln!(
                        "witness-node: synced registry from {} → {}",
                        args.from,
                        args.registry.display()
                    );
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("witness-node: sync-registry: {e:#}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Command::Serve(args) => {
            for role in &args.roles {
                match role.as_str() {
                    "anchor" | "kel" | "cosign" | "registry" => {}
                    other => {
                        eprintln!("witness-node: unknown role `{other}`");
                        return std::process::ExitCode::FAILURE;
                    }
                }
            }
            let has = |role: &str| args.roles.iter().any(|r| r == role);

            // Roles that read (anchor: key resolution) or serve (registry) the
            // party registry need it to be an openable repo. Ensure it exists —
            // an empty registry is a valid new-witness state, and this lets the
            // first node in a network (no peer to sync from) bootstrap cleanly.
            if has("anchor") || has("registry") {
                if let Err(e) = auths_witness_node::sync::ensure_registry(&args.registry) {
                    eprintln!("witness-node: registry init: {e:#}");
                    return std::process::ExitCode::FAILURE;
                }
            }

            let mut app = Router::new();

            if has("anchor") {
                let state = match build_state(&args) {
                    Ok(state) => state,
                    Err(e) => {
                        eprintln!("witness-node: anchor role: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
                // The KEL role's shared router already serves /health; register
                // the anchor role's own only when that role is off (one owner).
                app = app.merge(anchor_router(state, !has("kel")));
            }

            if has("kel") {
                match build_kel_router(&args) {
                    Ok(router) => app = app.merge(router),
                    Err(e) => {
                        eprintln!("witness-node: kel role: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                }
            }

            if has("cosign") {
                match build_cosign_router(&args) {
                    Ok(router) => app = app.merge(router),
                    Err(e) => {
                        eprintln!("witness-node: cosign role: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                }
            }

            // The anchor/kel/cosign roles share one tight hardening envelope —
            // the posture the standalone KEL witness shipped with.
            let core = app
                .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
                .layer(ConcurrencyLimitLayer::new(
                    auths_witness_node::MAX_CONCURRENT_REQUESTS,
                ))
                .layer(TimeoutLayer::with_status_code(
                    axum::http::StatusCode::REQUEST_TIMEOUT,
                    auths_witness_node::REQUEST_TIMEOUT,
                ));

            // The registry role serves git transfers — legitimately larger
            // bodies over longer timeouts than an anchor POST — so it gets its
            // own envelope, merged after `core` is sealed so the two never mix.
            // Fail closed (I-DEPLOY-6) if its repo or the `git` binary is absent.
            let app = if has("registry") {
                if let Err(e) = registry_ready(&args.registry) {
                    eprintln!(
                        "witness-node: registry role: {e} (registry path: {})",
                        args.registry.display()
                    );
                    return std::process::ExitCode::FAILURE;
                }
                if !auths_witness_node::serve_registry::git_available().await {
                    eprintln!(
                        "witness-node: registry role: the `git` binary is required to serve \
                         refs/auths/* but was not found on PATH"
                    );
                    return std::process::ExitCode::FAILURE;
                }
                let registry = auths_witness_node::serve_registry::registry_router(&args.registry)
                    .layer(DefaultBodyLimit::max(
                        auths_witness_node::serve_registry::REGISTRY_MAX_BODY_BYTES,
                    ))
                    .layer(ConcurrencyLimitLayer::new(
                        auths_witness_node::serve_registry::REGISTRY_MAX_CONCURRENT_REQUESTS,
                    ))
                    .layer(TimeoutLayer::with_status_code(
                        axum::http::StatusCode::REQUEST_TIMEOUT,
                        auths_witness_node::serve_registry::REGISTRY_TIMEOUT,
                    ));
                core.merge(registry)
            } else {
                core
            };
            let listener = match tokio::net::TcpListener::bind(&args.bind).await {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!("witness-node: bind {}: {e}", args.bind);
                    return std::process::ExitCode::FAILURE;
                }
            };
            eprintln!("witness-node: listening on {}", args.bind);
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("witness-node: server exited: {e}");
                return std::process::ExitCode::FAILURE;
            }
            std::process::ExitCode::SUCCESS
        }
    }
}
