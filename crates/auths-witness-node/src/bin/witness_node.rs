// Service binary boundary: operator diagnostics go to stderr, and the wall
// clock is read here at the edge before being injected into the pure rule —
// the sanctioned allowances every auths binary takes.
#![allow(clippy::print_stderr, clippy::disallowed_methods)]

//! The witness node binary: one artifact an operator runs.
//!
//! `serve` hosts the requested roles behind one hardened HTTP surface. A role
//! whose required adapters are not configured refuses at startup with a named
//! error — a partially-configured witness never serves cosignatures. The
//! anchor role is served in-process; the KEL-receipt and checkpoint-cosign
//! roles are still separate binaries and are refused here until they fold in,
//! rather than silently ignored.

use std::path::PathBuf;
use std::sync::Arc;

use auths_anchor::{Anchor, SeedId};
use auths_witness_node::anchor_role::{AnchorService, ServiceError, SubmitOutcome};
use auths_witness_node::registry::controller_keys_for_party;
use auths_witness_node::signer::{FileSigner, Signer as _};
use auths_witness_node::sqlite_store::SqliteAnchorStore;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use serde::Deserialize;
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
    /// Roles to serve (comma-separated). `anchor` is served in-process;
    /// `kel` and `cosign` are refused until their binaries fold in.
    #[arg(long, value_delimiter = ',', default_value = "anchor")]
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

struct AppState {
    service: AnchorService<FileSigner, SqliteAnchorStore, auths_transparency::FsTileStore>,
    registry: PathBuf,
    witness_name: String,
}

/// One anchor submission: the anchor plus the party naming the witness resolves
/// keys for. The party fields identify WHO is anchoring (a witness necessarily
/// knows its submitters); the anchor itself still carries no per-record data.
#[derive(Deserialize)]
struct SubmitBody {
    anchor: Anchor,
    party: PartyRef,
}

#[derive(Deserialize)]
struct PartyRef {
    root: String,
    agent: String,
}

fn error_body(status: StatusCode, detail: String) -> Response {
    (status, Json(serde_json::json!({ "error": detail }))).into_response()
}

async fn submit_anchor(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SubmitBody>,
) -> Response {
    let keys = match controller_keys_for_party(&state.registry, &body.party.root, &body.party.agent)
    {
        Ok(keys) => keys,
        Err(e) => return error_body(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
    };
    #[allow(clippy::disallowed_methods)] // service binary boundary: wall clock injected here
    let now = chrono::Utc::now();
    match state.service.submit(&body.anchor, &keys, now).await {
        Ok(SubmitOutcome::CoSigned {
            cosignature,
            inclusion,
            ..
        }) => Json(serde_json::json!({
            "cosignature": *cosignature,
            "inclusion": *inclusion,
        }))
        .into_response(),
        Ok(SubmitOutcome::Duplicity(proof)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "duplicity": *proof })),
        )
            .into_response(),
        Err(ServiceError::Anchor(e)) => error_body(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
        Err(ServiceError::Contended) => {
            error_body(StatusCode::CONFLICT, "contended — retry".to_string())
        }
        Err(e) => error_body(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn latest_anchor(
    State(state): State<Arc<AppState>>,
    AxumPath(seed_hex): AxumPath<String>,
) -> Response {
    let seed = match SeedId::from_hex(&seed_hex) {
        Ok(seed) => seed,
        Err(e) => return error_body(StatusCode::BAD_REQUEST, e.to_string()),
    };
    match state.service.latest(&seed) {
        Ok(Some(anchor)) => Json(serde_json::json!({ "anchor": anchor })).into_response(),
        Ok(None) => error_body(StatusCode::NOT_FOUND, "no anchor for this seed".to_string()),
        Err(e) => error_body(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    Json(serde_json::json!({
        "up": true,
        "roles": ["anchor"],
        "witness_name": state.witness_name,
    }))
    .into_response()
}

fn parse_seed(hex_seed: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(hex_seed.trim()).map_err(|e| format!("seed is not hex: {e}"))?;
    raw.try_into()
        .map_err(|_| "seed must be exactly 32 bytes of hex".to_string())
}

fn build_state(args: &ServeArgs) -> Result<Arc<AppState>, String> {
    if !args.registry.exists() {
        return Err(format!(
            "registry path {} does not exist — the anchor role fails closed without key resolution",
            args.registry.display()
        ));
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
    Ok(Arc::new(AppState {
        service: AnchorService::new(signer, store, log),
        registry: args.registry.clone(),
        witness_name: args.witness_name.clone(),
    }))
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
        Command::Serve(args) => {
            for role in &args.roles {
                match role.as_str() {
                    "anchor" => {}
                    "kel" | "cosign" => {
                        eprintln!(
                            "witness-node: role `{role}` is not served by this binary yet — \
                             run its dedicated server, or drop it from --roles"
                        );
                        return std::process::ExitCode::FAILURE;
                    }
                    other => {
                        eprintln!("witness-node: unknown role `{other}`");
                        return std::process::ExitCode::FAILURE;
                    }
                }
            }
            let state = match build_state(&args) {
                Ok(state) => state,
                Err(e) => {
                    eprintln!("witness-node: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let app = Router::new()
                .route("/v1/anchor", post(submit_anchor))
                .route("/v1/anchor/{seed}", get(latest_anchor))
                .route("/health", get(health))
                .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
                .layer(ConcurrencyLimitLayer::new(64))
                .layer(TimeoutLayer::new(std::time::Duration::from_secs(15)))
                .with_state(state);
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
