//! `auths-witness` — slim, hardened KERI rct-witness server binary.
//!
//! Thin presentation over the shared `auths-core` witness library: parse args,
//! load the W.1.1 stable identity, build the hardened app, serve. All witness
//! logic is `auths-core`.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use auths_core::witness::{
    WitnessServerConfig, WitnessServerState, generate_and_persist_witness_signer,
    load_witness_signer, witness_signer_from_seed_hex,
};
use auths_crypto::CurveType;
use auths_witness::hardened_witness_app;
use clap::Parser;

/// Slim, hardened KERI rct-witness server.
#[derive(Parser, Debug)]
#[command(name = "auths-witness", version, about)]
struct Args {
    /// Address to bind. TLS terminates at a reverse proxy (see the deployment kit).
    #[arg(long, default_value = "127.0.0.1:3333")]
    bind: SocketAddr,

    /// Path to the persisted, curve-tagged signing keystore. The advertised AID
    /// derives from this key and is stable across restarts.
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Create the keystore at `--identity` if it does not exist. Without this, a
    /// missing keystore fails closed (never mints a fresh, unpinnable key).
    #[arg(long)]
    generate: bool,

    /// Signing curve for a newly generated identity: "p256" (default) or "ed25519".
    #[arg(long, default_value = "p256")]
    curve: String,

    /// Path to the SQLite receipts database.
    #[arg(long, default_value = "receipts.db")]
    persist: PathBuf,
}

fn parse_curve(curve: &str) -> Result<CurveType> {
    match curve {
        "p256" | "P256" => Ok(CurveType::P256),
        "ed25519" | "Ed25519" => Ok(CurveType::Ed25519),
        other => Err(anyhow!(
            "unknown --curve '{other}'; expected 'p256' or 'ed25519'"
        )),
    }
}

/// Resolve the witness signing key, failing closed.
///
/// Precedence: `AUTHS_WITNESS_SEED` env (container injection) → `--identity`
/// keystore (load, or create with `--generate`). A deployed witness must have a
/// stable identity, so neither source present is an error.
fn resolve_signer(args: &Args, curve: CurveType) -> Result<auths_crypto::TypedSignerKey> {
    #[allow(clippy::disallowed_methods)]
    // Boundary: the binary reads its own deployment env. A container injects the
    // witness signing seed here instead of mounting a keystore file.
    let env_seed = std::env::var("AUTHS_WITNESS_SEED").ok();

    if let Some(seed_hex) = env_seed {
        return witness_signer_from_seed_hex(curve, &seed_hex)
            .map_err(|e| anyhow!("invalid AUTHS_WITNESS_SEED: {e}"));
    }

    let Some(path) = args.identity.as_deref() else {
        return Err(anyhow!(
            "no witness identity: pass --identity <path> (with --generate to create) \
             or set AUTHS_WITNESS_SEED; a deployed witness needs a stable, pinnable identity"
        ));
    };

    if path.exists() {
        load_witness_signer(path).map_err(|e| anyhow!("{e}"))
    } else if args.generate {
        let signer =
            generate_and_persist_witness_signer(path, curve).map_err(|e| anyhow!("{e}"))?;
        tracing::info!("generated new witness identity at {}", path.display());
        Ok(signer)
    } else {
        Err(anyhow!(
            "no witness identity at {}; pass --generate to create one",
            path.display()
        ))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let curve = parse_curve(&args.curve)?;
    let signer = resolve_signer(&args, curve)?;

    let config = WitnessServerConfig::from_signer(args.persist.clone(), signer)
        .map_err(|e| anyhow!("witness config: {e}"))?;
    let state = WitnessServerState::new(config).map_err(|e| anyhow!("witness state: {e}"))?;

    tracing::info!(
        bind = %args.bind,
        identity = %state.witness_did(),
        "auths-witness starting"
    );

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("failed to bind {}", args.bind))?;
    let app = hardened_witness_app(state);
    axum::serve(listener, app)
        .await
        .context("witness server error")?;
    Ok(())
}
