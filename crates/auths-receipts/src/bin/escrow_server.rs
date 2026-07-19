// CLI process boundary: environment configuration and the wall clock are read
// here and injected down — the sanctioned boundary allowances every auths binary takes.
#![allow(clippy::print_stderr, clippy::disallowed_methods)]

//! # auths-escrow-server — the T2 non-custodial escrow MCP server (stdio)
//!
//! `wrap` this bare binary to meter it on x402; it exposes `escrow_open`,
//! `escrow_milestone`, `escrow_object`, `escrow_release`, `escrow_arbitrate`.
//! Reserved mode only — no funds are ever locked or moved by this process.
//!
//! Configuration (env):
//! * `AUTHS_ESCROW_RECORDS_DIR` — the pin store (default `./escrow-records`)
//! * `AUTHS_ESCROW_ANCHOR_SEED` — 32-byte hex P-256 anchor-committer seed (generated if absent)
//! * `AUTHS_ESCROW_ANCHOR_CADENCE_SECS` — the measured anchor cadence (default 5)
//! * `AUTHS_ESCROW_SIGNING_SEED` — the tool's own signing seed (generated if absent)

use std::path::PathBuf;
use std::process::ExitCode;

use auths_evidence::{BundleSigner, SignatureSuite};
use auths_receipts::server::{EscrowConfig, EscrowServer};
use chrono::Utc;
use rmcp::ServiceExt;
use rmcp::transport::stdio;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn fresh_seed_hex() -> Result<String, String> {
    let (seed, _) =
        auths_crypto::typed_generate(auths_crypto::CurveType::P256).map_err(|e| e.to_string())?;
    let bytes = match seed {
        auths_crypto::TypedSeed::P256(bytes) | auths_crypto::TypedSeed::Ed25519(bytes) => bytes,
    };
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

fn main() -> ExitCode {
    let anchor_seed_hex = match env("AUTHS_ESCROW_ANCHOR_SEED") {
        Some(seed) => seed,
        None => match fresh_seed_hex() {
            Ok(seed) => seed,
            Err(e) => {
                eprintln!("auths-escrow-server: anchor seed: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let signer = match env("AUTHS_ESCROW_SIGNING_SEED") {
        Some(seed) => BundleSigner::from_seed_hex(&seed, SignatureSuite::P256),
        None => BundleSigner::generate(SignatureSuite::P256),
    };
    let signer = match signer {
        Ok(signer) => signer,
        Err(e) => {
            eprintln!("auths-escrow-server: signer: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cfg = EscrowConfig {
        records_dir: env("AUTHS_ESCROW_RECORDS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("escrow-records")),
        anchor_seed_hex,
        anchor_cadence_secs: env("AUTHS_ESCROW_ANCHOR_CADENCE_SECS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(5),
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("auths-escrow-server: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        let server = EscrowServer::new(cfg, signer, Utc::now)
            .serve(stdio())
            .await?;
        server.waiting().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("auths-escrow-server: {e}");
            ExitCode::FAILURE
        }
    }
}
