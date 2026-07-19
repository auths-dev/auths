// CLI process boundary: environment configuration and the wall clock are read
// here and injected down — the sanctioned boundary allowances every auths binary takes.
#![allow(clippy::print_stderr, clippy::disallowed_methods)]

//! # auths-receipts-server — the T1 receipts MCP server (stdio)
//!
//! `wrap` this bare binary to meter it on x402; it exposes `receipt_build`,
//! `receipt_verify`, `dispute_evidence`, `evidence_export`, `reversal_determine`.
//!
//! Configuration (env):
//! * `AUTHS_RECEIPTS_REGISTRY` — local registry path, or `AUTHS_RECEIPTS_REGISTRY_URL` (+ `AUTHS_RECEIPTS_CACHE_DIR`)
//! * `AUTHS_RECEIPTS_AGENT` / `AUTHS_RECEIPTS_ROOT` — the delegation
//! * `AUTHS_RECEIPTS_LOG` — spend-log override (optional)
//! * `AUTHS_RECEIPTS_GRANT` — JSON `BundleGrant` (scope/cap/currency/window/basis/policy)
//! * `AUTHS_RECEIPTS_SIGNING_SEED` — 32-byte hex P-256 seed (generated if absent)
//! * `AUTHS_RECEIPTS_TREASURY_CHECKPOINTS` / `AUTHS_RECEIPTS_TREASURY_PUBKEY` — anchor trail (optional)
//! * `AUTHS_RECEIPTS_NETWORK` — CAIP-2 id (default `eip155:84532`)
//! * `AUTHS_RECEIPTS_COUNTERPARTY` — default resolved counterparty
//! * `AUTHS_RECEIPTS_CLAIMS_DIR` — reversal claims dir (default `./claims`)

use std::path::PathBuf;
use std::process::ExitCode;

use auths_evidence::{
    BudgetBasis, BundleGrant, BundleSigner, CounterpartyPolicy, RegistrySource, SignatureSuite,
    TreasuryInput,
};
use auths_receipts::server::{ReceiptsConfig, ReceiptsServer};
use chrono::Utc;
use rmcp::ServiceExt;
use rmcp::transport::stdio;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn default_grant() -> BundleGrant {
    let now = Utc::now();
    BundleGrant {
        scope: vec!["paid.call".to_string()],
        cap: "$5".to_string(),
        currency: "USD".to_string(),
        issued_at: now - chrono::Duration::hours(1),
        expires_at: now + chrono::Duration::hours(24),
        budget_basis: BudgetBasis::CrossRail,
        counterparty_policy: CounterpartyPolicy::allow_all(),
    }
}

fn main() -> ExitCode {
    let registry = match (
        env("AUTHS_RECEIPTS_REGISTRY"),
        env("AUTHS_RECEIPTS_REGISTRY_URL"),
    ) {
        (Some(path), _) => RegistrySource::Local(PathBuf::from(path)),
        (None, Some(url)) => RegistrySource::Remote {
            url,
            cache_dir: env("AUTHS_RECEIPTS_CACHE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".auths-receipts-cache")),
        },
        (None, None) => {
            eprintln!(
                "auths-receipts-server: set AUTHS_RECEIPTS_REGISTRY or AUTHS_RECEIPTS_REGISTRY_URL"
            );
            return ExitCode::FAILURE;
        }
    };
    let (Some(agent), Some(root)) = (env("AUTHS_RECEIPTS_AGENT"), env("AUTHS_RECEIPTS_ROOT"))
    else {
        eprintln!("auths-receipts-server: set AUTHS_RECEIPTS_AGENT and AUTHS_RECEIPTS_ROOT");
        return ExitCode::FAILURE;
    };
    let grant = match env("AUTHS_RECEIPTS_GRANT") {
        Some(raw) => match serde_json::from_str::<BundleGrant>(&raw) {
            Ok(grant) => grant,
            Err(e) => {
                eprintln!("auths-receipts-server: invalid AUTHS_RECEIPTS_GRANT: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => default_grant(),
    };
    let treasury = match (
        env("AUTHS_RECEIPTS_TREASURY_CHECKPOINTS"),
        env("AUTHS_RECEIPTS_TREASURY_PUBKEY"),
    ) {
        (Some(checkpoints), Some(pubkey_hex)) => Some(TreasuryInput {
            checkpoints: PathBuf::from(checkpoints),
            pubkey_hex,
        }),
        _ => None,
    };
    let signer = match env("AUTHS_RECEIPTS_SIGNING_SEED") {
        Some(seed) => BundleSigner::from_seed_hex(&seed, SignatureSuite::P256),
        None => BundleSigner::generate(SignatureSuite::P256),
    };
    let signer = match signer {
        Ok(signer) => signer,
        Err(e) => {
            eprintln!("auths-receipts-server: signer: {e}");
            return ExitCode::FAILURE;
        }
    };

    let cfg = ReceiptsConfig {
        registry,
        agent,
        root,
        log: env("AUTHS_RECEIPTS_LOG").map(PathBuf::from),
        grant,
        treasury,
        network: env("AUTHS_RECEIPTS_NETWORK").unwrap_or_else(|| "eip155:84532".to_string()),
        default_counterparty: env("AUTHS_RECEIPTS_COUNTERPARTY").unwrap_or_default(),
        claims_dir: env("AUTHS_RECEIPTS_CLAIMS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("claims")),
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("auths-receipts-server: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        let server = ReceiptsServer::new(cfg, signer, Utc::now)
            .serve(stdio())
            .await?;
        server.waiting().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("auths-receipts-server: {e}");
            ExitCode::FAILURE
        }
    }
}
