// This module IS the receipts-api process boundary: it reads environment
// configuration and the wall clock here and injects them down — the sanctioned
// boundary allowances every auths binary takes, hosted in the lib because the
// bin is a two-line trampoline.
#![allow(clippy::disallowed_methods)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! The `receipts-api` subcommands: `serve`, `migrate`, `accounts create`,
//! `keys issue`, `keys revoke`, `billing rollup` (plan RC-E3.3.2 / RC-E3.3.7).

use std::path::PathBuf;

use auths_evidence::{
    BudgetBasis, BundleGrant, BundleSigner, CounterpartyPolicy, RegistrySource, SignatureSuite,
    TreasuryInput,
};
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;

use super::auth::{RateLimiter, generate_key};
use super::state::{ApiState, migrate};
use crate::server::ReceiptsConfig;

/// Typed CLI errors (the bin maps them to exit codes).
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Bad usage / missing flags.
    #[error("{0}")]
    Usage(String),
    /// Environment/configuration problems.
    #[error("{0}")]
    Config(String),
    /// Database problems.
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    /// Server runtime problems.
    #[error("{0}")]
    Serve(String),
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

async fn pool() -> Result<sqlx::PgPool, CliError> {
    let url = env("DATABASE_URL").ok_or_else(|| CliError::Config("DATABASE_URL unset".into()))?;
    PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .map_err(CliError::Db)
}

/// Run one `receipts-api` invocation.
///
/// Args:
/// * `args`: the process args after the binary name.
///
/// Usage:
/// ```ignore
/// receipts_api::cli::run(&args).await?;
/// ```
pub async fn run(args: &[String]) -> Result<(), CliError> {
    match args.first().map(String::as_str) {
        Some("serve") => serve().await,
        Some("migrate") => {
            let pool = pool().await?;
            migrate(&pool).await?;
            println!("migrate: schema applied");
            Ok(())
        }
        Some("accounts") if args.get(1).map(String::as_str) == Some("create") => {
            accounts_create(&args[2..]).await
        }
        Some("keys") if args.get(1).map(String::as_str) == Some("issue") => {
            keys_issue(&args[2..]).await
        }
        Some("keys") if args.get(1).map(String::as_str) == Some("revoke") => {
            keys_revoke(&args[2..]).await
        }
        Some("billing") if args.get(1).map(String::as_str) == Some("rollup") => {
            billing_rollup(&args[2..]).await
        }
        _ => Err(CliError::Usage(
            "usage: receipts-api <serve|migrate|accounts create|keys issue|keys revoke|billing rollup>"
                .to_string(),
        )),
    }
}

fn receipts_config() -> Result<ReceiptsConfig, CliError> {
    let registry = match (
        env("AUTHS_RECEIPTS_REGISTRY"),
        env("AUTHS_RECEIPTS_REGISTRY_URL"),
    ) {
        (Some(path), _) => RegistrySource::Local(PathBuf::from(path)),
        (None, Some(url)) => RegistrySource::Remote {
            url,
            cache_dir: env("AUTHS_RECEIPTS_CACHE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".receipts-api-cache")),
        },
        (None, None) => {
            return Err(CliError::Config(
                "set AUTHS_RECEIPTS_REGISTRY or AUTHS_RECEIPTS_REGISTRY_URL".to_string(),
            ));
        }
    };
    let agent = env("AUTHS_RECEIPTS_AGENT")
        .ok_or_else(|| CliError::Config("AUTHS_RECEIPTS_AGENT unset".to_string()))?;
    let root = env("AUTHS_RECEIPTS_ROOT")
        .ok_or_else(|| CliError::Config("AUTHS_RECEIPTS_ROOT unset".to_string()))?;
    let grant = match env("AUTHS_RECEIPTS_GRANT") {
        Some(raw) => serde_json::from_str::<BundleGrant>(&raw)
            .map_err(|e| CliError::Config(format!("AUTHS_RECEIPTS_GRANT: {e}")))?,
        None => {
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
    Ok(ReceiptsConfig {
        registry,
        agent,
        root,
        log: env("AUTHS_RECEIPTS_LOG").map(PathBuf::from),
        grant,
        treasury,
        network: env("AUTHS_RECEIPTS_NETWORK").unwrap_or_else(|| "eip155:84532".to_string()),
        default_counterparty: env("AUTHS_RECEIPTS_COUNTERPARTY").unwrap_or_default(),
        claims_dir: env("RECEIPTS_API_CLAIMS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("claims")),
    })
}

async fn serve() -> Result<(), CliError> {
    let pool = pool().await?;
    migrate(&pool).await?;
    let signer = match env("RECEIPTS_API_SIGNING_SEED") {
        Some(seed) => BundleSigner::from_seed_hex(&seed, SignatureSuite::P256),
        None => BundleSigner::generate(SignatureSuite::P256),
    }
    .map_err(|e| CliError::Config(format!("signer: {e}")))?;
    let state = ApiState {
        pool,
        receipts: std::sync::Arc::new(receipts_config()?),
        signer: std::sync::Arc::new(signer),
        clock: Utc::now,
        rate_per_min: env("RECEIPTS_API_RATE_PER_MIN")
            .and_then(|v| v.parse().ok())
            .unwrap_or(120),
        rate_limiter: std::sync::Arc::new(RateLimiter::default()),
    };
    let addr = env("RECEIPTS_API_ADDR").unwrap_or_else(|| "127.0.0.1:7810".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| CliError::Serve(format!("bind {addr}: {e}")))?;
    println!("receipts-api: serving on {addr}");
    axum::serve(listener, super::router(state))
        .await
        .map_err(|e| CliError::Serve(e.to_string()))
}

async fn accounts_create(args: &[String]) -> Result<(), CliError> {
    let name = flag(args, "--name").ok_or_else(|| CliError::Usage("--name required".into()))?;
    let mode = flag(args, "--mode").unwrap_or_else(|| "metered".to_string());
    let included: i32 = flag(args, "--included")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let root = flag(args, "--root");
    let price_book = flag(args, "--price-book").unwrap_or_else(|| "{}".to_string());
    let pool = pool().await?;
    migrate(&pool).await?;
    let id = format!(
        "acct-{}",
        &super::handlers::hex_digest(name.as_bytes())[..12]
    );
    sqlx::query(
        "INSERT INTO api_accounts (id, name, auths_root, billing_mode, retainer_included_bundles,
             price_book, created_at)
         VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::timestamptz)",
    )
    .bind(&id)
    .bind(&name)
    .bind(&root)
    .bind(&mode)
    .bind(included)
    .bind(&price_book)
    .bind(Utc::now().to_rfc3339())
    .execute(&pool)
    .await?;
    println!("account created: {id} ({name}, {mode})");
    Ok(())
}

async fn keys_issue(args: &[String]) -> Result<(), CliError> {
    let account =
        flag(args, "--account").ok_or_else(|| CliError::Usage("--account required".into()))?;
    let scopes = flag(args, "--scopes")
        .unwrap_or_else(|| "bundles:write,bundles:read,verify,export,usage:read".to_string());
    let name = flag(args, "--name").unwrap_or_default();
    let pool = pool().await?;
    let (full, prefix, hash) =
        generate_key().map_err(|e| CliError::Config(format!("generate: {e}")))?;
    let scope_list: Vec<String> = scopes.split(',').map(str::to_string).collect();
    let id = format!("key-{prefix}");
    sqlx::query(
        "INSERT INTO api_keys (id, account_id, key_prefix, key_hash, name, scopes, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7::timestamptz)",
    )
    .bind(&id)
    .bind(&account)
    .bind(&prefix)
    .bind(&hash)
    .bind(&name)
    .bind(&scope_list)
    .bind(Utc::now().to_rfc3339())
    .execute(&pool)
    .await?;
    println!("key issued (SHOWN ONCE — only its hash persists):");
    println!("{full}");
    println!("id: {id}  scopes: {scopes}");
    Ok(())
}

async fn keys_revoke(args: &[String]) -> Result<(), CliError> {
    let key = flag(args, "--key").ok_or_else(|| CliError::Usage("--key required".into()))?;
    let pool = pool().await?;
    let updated = sqlx::query("UPDATE api_keys SET revoked_at = $1::timestamptz WHERE id = $2")
        .bind(Utc::now().to_rfc3339())
        .bind(&key)
        .execute(&pool)
        .await?;
    if updated.rows_affected() == 0 {
        return Err(CliError::Usage(format!("no key `{key}`")));
    }
    println!("key revoked: {key}");
    Ok(())
}

async fn billing_rollup(args: &[String]) -> Result<(), CliError> {
    let period = flag(args, "--period").unwrap_or_else(|| Utc::now().format("%Y-%m").to_string());
    let pool = pool().await?;
    let rows = sqlx::query_as::<_, (String, String, i64, i64)>(
        "SELECT account_id, kind, COUNT(*), COALESCE(SUM(unit_cost_cents), 0)
         FROM usage_events
         WHERE to_char(created_at, 'YYYY-MM') = $1
         GROUP BY account_id, kind",
    )
    .bind(&period)
    .fetch_all(&pool)
    .await?;
    let mut per_account: std::collections::HashMap<
        String,
        (serde_json::Map<String, serde_json::Value>, i64),
    > = std::collections::HashMap::new();
    for (account, kind, count, cents) in rows {
        let entry = per_account.entry(account).or_default();
        entry
            .0
            .insert(kind, serde_json::json!({ "count": count, "cents": cents }));
        entry.1 += cents;
    }
    for (account, (by_kind, total)) in &per_account {
        sqlx::query(
            "INSERT INTO usage_rollups (account_id, period, by_kind, total_cents, rolled_up_at)
             VALUES ($1,$2,$3::jsonb,$4,$5::timestamptz)
             ON CONFLICT (account_id, period)
             DO UPDATE SET by_kind = EXCLUDED.by_kind, total_cents = EXCLUDED.total_cents,
                           rolled_up_at = EXCLUDED.rolled_up_at",
        )
        .bind(account)
        .bind(&period)
        .bind(serde_json::Value::Object(by_kind.clone()).to_string())
        .bind(total)
        .bind(Utc::now().to_rfc3339())
        .execute(&pool)
        .await?;
        println!("rollup {period} {account}: {total} cents");
    }
    println!("rollup complete: {} account(s)", per_account.len());
    Ok(())
}
