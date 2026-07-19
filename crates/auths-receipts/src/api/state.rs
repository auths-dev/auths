//! Shared state for the retainer API — the Postgres pool, the evidence-core
//! configuration (the SAME `ReceiptsConfig` the MCP server mounts), the signing
//! identity, and the injected clock.

use std::sync::Arc;

use auths_evidence::BundleSigner;
use sqlx::PgPool;

use super::auth::RateLimiter;
use crate::server::{Clock, ReceiptsConfig};

/// The API's shared state. Cheap to clone; everything heavy is behind `Arc`.
#[derive(Clone)]
pub struct ApiState {
    /// The Postgres pool.
    pub pool: PgPool,
    /// The evidence-core configuration (registry, grant, anchor trail, …).
    pub receipts: Arc<ReceiptsConfig>,
    /// The bundle-signing identity (`issued_by`).
    pub signer: Arc<BundleSigner>,
    /// The injected wall clock.
    pub clock: Clock,
    /// Per-key requests-per-minute cap.
    pub rate_per_min: u32,
    /// The per-key fixed-window limiter.
    pub rate_limiter: Arc<RateLimiter>,
}

/// Run the schema DDL (idempotent `CREATE IF NOT EXISTS` migrations — the same
/// posture as auths-storage's Postgres backend).
///
/// Args:
/// * `pool`: the target database.
///
/// Usage:
/// ```ignore
/// migrate(&pool).await?;
/// ```
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    let ddl = include_str!("../../migrations/0001_receipts_api.sql");
    // Postgres DDL batches fine through a simple statement split on `;` at line
    // ends; the migration file keeps one statement per `);`-terminated block.
    for statement in split_statements(ddl) {
        sqlx::query(&statement).execute(pool).await?;
    }
    Ok(())
}

fn split_statements(sql: &str) -> Vec<String> {
    sql.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.lines().all(|l| l.trim_start().starts_with("--")))
        .map(|s| format!("{s};"))
        .collect()
}
