//! API-key auth + tenancy (plan RC-E3.3.2): `Authorization: Bearer
//! ark_<prefix>_<secret>`. Lookup by plaintext prefix, Argon2id verify of the
//! secret, revocation check, per-route scope check, per-key rate limit. The full
//! key is printed ONCE at issue; only its hash + prefix persist.

use std::collections::HashMap;
use std::sync::Mutex;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use chrono::{DateTime, Utc};
use rand::RngCore;

use super::error::ApiError;
use super::state::ApiState;

/// The authenticated account, attached to request extensions.
#[derive(Debug, Clone)]
pub struct Account {
    /// The account id.
    pub id: String,
    /// Billing mode: `retainer` / `metered` / `contract`.
    pub billing_mode: String,
    /// Bundles included in the retainer period.
    pub retainer_included_bundles: i32,
    /// The per-op price book (JSON object of cents by kind).
    pub price_book: serde_json::Value,
}

/// The authenticated key, attached to request extensions.
#[derive(Debug, Clone)]
pub struct ApiKey {
    /// The key id.
    pub id: String,
    /// The key's granted scopes.
    pub scopes: Vec<String>,
}

impl ApiKey {
    /// Require a scope, or 403.
    pub fn require(&self, scope: &str) -> Result<(), ApiError> {
        if self.scopes.iter().any(|s| s == scope) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!("key lacks scope `{scope}`")))
        }
    }
}

/// A fixed-window per-key rate limiter (requests per minute, from config).
#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<String, (i64, u32)>>,
}

impl RateLimiter {
    /// Count one request; `Err(RateLimited)` past the per-minute cap.
    pub fn check(&self, key_id: &str, per_min: u32, now: DateTime<Utc>) -> Result<(), ApiError> {
        let minute = now.timestamp() / 60;
        #[allow(clippy::expect_used)] // INVARIANT: poisoned mutex = another thread panicked
        let mut windows = self.windows.lock().expect("rate limiter lock");
        // Bound the map: drop stale windows once it grows past a working set.
        if windows.len() > 10_000 {
            windows.retain(|_, (window, _)| *window == minute);
        }
        let entry = windows.entry(key_id.to_string()).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        entry.1 += 1;
        if entry.1 > per_min {
            Err(ApiError::RateLimited)
        } else {
            Ok(())
        }
    }
}

/// Generate a fresh API key: `(full_key, prefix, argon2id_hash)`. The full key is
/// shown once; the caller persists only prefix + hash.
pub fn generate_key() -> Result<(String, String, String), ApiError> {
    let mut prefix_bytes = [0u8; 4];
    let mut secret_bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut prefix_bytes);
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let prefix = hex(&prefix_bytes);
    let secret = hex(&secret_bytes);
    let full = format!("ark_{prefix}_{secret}");
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| ApiError::Internal(format!("hash key: {e}")))?
        .to_string();
    Ok((full, prefix, hash))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Constant-time verify of a presented secret against the stored Argon2id hash.
pub fn verify_secret(secret: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(secret.as_bytes(), &parsed)
        .is_ok()
}

fn parse_bearer(header: Option<&str>) -> Result<(String, String), ApiError> {
    let raw = header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("missing bearer key".to_string()))?;
    let mut parts = raw.splitn(3, '_');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("ark"), Some(prefix), Some(secret)) if !prefix.is_empty() && !secret.is_empty() => {
            Ok((prefix.to_string(), secret.to_string()))
        }
        _ => Err(ApiError::Unauthorized("malformed api key".to_string())),
    }
}

/// The `/v1/*` auth middleware: resolve the key, verify, rate-limit, attach
/// `Account` + `ApiKey`, and stamp `last_used_at` out-of-band.
pub async fn require_api_key(
    State(state): State<ApiState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let (prefix, secret) = parse_bearer(header.as_deref())?;

    let row = sqlx::query_as::<_, (String, String, String, Vec<String>, Option<String>, String)>(
        "SELECT k.id, k.account_id, k.key_hash, k.scopes, k.revoked_at::text, a.status
         FROM api_keys k JOIN api_accounts a ON a.id = k.account_id
         WHERE k.key_prefix = $1",
    )
    .bind(&prefix)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("unknown api key".to_string()))?;
    let (key_id, account_id, key_hash, scopes, revoked_at, account_status) = row;

    if !verify_secret(&secret, &key_hash) {
        return Err(ApiError::Unauthorized("invalid api key".to_string()));
    }
    if revoked_at.is_some() {
        return Err(ApiError::Unauthorized("revoked api key".to_string()));
    }
    if account_status != "active" {
        return Err(ApiError::Unauthorized("account suspended".to_string()));
    }
    state
        .rate_limiter
        .check(&key_id, state.rate_per_min, (state.clock)())?;

    let account = sqlx::query_as::<_, (String, String, i32, String)>(
        "SELECT id, billing_mode, retainer_included_bundles, price_book::text
         FROM api_accounts WHERE id = $1",
    )
    .bind(&account_id)
    .fetch_one(&state.pool)
    .await?;
    let price_book = serde_json::from_str(&account.3).unwrap_or(serde_json::Value::Null);

    request.extensions_mut().insert(Account {
        id: account.0,
        billing_mode: account.1,
        retainer_included_bundles: account.2,
        price_book,
    });
    request.extensions_mut().insert(ApiKey {
        id: key_id.clone(),
        scopes,
    });

    // last_used_at is telemetry — never on the request's critical path.
    let pool = state.pool.clone();
    let now = (state.clock)().to_rfc3339();
    tokio::spawn(async move {
        let _ = sqlx::query("UPDATE api_keys SET last_used_at = $1::timestamptz WHERE id = $2")
            .bind(now)
            .bind(key_id)
            .execute(&pool)
            .await;
    });

    Ok(next.run(request).await)
}
