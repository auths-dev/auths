//! The enterprise retainer HTTP surface (plan RC-E3.3): a thin,
//! stateless-per-request axum service over the SAME `auths-evidence` core the MCP
//! tools call. It adds only what HTTP buyers need — API-key auth, tenant
//! isolation, the `disputeRef` index, usage recording, idempotency — and holds no
//! funds, ever: usage is recorded and exposed; charging reconciles through the
//! market's billing rail.

pub mod auth;
pub mod cli;
pub mod error;
pub mod handlers;
pub mod state;

use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use auth::{Account, ApiKey};
use error::ApiError;
use state::ApiState;

/// Assemble the router: authenticated `/v1/*` + unauthenticated ops routes.
///
/// Args:
/// * `state`: the shared API state.
///
/// Usage:
/// ```ignore
/// axum::serve(listener, router(state)).await?;
/// ```
pub fn router(state: ApiState) -> Router {
    let v1 = Router::new()
        .route(
            "/v1/bundles",
            post(handlers::build_bundle).get(handlers::list_bundles),
        )
        .route("/v1/bundles/{id}", get(handlers::get_bundle))
        .route("/v1/bundles/{id}/export", get(handlers::export_bundle))
        .route("/v1/verify", post(handlers::verify_bundle))
        .route("/v1/reversals", post(handlers::post_reversal))
        .route("/v1/usage", get(handlers::get_usage))
        .route("/v1/account", get(handlers::get_account))
        .route_layer(from_fn_with_state(state.clone(), auth::require_api_key))
        .with_state(state.clone());
    Router::new()
        .merge(v1)
        .merge(ops_routes())
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
}

fn ops_routes() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        .route("/openapi.json", get(openapi))
}

async fn openapi() -> Response {
    // A deliberately minimal, hand-maintained document naming every route and its
    // auth; full schema generation is deferred with the metrics endpoint.
    Json(serde_json::json!({
        "openapi": "3.0.0",
        "info": { "title": "auths receipts-api", "version": "1.0.0" },
        "paths": {
            "/v1/bundles": { "post": { "summary": "Build a dispute-evidence bundle (Idempotency-Key honored)" },
                              "get": { "summary": "List bundles, ?disputeRef= index, cursor-paginated" } },
            "/v1/bundles/{id}": { "get": { "summary": "One stored bundle (tenant-scoped)" } },
            "/v1/bundles/{id}/export": { "get": { "summary": "Exhibit export (?format=pdf)" } },
            "/v1/verify": { "post": { "summary": "Offline verification; echoes S4 binding fields" } },
            "/v1/reversals": { "post": { "summary": "Reversal determination (reversal/v1)" } },
            "/v1/usage": { "get": { "summary": "Usage by kind; retainer used-vs-included" } },
            "/v1/account": { "get": { "summary": "The account + plan" } }
        },
        "components": { "securitySchemes": { "apiKey": {
            "type": "http", "scheme": "bearer",
            "description": "Authorization: Bearer ark_<prefix>_<secret>"
        } } }
    }))
    .into_response()
}

/// The per-op price from the account's price book (cents).
pub(crate) fn price_of(account: &Account, kind: &str) -> Option<i64> {
    account.price_book.get(kind).and_then(|v| v.as_i64())
}

/// Record one billable usage event, priced from the account's price book —
/// exactly once per operation (RC-E3.3.7).
pub(crate) async fn record_usage(
    state: &ApiState,
    account: &Account,
    key: &ApiKey,
    kind: &str,
    bundle_id: Option<&str>,
    idempotency_key: Option<&str>,
) -> Result<(), ApiError> {
    let now = (state.clock)();
    let id = format!(
        "ue-{}",
        handlers::hex_digest(
            format!(
                "{}:{}:{}:{}",
                account.id,
                kind,
                now.timestamp_nanos_opt().unwrap_or(0),
                bundle_id.unwrap_or("")
            )
            .as_bytes()
        )
    );
    let unit_cost = price_of(account, kind).unwrap_or(0);
    sqlx::query(
        "INSERT INTO usage_events (id, account_id, api_key_id, kind, unit_cost_cents, bundle_id,
             idempotency_key, metadata, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'{}'::jsonb,$8::timestamptz)",
    )
    .bind(&id)
    .bind(&account.id)
    .bind(&key.id)
    .bind(kind)
    .bind(unit_cost as i32)
    .bind(bundle_id)
    .bind(idempotency_key)
    .bind(now.to_rfc3339())
    .execute(&state.pool)
    .await?;
    Ok(())
}

/// Idempotency replay (RC-E3.3.6): same key + same body → the stored response;
/// same key + different body → 409.
pub(crate) async fn idempotency_replay(
    state: &ApiState,
    account_id: &str,
    key: &str,
    request_hash: &str,
) -> Result<Option<Response>, ApiError> {
    let row = sqlx::query_as::<_, (String, String, i32)>(
        "SELECT request_hash, response_json::text, status_code
         FROM idempotency_keys WHERE account_id = $1 AND key = $2",
    )
    .bind(account_id)
    .bind(key)
    .fetch_optional(&state.pool)
    .await?;
    match row {
        None => Ok(None),
        Some((stored_hash, body, status)) if stored_hash == request_hash => {
            Ok(Some(handlers::replay_response(status, &body)))
        }
        Some(_) => Err(ApiError::IdempotencyConflict(format!(
            "idempotency key `{key}` was used with a different request body"
        ))),
    }
}

/// Store the response for later replays.
pub(crate) async fn idempotency_record(
    state: &ApiState,
    account_id: &str,
    key: &str,
    request_hash: &str,
    status: i32,
    body: &serde_json::Value,
) -> Result<(), ApiError> {
    let body = serde_json::to_string(body).map_err(|e| ApiError::Internal(e.to_string()))?;
    sqlx::query(
        "INSERT INTO idempotency_keys (account_id, key, request_hash, response_json, status_code, created_at)
         VALUES ($1,$2,$3,$4::jsonb,$5,$6::timestamptz)
         ON CONFLICT (account_id, key) DO NOTHING",
    )
    .bind(account_id)
    .bind(key)
    .bind(request_hash)
    .bind(&body)
    .bind(status)
    .bind((state.clock)().to_rfc3339())
    .execute(&state.pool)
    .await?;
    Ok(())
}
