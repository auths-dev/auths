//! The `/v1` handlers — thin translations from HTTP to the SAME core functions
//! the MCP tools call (`dispute_evidence`, `verify_offline`,
//! `determine_reversal`): zero second implementations (plan RC-E3.3).

use auths_evidence::{
    EvidenceBundle, HoldState, RegistrySource, ReversalInputs, ReversalOutcome, determine_reversal,
    verify_offline,
};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::auth::{Account, ApiKey};
use super::error::ApiError;
use super::state::ApiState;
use crate::dispute::{DisputeInputs, dispute_evidence};
use crate::exhibit::{pdf_exhibit, verification_appendix};
use crate::reversal::rail_for;

fn new_id(clock_now_nanos: i64) -> String {
    let mut bytes = [0u8; 12];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut out = format!("{clock_now_nanos:x}-");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// `POST /v1/bundles` — the retainer money call (RC-E3.3.3).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildBundleRequest {
    /// The disputed payment reference.
    pub payment_ref: String,
    /// A remote registry override (fetched through the byte cache).
    pub registry_url: Option<String>,
    /// The escrow record by value, when the deal used one.
    pub escrow_record: Option<serde_json::Value>,
    /// The pinned escrow anchor key.
    pub escrow_anchor_key_hex: Option<String>,
    /// A minimized compliance cross-link.
    pub compliance_receipt: Option<serde_json::Value>,
    /// The freshness policy for the D4 stamp.
    pub head_max_age_secs: Option<u64>,
    /// The dispute reference to index the bundle under.
    pub dispute_ref: Option<String>,
    /// The resolved counterparty.
    pub counterparty: Option<String>,
}

pub async fn build_bundle(
    State(state): State<ApiState>,
    axum::Extension(account): axum::Extension<Account>,
    axum::Extension(key): axum::Extension<ApiKey>,
    headers: HeaderMap,
    Json(request): Json<BuildBundleRequest>,
) -> Result<Response, ApiError> {
    key.require("bundles:write")?;
    let idem_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let request_hash = {
        let canon = serde_json::json!({
            "paymentRef": request.payment_ref,
            "registryUrl": request.registry_url,
            "disputeRef": request.dispute_ref,
            "counterparty": request.counterparty,
            "headMaxAgeSecs": request.head_max_age_secs,
        });
        let bytes = json_canon::to_string(&canon).unwrap_or_default();
        hex_digest(bytes.as_bytes())
    };
    if let Some(idem) = &idem_key
        && let Some(replay) =
            super::idempotency_replay(&state, &account.id, idem, &request_hash).await?
    {
        return Ok(replay);
    }

    let mut input = state.receipts.chain_input();
    if let Some(url) = &request.registry_url {
        input.registry = RegistrySource::Remote {
            url: url.clone(),
            cache_dir: std::path::PathBuf::from(".receipts-api-cache"),
        };
    }
    let counterparty = request
        .counterparty
        .clone()
        .unwrap_or_else(|| state.receipts.default_counterparty.clone());
    let bundle = dispute_evidence(
        input,
        &request.payment_ref,
        state.receipts.network.clone(),
        counterparty,
        DisputeInputs {
            escrow_record: request.escrow_record.clone(),
            escrow_anchor_key_hex: request.escrow_anchor_key_hex.clone(),
            compliance: request.compliance_receipt.clone(),
            head_max_age_secs: request.head_max_age_secs,
        },
        &state.signer,
        (state.clock)(),
    )
    .await?;

    let now = (state.clock)();
    let id = new_id(now.timestamp_nanos_opt().unwrap_or(0));
    let bundle_json =
        serde_json::to_string(&bundle).map_err(|e| ApiError::Internal(e.to_string()))?;
    let log_hash = hex_digest(bundle_json.as_bytes());
    sqlx::query(
        "INSERT INTO bundles (id, account_id, dispute_ref, subject_root, subject_agent,
             settlement_tx, call_index, log_hash, call_verdict, log_verdict, anchor_tier,
             bundle_json, size_bytes, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14::timestamptz)",
    )
    .bind(&id)
    .bind(&account.id)
    .bind(&request.dispute_ref)
    .bind(&bundle.subject.root)
    .bind(&bundle.subject.agent)
    .bind(&bundle.settlement.tx)
    .bind(bundle.call.index as i32)
    .bind(&log_hash)
    .bind(bundle.verdicts.call.code())
    .bind(bundle.verdicts.log.code())
    .bind(format!("{:?}", bundle.verdicts.as_of.tier).to_lowercase())
    .bind(&bundle_json)
    .bind(bundle_json.len() as i32)
    .bind(now.to_rfc3339())
    .execute(&state.pool)
    .await?;
    super::record_usage(
        &state,
        &account,
        &key,
        "dispute_evidence",
        Some(&id),
        idem_key.as_deref(),
    )
    .await?;

    let body = serde_json::json!({
        "id": id,
        "disputeRef": request.dispute_ref,
        "verdicts": bundle.verdicts,
        "asOf": bundle.verdicts.as_of,
        "createdAt": now.to_rfc3339(),
        "bundle": bundle,
    });
    if let Some(idem) = &idem_key {
        super::idempotency_record(&state, &account.id, idem, &request_hash, 201, &body).await?;
    }
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// `POST /v1/verify` — offline verification over HTTP (RC-E3.3.4). Stateless;
/// the bundle need not be one we stored. The response echoes the S4 binding
/// fields; the CALLER asserts they match the transaction it is adjudicating.
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The bundle to re-check.
    pub bundle: EvidenceBundle,
}

pub async fn verify_bundle(
    State(state): State<ApiState>,
    axum::Extension(account): axum::Extension<Account>,
    axum::Extension(key): axum::Extension<ApiKey>,
    Json(request): Json<VerifyRequest>,
) -> Result<Response, ApiError> {
    key.require("verify")?;
    let verdict = verify_offline(&request.bundle).await;
    super::record_usage(&state, &account, &key, "verify", None, None).await?;
    Ok(Json(verdict).into_response())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    dispute_ref: Option<String>,
    cursor: Option<i64>,
    limit: Option<i64>,
}

/// `GET /v1/bundles` — the `disputeRef` index (RC-E3.3.5), newest first.
pub async fn list_bundles(
    State(state): State<ApiState>,
    axum::Extension(account): axum::Extension<Account>,
    axum::Extension(key): axum::Extension<ApiKey>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    key.require("bundles:read")?;
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.cursor.unwrap_or(0).max(0);
    let rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            String,
            String,
            String,
            i32,
            String,
            String,
            String,
        ),
    >(
        "SELECT id, dispute_ref, subject_root, subject_agent, settlement_tx, call_index,
                call_verdict, log_verdict, created_at::text
         FROM bundles
         WHERE account_id = $1 AND ($2::text IS NULL OR dispute_ref = $2)
         ORDER BY created_at DESC
         LIMIT $3 OFFSET $4",
    )
    .bind(&account.id)
    .bind(&query.dispute_ref)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;
    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.0, "disputeRef": r.1, "subjectRoot": r.2, "subjectAgent": r.3,
                "settlementTx": r.4, "callIndex": r.5, "callVerdict": r.6,
                "logVerdict": r.7, "createdAt": r.8,
            })
        })
        .collect();
    let next = if items.len() as i64 == limit {
        Some(offset + limit)
    } else {
        None
    };
    Ok(Json(serde_json::json!({ "items": items, "nextCursor": next })).into_response())
}

/// `GET /v1/bundles/{id}` — one stored bundle, tenant-scoped (cross-tenant = 404).
pub async fn get_bundle(
    State(state): State<ApiState>,
    axum::Extension(account): axum::Extension<Account>,
    axum::Extension(key): axum::Extension<ApiKey>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    key.require("bundles:read")?;
    let row = sqlx::query_as::<_, (String, Option<String>, String, String)>(
        "SELECT bundle_json::text, dispute_ref, created_at::text, log_hash
         FROM bundles WHERE account_id = $1 AND id = $2",
    )
    .bind(&account.id)
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let bundle: serde_json::Value =
        serde_json::from_str(&row.0).map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "id": id, "disputeRef": row.1, "createdAt": row.2, "logHash": row.3, "bundle": bundle,
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    format: Option<String>,
}

/// `GET /v1/bundles/{id}/export?format=pdf` — the exhibit hook (RC-E3.4). PSP
/// field mappings are decide-gated; `pdf` ships.
pub async fn export_bundle(
    State(state): State<ApiState>,
    axum::Extension(account): axum::Extension<Account>,
    axum::Extension(key): axum::Extension<ApiKey>,
    Path(id): Path<String>,
    Query(query): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    key.require("export")?;
    let format = query.format.as_deref().unwrap_or("pdf");
    if let Some(psp) = format.strip_prefix("psp:") {
        return Err(ApiError::Unprocessable(format!(
            "psp mapping `{psp}` is decide-gated (plan RC-E3.4) — needs a design partner who files real disputes"
        )));
    }
    if format != "pdf" {
        return Err(ApiError::BadRequest(format!("unknown format `{format}`")));
    }
    let row = sqlx::query_as::<_, (String,)>(
        "SELECT bundle_json::text FROM bundles WHERE account_id = $1 AND id = $2",
    )
    .bind(&account.id)
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let bundle: EvidenceBundle =
        serde_json::from_str(&row.0).map_err(|e| ApiError::Internal(e.to_string()))?;
    let mut lines: Vec<String> = bundle
        .rendered
        .as_deref()
        .unwrap_or("(bundle carries no render)")
        .lines()
        .map(str::to_string)
        .collect();
    lines.extend(verification_appendix());
    let title = format!(
        "AUTHS EVIDENCE EXHIBIT — tx {} (call #{})",
        bundle.settlement.tx, bundle.call.index
    );
    let pdf = pdf_exhibit(&title, &lines);
    super::record_usage(&state, &account, &key, "export", Some(&id), None).await?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pdf")],
        pdf,
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub struct UsageQuery {
    from: Option<String>,
    to: Option<String>,
}

/// `GET /v1/usage` — used-vs-included + overage for retainer accounts (RC-E3.3.7).
pub async fn get_usage(
    State(state): State<ApiState>,
    axum::Extension(account): axum::Extension<Account>,
    axum::Extension(key): axum::Extension<ApiKey>,
    Query(query): Query<UsageQuery>,
) -> Result<Response, ApiError> {
    key.require("usage:read")?;
    let rows = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT kind, COUNT(*), COALESCE(SUM(unit_cost_cents), 0)
         FROM usage_events
         WHERE account_id = $1
           AND ($2::text IS NULL OR created_at >= $2::timestamptz)
           AND ($3::text IS NULL OR created_at <= $3::timestamptz)
         GROUP BY kind",
    )
    .bind(&account.id)
    .bind(&query.from)
    .bind(&query.to)
    .fetch_all(&state.pool)
    .await?;
    let mut by_kind = serde_json::Map::new();
    let mut used_bundles: i64 = 0;
    let mut total_cents: i64 = 0;
    for (kind, count, cents) in rows {
        if kind == "dispute_evidence" || kind == "bundle_build" {
            used_bundles += count;
        }
        total_cents += cents;
        by_kind.insert(kind, serde_json::json!({ "count": count, "cents": cents }));
    }
    let body = if account.billing_mode == "retainer" {
        let included = account.retainer_included_bundles as i64;
        let overage = (used_bundles - included).max(0);
        let overage_cents = overage * super::price_of(&account, "overage").unwrap_or(0);
        serde_json::json!({
            "byKind": by_kind,
            "includedBundles": included,
            "usedBundles": used_bundles,
            "overageBundles": overage,
            "projectedOverageCents": overage_cents,
        })
    } else {
        serde_json::json!({ "byKind": by_kind, "totalCents": total_cents })
    };
    Ok(Json(body).into_response())
}

/// `GET /v1/account` — the plan + this period's shape.
pub async fn get_account(
    State(state): State<ApiState>,
    axum::Extension(account): axum::Extension<Account>,
) -> Result<Response, ApiError> {
    let row = sqlx::query_as::<_, (String, Option<String>, String, i32, i32, String)>(
        "SELECT name, auths_root, billing_mode, retainer_included_bundles, overage_cents, created_at::text
         FROM api_accounts WHERE id = $1",
    )
    .bind(&account.id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(serde_json::json!({
        "id": account.id, "name": row.0, "auths_root": row.1, "billingMode": row.2,
        "retainerIncludedBundles": row.3, "overageCents": row.4, "createdAt": row.5,
        "priceBook": account.price_book,
    }))
    .into_response())
}

/// `POST /v1/reversals` — the human chargeback desk's reversal surface
/// (RC-E3.5.6), over the same core as the MCP `reversal_determine`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReversalRequest {
    /// A stored bundle id, or…
    pub bundle_id: Option<String>,
    /// …the bundle by value.
    pub bundle: Option<EvidenceBundle>,
    pub dispute_ref: Option<String>,
    pub payee_org: Option<String>,
    pub payee_settlement_account: Option<String>,
    /// `escrow-held` / `stripe-auth` / `x402-reversible` / `none`.
    pub hold: Option<String>,
}

pub async fn post_reversal(
    State(state): State<ApiState>,
    axum::Extension(account): axum::Extension<Account>,
    axum::Extension(key): axum::Extension<ApiKey>,
    Json(request): Json<ReversalRequest>,
) -> Result<Response, ApiError> {
    key.require("bundles:write")?;
    let bundle = match (&request.bundle, &request.bundle_id) {
        (Some(bundle), _) => bundle.clone(),
        (None, Some(id)) => {
            let row = sqlx::query_as::<_, (String,)>(
                "SELECT bundle_json::text FROM bundles WHERE account_id = $1 AND id = $2",
            )
            .bind(&account.id)
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
            serde_json::from_str(&row.0).map_err(|e| ApiError::Internal(e.to_string()))?
        }
        (None, None) => {
            return Err(ApiError::BadRequest(
                "bundle or bundleId required".to_string(),
            ));
        }
    };
    let hold = match request.hold.as_deref() {
        Some("escrow-held") => HoldState::EscrowHeld,
        Some("stripe-auth") => HoldState::StripeAuthUncaptured,
        Some("x402-reversible") => HoldState::X402Reversible,
        Some("none") | None => HoldState::None,
        Some(other) => return Err(ApiError::BadRequest(format!("unknown hold `{other}`"))),
    };
    let outcome = determine_reversal(
        &bundle,
        ReversalInputs {
            dispute_ref: request.dispute_ref.clone(),
            payee_org: request.payee_org.clone(),
            payee_settlement_account: request.payee_settlement_account.clone(),
            hold,
        },
        &state.signer,
    )
    .await?;
    super::record_usage(&state, &account, &key, "reversal", None, None).await?;
    match outcome {
        ReversalOutcome::WithinRemit => Ok(Json(serde_json::json!({
            "determined": false, "route": "subjective",
            "why": "within remit — no auto-reversal; escrow/arbitration decides",
        }))
        .into_response()),
        ReversalOutcome::Ungrounded(why) => Ok(Json(serde_json::json!({
            "determined": false, "route": "none", "why": why,
        }))
        .into_response()),
        ReversalOutcome::Determined(det) => {
            let rail = rail_for(&det, None, state.receipts.claims_dir.clone());
            let executed = rail
                .execute(&det)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(Json(serde_json::json!({
                "determined": true,
                "determination": det,
                "rail": { "adapter": rail.name(), "result": executed },
            }))
            .into_response())
        }
    }
}

/// `POST /v1/bundles` is also reachable as a cheap receipt build; the exhibit
/// content type helper keeps clippy's type inference simple.
pub fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode a stored idempotent response body back into a `Response`.
pub fn replay_response(status: i32, body: &str) -> Response {
    let status = StatusCode::from_u16(status as u16).unwrap_or(StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    (status, Json(value)).into_response()
}

/// The exhibit base64 helper (kept for MCP parity in tests).
pub fn pdf_base64(pdf: &[u8]) -> String {
    BASE64.encode(pdf)
}
