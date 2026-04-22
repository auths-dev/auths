//! Axum route handlers for the pairing daemon.
//!
//! Each handler extracts HTTP parameters and delegates to business logic
//! methods on [`DaemonState`]. Handlers only map between HTTP and domain
//! types — every error path returns a typed [`DaemonError`] and the
//! status-code mapping lives in a single `IntoResponse` impl (see
//! `src/error.rs`).
//!
//! # Auth model
//!
//! - `GET /v1/pairing/sessions/lookup` — HMAC-over-short-code via the
//!   `Authorization: Auths-HMAC …` header. The phone holds only the
//!   short code at this stage, so HMAC is the strongest authenticator
//!   available.
//! - `GET /v1/pairing/sessions/{id}` — public (status enum only).
//! - All other session-scoped endpoints — Ed25519 / P-256 signature
//!   via `Authorization: Auths-Sig …`. First successful verify binds
//!   the pubkey; all subsequent requests must use the same key.
//!
//! Legacy `X-Pairing-Token` bearer auth is removed — bearer tokens
//! leak via URL, Referer, HPACK, and logs; signatures don't.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Method},
};

use auths_core::pairing::types::{
    GetConfirmationResponse, GetSessionResponse, SubmitConfirmationRequest, SubmitResponseRequest,
    SuccessResponse,
};

use crate::DaemonState;
use crate::auth::{
    AuthError, AuthScheme, ParsedAuth, parse_authorization, pubkey_kid, verify_hmac, verify_sig,
};
use crate::error::DaemonError;
use crate::rate_limiter::{TieredRateLimiter, uniform_time_floor};
use crate::request_limits::LimitedJson;

/// Health check endpoint.
pub async fn handle_health() -> &'static str {
    "ok"
}

/// Lookup the active session via the HMAC-authenticated bootstrap
/// path. The short code is NOT in the URL; it's bound into the
/// `Authorization: Auths-HMAC` header's kid + HMAC signature.
pub async fn handle_lookup_hmac(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Extension(limiter): axum::extract::Extension<Arc<TieredRateLimiter>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<GetSessionResponse>, DaemonError> {
    // Uniform-time floor: both hit and miss paths exit at the same
    // wall time to prevent short-code enumeration via response timing.
    let start = Instant::now();
    let floor = limiter.config().uniform_miss_floor;

    let result = verify_and_lookup_hmac(&state, &headers, &body).await;
    let was_hit = result.is_ok();
    limiter.record_lookup_outcome(addr.ip(), was_hit);
    uniform_time_floor(start, floor).await;
    result.map(Json)
}

async fn verify_and_lookup_hmac(
    state: &DaemonState,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<GetSessionResponse, DaemonError> {
    if state.is_expired(tokio::time::Instant::now()) {
        return Err(DaemonError::SessionExpired);
    }
    let parsed = extract_auth(headers, AuthScheme::Hmac)?;
    let now = current_unix();
    verify_hmac(
        &parsed,
        Method::GET.as_str(),
        "/v1/pairing/sessions/lookup",
        body,
        &state.session.short_code,
        now,
    )
    .map_err(auth_to_daemon_error)?;
    state
        .nonce_cache
        .check_and_insert(&parsed.kid, &parsed.nonce)
        .map_err(auth_to_daemon_error)?;

    let status = *state.status.lock().await;
    Ok(GetSessionResponse {
        session_id: state.session.session_id.clone(),
        status,
        ttl_seconds: 300,
        token: Some(state.session.clone()),
        response: None,
    })
}

/// Public status endpoint — no auth required. Returns only the
/// non-secret session-status enum. Used by a paired phone to poll
/// readiness between steps of the pairing handshake.
pub async fn handle_get_session(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<Json<GetSessionResponse>, DaemonError> {
    state
        .get_session(&id)
        .await
        .map(Json)
        .ok_or(DaemonError::NotFound)
}

/// Submit a pairing response. This is the first authenticated
/// session-scoped request from the phone. It carries the device's
/// signing pubkey in the body AND a signature in the `Auths-Sig`
/// header; we verify the signature using the body's pubkey and bind
/// it to the session for all subsequent requests.
pub async fn handle_submit_response(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SuccessResponse>, DaemonError> {
    if state.is_expired(tokio::time::Instant::now()) {
        return Err(DaemonError::SessionExpired);
    }
    let path = format!("/v1/pairing/sessions/{id}/response");

    // Body-level validation runs first — cheap byte-level checks that
    // can reject obviously-malformed traffic without touching the
    // (mutex-locked) auth state.
    let request: SubmitResponseRequest = parse_json_body(&body)?;

    let parsed = extract_auth(&headers, AuthScheme::Sig)?;
    let pubkey = decode_device_pubkey(&request)?;

    // kid check: the header's kid must match this pubkey's kid.
    let expected_kid = pubkey_kid(&pubkey);
    if parsed.kid != expected_kid {
        return Err(DaemonError::UnauthorizedSig);
    }

    let now = current_unix();
    verify_sig(&parsed, Method::POST.as_str(), &path, &body, &pubkey, now)
        .map_err(auth_to_daemon_error)?;
    state
        .nonce_cache
        .check_and_insert(&parsed.kid, &parsed.nonce)
        .map_err(auth_to_daemon_error)?;
    state
        .pubkey_binding
        .bind_or_match(&pubkey)
        .map_err(auth_to_daemon_error)?;

    verify_subkey_chain_if_present(&request, &id, &pubkey)?;

    state
        .submit_response(&id, request)
        .await
        .map(Json)
        .map_err(|_| DaemonError::Conflict)
}

/// Verify the optional `subkey_chain` extension carried on a response
/// submission. If the daemon was compiled without `subkey-chain-v1`
/// but the request carries a chain, reject with
/// `UnsupportedSubkeyChain` — silent ignore would let the controller
/// record the session-only subkey as the stable phone identifier
/// without the chain-of-custody proof the chain was meant to provide.
fn verify_subkey_chain_if_present(
    request: &SubmitResponseRequest,
    session_id: &str,
    subkey_pubkey: &auths_keri::KeriPublicKey,
) -> Result<(), DaemonError> {
    let Some(ref chain) = request.subkey_chain else {
        return Ok(());
    };

    #[cfg(not(feature = "subkey-chain-v1"))]
    {
        let _ = (chain, session_id, subkey_pubkey);
        return Err(DaemonError::UnsupportedSubkeyChain);
    }

    #[cfg(feature = "subkey-chain-v1")]
    {
        use auths_pairing_protocol::subkey_chain::{SubkeyChainError, verify_subkey_chain};

        // Subkey chain is currently defined only for P-256 subkeys (the
        // iOS Secure Enclave is P-256 exclusively). An Ed25519-bound
        // session carrying a chain is a client bug; reject it loudly.
        let subkey_compressed: &[u8] = match subkey_pubkey {
            auths_keri::KeriPublicKey::P256(bytes) => bytes.as_slice(),
            auths_keri::KeriPublicKey::Ed25519(_) => {
                return Err(DaemonError::InvalidSubkeyChain {
                    reason: "chain only supported for P-256 subkey",
                });
            }
        };

        match verify_subkey_chain(chain, subkey_compressed, session_id) {
            Ok(_bootstrap) => {
                // TODO: record `_bootstrap` as the stable phone
                // identifier on the session for cross-session
                // revocation. Session state plumbing is outside the
                // scope of this handler; the verifier returning Ok
                // is the gate that prevents silent acceptance.
                Ok(())
            }
            Err(SubkeyChainError::SelfReferential) => Err(DaemonError::InvalidSubkeyChain {
                reason: "self-referential chain (bootstrap == subkey)",
            }),
            Err(SubkeyChainError::VerifyFailed) => Err(DaemonError::InvalidSubkeyChain {
                reason: "binding signature does not verify",
            }),
            Err(SubkeyChainError::BootstrapPubkeyLength(_))
            | Err(SubkeyChainError::SignatureLength(_))
            | Err(SubkeyChainError::SubkeyPubkeyLength(_)) => {
                Err(DaemonError::InvalidSubkeyChain {
                    reason: "chain field has wrong length",
                })
            }
            Err(SubkeyChainError::BootstrapPubkeyDecode(_))
            | Err(SubkeyChainError::SignatureDecode(_))
            | Err(SubkeyChainError::BootstrapPubkeyInvalid(_)) => {
                Err(DaemonError::InvalidSubkeyChain {
                    reason: "chain field could not be parsed",
                })
            }
        }
    }
}

/// Submit SAS confirmation. Requires `Auths-Sig` under the pubkey
/// bound by `submit_response`.
pub async fn handle_submit_confirmation(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SuccessResponse>, DaemonError> {
    if state.is_expired(tokio::time::Instant::now()) {
        return Err(DaemonError::SessionExpired);
    }
    let path = format!("/v1/pairing/sessions/{id}/confirm");
    let parsed = extract_auth(&headers, AuthScheme::Sig)?;
    let pubkey = state
        .pubkey_binding
        .current()
        .ok_or(DaemonError::UnauthorizedSig)?;
    let expected_kid = pubkey_kid(&pubkey);
    if parsed.kid != expected_kid {
        return Err(DaemonError::UnauthorizedSig);
    }
    let now = current_unix();
    verify_sig(&parsed, Method::POST.as_str(), &path, &body, &pubkey, now)
        .map_err(auth_to_daemon_error)?;
    state
        .nonce_cache
        .check_and_insert(&parsed.kid, &parsed.nonce)
        .map_err(auth_to_daemon_error)?;

    let request: SubmitConfirmationRequest = parse_json_body(&body)?;
    state
        .submit_confirmation(&id, request)
        .await
        .map(Json)
        .map_err(|_| DaemonError::Conflict)
}

/// Get confirmation state. Requires `Auths-Sig` under the bound pubkey.
pub async fn handle_get_confirmation(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<GetConfirmationResponse>, DaemonError> {
    if state.is_expired(tokio::time::Instant::now()) {
        return Err(DaemonError::SessionExpired);
    }
    let path = format!("/v1/pairing/sessions/{id}/confirmation");
    let parsed = extract_auth(&headers, AuthScheme::Sig)?;
    let pubkey = state
        .pubkey_binding
        .current()
        .ok_or(DaemonError::UnauthorizedSig)?;
    let expected_kid = pubkey_kid(&pubkey);
    if parsed.kid != expected_kid {
        return Err(DaemonError::UnauthorizedSig);
    }
    let now = current_unix();
    verify_sig(&parsed, Method::GET.as_str(), &path, &body, &pubkey, now)
        .map_err(auth_to_daemon_error)?;
    state
        .nonce_cache
        .check_and_insert(&parsed.kid, &parsed.nonce)
        .map_err(auth_to_daemon_error)?;

    state
        .get_confirmation(&id)
        .await
        .map(Json)
        .ok_or(DaemonError::NotFound)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn extract_auth(
    headers: &HeaderMap,
    expected_scheme: AuthScheme,
) -> Result<ParsedAuth, DaemonError> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(match expected_scheme {
            AuthScheme::Hmac => DaemonError::UnauthorizedHmac,
            AuthScheme::Sig => DaemonError::UnauthorizedSig,
        })?;
    let parsed = parse_authorization(header).map_err(auth_to_daemon_error)?;
    if parsed.scheme != expected_scheme {
        return Err(match expected_scheme {
            AuthScheme::Hmac => DaemonError::UnauthorizedHmac,
            AuthScheme::Sig => DaemonError::UnauthorizedSig,
        });
    }
    Ok(parsed)
}

fn auth_to_daemon_error(e: AuthError) -> DaemonError {
    match e {
        AuthError::MissingHeader
        | AuthError::MalformedHeader
        | AuthError::UnknownScheme
        | AuthError::BadKid
        | AuthError::TimestampSkew
        | AuthError::BadSignature
        | AuthError::KeyBindingMismatch => DaemonError::UnauthorizedSig,
        AuthError::ReplayedNonce => DaemonError::NonceReplay,
    }
}

fn parse_json_body<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, DaemonError> {
    // The body-limit + depth-scan middleware already ran via
    // `LimitedJson` extractor when the handler declared it. Here we
    // parse manually because the body bytes are also the signing
    // input — we need both forms.
    if body.len() > crate::request_limits::MAX_BODY_BYTES {
        return Err(DaemonError::PayloadTooLarge);
    }
    crate::request_limits::check_json_depth(body, crate::request_limits::MAX_JSON_DEPTH)?;
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| DaemonError::JsonDepthExceeded)?;
    crate::request_limits::check_string_lengths(&value)?;
    serde_json::from_value(value).map_err(|_| DaemonError::JsonDepthExceeded)
}

pub(crate) fn decode_device_pubkey(
    req: &SubmitResponseRequest,
) -> Result<auths_keri::KeriPublicKey, DaemonError> {
    // Dispatch on the sibling `curve` tag — never on byte length
    // (CLAUDE.md §4 wire-format-curve-tagging rule). Length is a
    // validation check *after* routing, so a 32-byte payload with
    // `curve: P256` surfaces as a distinct `InvalidPubkeyLength`
    // error rather than being silently reinterpreted as Ed25519.
    use auths_core::pairing::CurveTag;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let bytes = URL_SAFE_NO_PAD
        .decode(req.device_signing_pubkey.as_str())
        .map_err(|_| DaemonError::UnauthorizedSig)?;

    match req.curve {
        CurveTag::Ed25519 => {
            if bytes.len() != 32 {
                return Err(DaemonError::InvalidPubkeyLength {
                    curve: "ed25519",
                    expected: 32,
                    actual: bytes.len(),
                });
            }
            let arr: [u8; 32] = bytes.try_into().map_err(|_| DaemonError::UnauthorizedSig)?;
            Ok(auths_keri::KeriPublicKey::Ed25519(arr))
        }
        CurveTag::P256 => {
            if bytes.len() != 33 {
                return Err(DaemonError::InvalidPubkeyLength {
                    curve: "p256",
                    expected: 33,
                    actual: bytes.len(),
                });
            }
            let arr: [u8; 33] = bytes.try_into().map_err(|_| DaemonError::UnauthorizedSig)?;
            Ok(auths_keri::KeriPublicKey::P256(arr))
        }
    }
}

#[allow(clippy::disallowed_methods)] // INVARIANT: daemon is a server process — wall-clock time for auth header validation is appropriate
fn current_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// Silence dead-code warnings when feature combinations change.
#[allow(dead_code)]
fn _limited_json_reference<T>() -> Option<LimitedJson<T>> {
    None
}

#[cfg(test)]
mod decode_device_pubkey_tests {
    use super::decode_device_pubkey;
    use crate::error::DaemonError;
    use auths_core::pairing::CurveTag;
    use auths_core::pairing::types::{Base64UrlEncoded, SubmitResponseRequest};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn req(bytes: &[u8], curve: CurveTag) -> SubmitResponseRequest {
        SubmitResponseRequest {
            device_ephemeral_pubkey: Base64UrlEncoded::from_raw(URL_SAFE_NO_PAD.encode([0u8; 32])),
            device_signing_pubkey: Base64UrlEncoded::from_raw(URL_SAFE_NO_PAD.encode(bytes)),
            curve,
            device_did: "did:key:zTestTestTest".into(),
            signature: Base64UrlEncoded::from_raw(URL_SAFE_NO_PAD.encode([0u8; 64])),
            device_name: None,
            subkey_chain: None,
            new_device_signing_pubkey: None,
        }
    }

    #[test]
    fn routes_ed25519_by_curve_tag() {
        let r = req(&[0xAB; 32], CurveTag::Ed25519);
        let key = decode_device_pubkey(&r).expect("32-byte Ed25519 must accept");
        assert!(matches!(key, auths_keri::KeriPublicKey::Ed25519(_)));
    }

    #[test]
    fn routes_p256_by_curve_tag() {
        // 33-byte compressed SEC1; leading byte must be 0x02/0x03 for a
        // real point, but decode_device_pubkey does not validate curve
        // membership — that happens downstream in verify_signature.
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let r = req(&bytes, CurveTag::P256);
        let key = decode_device_pubkey(&r).expect("33-byte P-256 must accept");
        assert!(matches!(key, auths_keri::KeriPublicKey::P256(_)));
    }

    #[test]
    fn ed25519_with_33_bytes_errors_on_length_not_signature() {
        // Historical bug: length dispatch would silently reinterpret
        // this 33-byte payload as P-256. After the fix it routes as
        // Ed25519 (per `curve` tag), then fails length validation with
        // a distinct error code.
        let r = req(&[0u8; 33], CurveTag::Ed25519);
        let err = decode_device_pubkey(&r).expect_err("Ed25519 with 33 bytes must error");
        match err {
            DaemonError::InvalidPubkeyLength {
                curve,
                expected,
                actual,
            } => {
                assert_eq!(curve, "ed25519");
                assert_eq!(expected, 32);
                assert_eq!(actual, 33);
            }
            other => panic!("expected InvalidPubkeyLength, got {other:?}"),
        }
    }

    #[test]
    fn p256_with_32_bytes_errors_on_length_not_signature() {
        // Symmetric to the above: 32-byte payload with curve: P256
        // must surface as a routing/length error, not be silently
        // dispatched as Ed25519.
        let r = req(&[0u8; 32], CurveTag::P256);
        let err = decode_device_pubkey(&r).expect_err("P-256 with 32 bytes must error");
        match err {
            DaemonError::InvalidPubkeyLength {
                curve,
                expected,
                actual,
            } => {
                assert_eq!(curve, "p256");
                assert_eq!(expected, 33);
                assert_eq!(actual, 32);
            }
            other => panic!("expected InvalidPubkeyLength, got {other:?}"),
        }
    }

    #[test]
    fn p256_with_65_bytes_uncompressed_sec1_errors_on_length() {
        // iOS Secure Enclave exports 65-byte uncompressed SEC1.
        // ADR 003 specifies the wire form is 33-byte compressed;
        // submitting 65 bytes is a wire-format error routed as
        // InvalidPubkeyLength, not InvalidSignature.
        let r = req(&[0u8; 65], CurveTag::P256);
        let err = decode_device_pubkey(&r).expect_err("P-256 with 65 bytes must error");
        match err {
            DaemonError::InvalidPubkeyLength { actual, .. } => assert_eq!(actual, 65),
            other => panic!("expected InvalidPubkeyLength, got {other:?}"),
        }
    }

    #[test]
    fn absent_curve_field_defaults_to_p256() {
        // `SubmitResponseRequest.curve` uses `#[serde(default)]` which
        // resolves to `CurveTag::P256`. A request omitting `curve` must
        // route as P-256 (the workspace default), so a 32-byte payload
        // fails length validation rather than being routed as Ed25519.
        let body = serde_json::json!({
            "device_ephemeral_pubkey": URL_SAFE_NO_PAD.encode([0u8; 32]),
            "device_signing_pubkey": URL_SAFE_NO_PAD.encode([0u8; 32]),
            "device_did": "did:key:zTestTestTest",
            "signature": URL_SAFE_NO_PAD.encode([0u8; 64])
        });
        let r: SubmitResponseRequest =
            serde_json::from_value(body).expect("default-curve request must deserialize");
        assert_eq!(r.curve, CurveTag::P256);
        let err = decode_device_pubkey(&r).expect_err("32B + default curve (P256) must error");
        assert!(matches!(err, DaemonError::InvalidPubkeyLength { .. }));
    }

    #[test]
    fn malformed_base64_still_returns_unauthorized_sig() {
        // Base64-decode failure is not a routing error — it's a malformed
        // token, indistinguishable at this layer from a forged one.
        let r = SubmitResponseRequest {
            device_ephemeral_pubkey: Base64UrlEncoded::from_raw("ok".into()),
            device_signing_pubkey: Base64UrlEncoded::from_raw("!!!not-base64!!!".into()),
            curve: CurveTag::P256,
            device_did: "did:key:zTestTestTest".into(),
            signature: Base64UrlEncoded::from_raw(URL_SAFE_NO_PAD.encode([0u8; 64])),
            device_name: None,
            subkey_chain: None,
            new_device_signing_pubkey: None,
        };
        let err = decode_device_pubkey(&r).expect_err("malformed base64 must error");
        assert!(matches!(err, DaemonError::UnauthorizedSig));
    }
}
