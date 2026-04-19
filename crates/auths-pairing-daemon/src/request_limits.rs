//! Request-size + JSON-depth + string-length caps.
//!
//! # Why this layer exists
//!
//! Axum's default `Json` extractor caps at 2 MiB and does no nested-
//! depth check. A caller with a 1 MiB body of `[[[[…]]]]` triggers
//! `serde_json`'s default 128-frame recursion limit (stack overflow
//! on some platforms) or just wastes a lot of CPU on a pointless
//! parse. This module plants three caps that run BEFORE any handler
//! dispatch:
//!
//! 1. A global [`tower_http::limit::RequestBodyLimitLayer`] at 64 KiB —
//!    enforced on the router at the byte level, rejects with 413
//!    PayloadTooLarge.
//! 2. A byte-level `{`/`[` depth scan that runs before JSON parse and
//!    caps nesting at 16 → 400 JsonDepthExceeded.
//! 3. A post-parse string-length walk that rejects any string field
//!    longer than 4096 bytes → 413 PayloadTooLarge.
//!
//! # `LimitedJson<T>` extractor
//!
//! Handlers use [`LimitedJson<T>`] instead of `axum::Json<T>`. The
//! extractor applies the depth check before
//! parse and the string-length walk after parse-to-[`serde_json::Value`].
//! The final `serde_json::from_value(…)` is strictly typed, so any
//! remaining malformation surfaces as JSON parse errors (→
//! [`DaemonError::JsonDepthExceeded`]) rather than a 500.
//!
//! # Why not `serde_json`'s built-in max?
//!
//! `serde_json::Deserializer` has a fixed 128-frame recursion guard
//! that is NOT user-configurable. It fail-stops stack overflow but
//! doesn't let us pick a tighter bound. We enforce 16 separately
//! because that's strictly less than 128, aligns with the typical
//! "no human-readable payload nests that deep" heuristic, and is
//! enforceable in a single pass before allocating anything.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{StatusCode, header};

use crate::error::DaemonError;

/// Global request-body size cap (bytes). 64 KiB — far above any
/// legitimate pairing request (largest is ~1 KiB) and far below any
/// DoS vector worth caring about.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Maximum JSON nesting depth. `{` and `[` each add one level;
/// strings are ignored. The typed pairing payloads nest at most two
/// levels; 16 is a comfortable ceiling.
pub const MAX_JSON_DEPTH: u8 = 16;

/// Maximum allowed length of any JSON string value (bytes, post-parse
/// — so Unicode escapes expand to their UTF-8 form before the check).
/// 4 KiB fits every legitimate field (DIDs, base64url pubkeys,
/// capabilities) with room to spare.
pub const MAX_JSON_STRING_BYTES: usize = 4096;

/// Byte-level JSON depth scanner.
///
/// Counts `{` and `[` encountered outside of string literals, rejects
/// when depth would exceed `max_depth`. Does not validate JSON beyond
/// depth — malformation surfaces at the `serde_json` parse step that
/// follows.
pub fn check_json_depth(bytes: &[u8], max_depth: u8) -> Result<(), DaemonError> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape = false;
    for &b in bytes {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth as usize {
                    return Err(DaemonError::JsonDepthExceeded);
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Post-parse recursive walk of a [`serde_json::Value`] rejecting any
/// string field whose UTF-8 byte length exceeds [`MAX_JSON_STRING_BYTES`].
pub fn check_string_lengths(v: &serde_json::Value) -> Result<(), DaemonError> {
    match v {
        serde_json::Value::String(s) => {
            if s.len() > MAX_JSON_STRING_BYTES {
                return Err(DaemonError::PayloadTooLarge);
            }
        }
        serde_json::Value::Array(arr) => {
            for x in arr {
                check_string_lengths(x)?;
            }
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if key.len() > MAX_JSON_STRING_BYTES {
                    return Err(DaemonError::PayloadTooLarge);
                }
                check_string_lengths(val)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// JSON extractor with all three caps applied. Drop-in replacement
/// for [`axum::Json`] in the daemon's handlers.
///
/// Order of operations:
/// 1. Collect body bytes (tower-http's `RequestBodyLimitLayer` has
///    already capped at 64 KiB — this extractor defends in depth
///    against a future mis-wire).
/// 2. [`check_json_depth`] (400).
/// 3. Parse to [`serde_json::Value`].
/// 4. [`check_string_lengths`] (413).
/// 5. `serde_json::from_value::<T>` to the typed payload.
#[derive(Debug, Clone)]
pub struct LimitedJson<T>(pub T);

impl<T, S> FromRequest<S> for LimitedJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = DaemonError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Reject without reading the body if Content-Type isn't JSON.
        // Axum's Json does this check; we mirror it for consistency.
        if !is_json_content_type(&req) {
            return Err(DaemonError::JsonDepthExceeded);
        }
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|rej| {
                // `Bytes::from_request` uses `tower_http::limit::RequestBodyLimitLayer`
                // upstream to reject oversize bodies with 413 PAYLOAD_TOO_LARGE.
                // Map that (and only that) to PayloadTooLarge; everything else
                // becomes a generic 400.
                if rej.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    DaemonError::PayloadTooLarge
                } else {
                    DaemonError::JsonDepthExceeded
                }
            })?;

        if bytes.len() > MAX_BODY_BYTES {
            return Err(DaemonError::PayloadTooLarge);
        }
        check_json_depth(&bytes, MAX_JSON_DEPTH)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| DaemonError::JsonDepthExceeded)?;
        check_string_lengths(&value)?;
        let parsed: T = serde_json::from_value(value).map_err(|_| DaemonError::JsonDepthExceeded)?;
        Ok(Self(parsed))
    }
}

fn is_json_content_type(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            let mime = s.split(';').next().unwrap_or("").trim();
            mime.eq_ignore_ascii_case("application/json")
        })
        .unwrap_or(false)
}

/// Builder that constructs the `tower_http::limit::RequestBodyLimitLayer`
/// used by [`crate::router`]. Centralized here so the constant is in one
/// place.
pub fn body_limit_layer() -> tower_http::limit::RequestBodyLimitLayer {
    tower_http::limit::RequestBodyLimitLayer::new(MAX_BODY_BYTES)
}

// `Arc` isn't used directly here, but a future task may want a shared
// config struct for the caps — re-export keeps the call sites consistent.
#[allow(dead_code)]
type _ArcMarker = Arc<()>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_15_and_16_accepted() {
        let s15: String = format!("{}{}", "[".repeat(15), "]".repeat(15));
        let s16: String = format!("{}{}", "[".repeat(16), "]".repeat(16));
        assert!(check_json_depth(s15.as_bytes(), MAX_JSON_DEPTH).is_ok());
        assert!(check_json_depth(s16.as_bytes(), MAX_JSON_DEPTH).is_ok());
    }

    #[test]
    fn depth_17_rejected() {
        let s17: String = format!("{}{}", "[".repeat(17), "]".repeat(17));
        assert!(matches!(
            check_json_depth(s17.as_bytes(), MAX_JSON_DEPTH),
            Err(DaemonError::JsonDepthExceeded)
        ));
    }

    #[test]
    fn depth_ignores_braces_inside_strings() {
        let s = br#"{"payload": "[[[[[[[[[[[[[[[[[[[[["}"#;
        // 1-deep outer object + a string literal containing many `[`
        // — real depth is 1, string-contents don't count.
        assert!(check_json_depth(s, MAX_JSON_DEPTH).is_ok());
    }

    #[test]
    fn depth_handles_escaped_quote_inside_string() {
        let s = br#"{"k": "a\"b\"c{{{{{"}"#;
        assert!(check_json_depth(s, MAX_JSON_DEPTH).is_ok());
    }

    #[test]
    fn depth_handles_utf8_payload() {
        let s = "{\"k\": \"こんにちは 世界 {{{{\"}".as_bytes();
        assert!(check_json_depth(s, MAX_JSON_DEPTH).is_ok());
    }

    #[test]
    fn string_length_walk_accepts_short_strings() {
        let v: serde_json::Value =
            serde_json::json!({"did": "did:keri:xyz", "caps": ["sign"]});
        assert!(check_string_lengths(&v).is_ok());
    }

    #[test]
    fn string_length_walk_rejects_long_string() {
        let long = "a".repeat(MAX_JSON_STRING_BYTES + 1);
        let v: serde_json::Value = serde_json::json!({"notes": long});
        assert!(matches!(
            check_string_lengths(&v),
            Err(DaemonError::PayloadTooLarge)
        ));
    }

    #[test]
    fn string_length_walk_rejects_long_nested_string() {
        let long = "x".repeat(MAX_JSON_STRING_BYTES + 1);
        let v: serde_json::Value = serde_json::json!({
            "outer": {"inner": [1, 2, {"deep": long}]}
        });
        assert!(matches!(
            check_string_lengths(&v),
            Err(DaemonError::PayloadTooLarge)
        ));
    }

    #[test]
    fn string_length_walk_rejects_long_key() {
        let long = "k".repeat(MAX_JSON_STRING_BYTES + 1);
        let v: serde_json::Value = serde_json::json!({long: "short"});
        assert!(matches!(
            check_string_lengths(&v),
            Err(DaemonError::PayloadTooLarge)
        ));
    }
}
