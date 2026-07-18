//! The relying-party surface — everything a server needs to authenticate an
//! `Auths-Presentation` request lives HERE, in Rust, behind one call.
//!
//! A relying party (the market, any future API) must never re-implement the
//! wire: no header parsing, no base64 juggling, no verify-request assembly, no
//! verdict-to-denial mapping in application code. The flow is:
//!
//! 1. [`mint_challenge_nonce`] — mint the single-use nonce the RP stores.
//! 2. [`presentation_nonce`] — parse-only peek at an incoming header, so the
//!    RP can consume the nonce from its store BEFORE any verification (a
//!    failed attempt must still burn its challenge).
//! 3. [`authenticate_presentation`] — the full check: wire parse, audience and
//!    nonce binding, evidence-carrying verify request, KEL-authenticated
//!    verification, and the verdict→denial doctrine. Returns a typed report;
//!    grants (which capabilities admit which action) stay the RP's policy.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use napi_derive::napi;

use auths_rp::{AUTHS_PRESENTATION_SCHEME, Nonce, WireBinding, WirePresentation};

/// The parse-only view of an incoming presentation header: what the relying
/// party needs to consume its challenge, before anything is trusted.
#[napi(object)]
pub struct NapiPresentationPeek {
    /// The base64url challenge nonce the subject signed over.
    pub nonce: String,
    /// The audience the presentation claims to bind to (verified later).
    pub audience: String,
    /// The SAID of the credential being presented (verified later).
    pub credential_said: String,
}

/// The outcome of authenticating a presentation request.
#[napi(object)]
pub struct NapiAgentAuthReport {
    /// True only when the presentation verified end-to-end.
    pub authorized: bool,
    /// `"ok"` when authorized; otherwise the kebab-case denial code
    /// (e.g. `"presentation-kel-unauthenticated"`, `"wrong-audience"`).
    pub code: String,
    /// The proven subject AID — present when authorized.
    pub subject: Option<String>,
    /// The subject's proven root (its delegator when delegated) — present when authorized.
    pub subject_root: Option<String>,
    /// The credential's issuer AID — present when authorized.
    pub issuer: Option<String>,
    /// The capabilities the verified credential grants — present when authorized.
    pub caps: Option<Vec<String>>,
    /// Failure detail for diagnostics — present on some denials.
    pub detail: Option<String>,
}

fn denied(code: &str, detail: Option<String>) -> NapiAgentAuthReport {
    NapiAgentAuthReport {
        authorized: false,
        code: code.to_string(),
        subject: None,
        subject_root: None,
        issuer: None,
        caps: None,
        detail,
    }
}

/// Mint a single-use challenge nonce (32 random bytes, base64url) for the
/// relying party to store and hand to an agent. Format and length are the
/// auths-rp contract — a relying party never invents its own nonce shape.
///
/// Args: (none)
///
/// Usage:
/// ```ignore
/// const nonce = mintChallengeNonce(); // store with a TTL, consume exactly once
/// ```
#[napi]
pub fn mint_challenge_nonce() -> String {
    use rand::RngCore as _;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Nonce::from_bytes(bytes).to_b64url()
}

fn parse_wire(authorization_header: &str) -> Result<WirePresentation, &'static str> {
    let scheme = format!("{AUTHS_PRESENTATION_SCHEME} ");
    let token = authorization_header
        .strip_prefix(&scheme)
        .ok_or("bad-authorization-header")?
        .trim();
    let json = B64_URL
        .decode(token)
        .map_err(|_| "bad-authorization-header")?;
    serde_json::from_slice::<WirePresentation>(&json).map_err(|_| "bad-authorization-header")
}

/// Parse-only peek at an `Authorization: Auths-Presentation` header.
///
/// Nothing here is trusted — it exists so the relying party can consume the
/// single-use nonce from its store before verification runs. Only the
/// interactive challenge binding is accepted.
///
/// Args:
/// * `authorization_header`: The full `Authorization` header value.
///
/// Usage:
/// ```ignore
/// const peek = presentationNonce(header);
/// const consumed = await store.consume(peek.nonce);
/// ```
#[napi]
pub fn presentation_nonce(authorization_header: String) -> napi::Result<NapiPresentationPeek> {
    let wire = parse_wire(&authorization_header)
        .map_err(|code| napi::Error::from_reason(code.to_string()))?;
    let WireBinding::Challenge { nonce } = wire.binding else {
        return Err(napi::Error::from_reason(
            "challenge-binding-required".to_string(),
        ));
    };
    Ok(NapiPresentationPeek {
        nonce,
        audience: wire.audience,
        credential_said: wire.credential_said,
    })
}

/// Authenticate a presentation request end-to-end.
///
/// The caller has already consumed the single-use nonce (via
/// [`presentation_nonce`] + its own store); this performs everything else:
/// audience binding, nonce equality, the evidence-carrying verify request
/// (every supplied KEL is signature-authenticated before replay), and the
/// verdict→denial mapping. Capability policy is deliberately NOT here — the
/// report carries `caps` and the relying party decides what they admit.
///
/// Args:
/// * `authorization_header`: The full `Authorization` header value.
/// * `evidence_json`: The evidence bundle from `credential present --with-evidence`.
/// * `expected_audience`: The relying party's own audience identifier.
/// * `expected_nonce`: The base64url nonce the caller just consumed.
/// * `now_iso`: Verification time (RFC 3339); defaults to the current time.
///
/// Usage:
/// ```ignore
/// const report = await authenticatePresentation(header, evidenceJson, 'market.auths.dev', peek.nonce);
/// if (report.authorized) { /* report.subject, report.subjectRoot, report.caps */ }
/// ```
#[napi]
pub async fn authenticate_presentation(
    authorization_header: String,
    evidence_json: String,
    expected_audience: String,
    expected_nonce: String,
    now_iso: Option<String>,
) -> napi::Result<NapiAgentAuthReport> {
    let wire = match parse_wire(&authorization_header) {
        Ok(wire) => wire,
        Err(code) => return Ok(denied(code, None)),
    };
    let WireBinding::Challenge { nonce } = &wire.binding else {
        return Ok(denied("challenge-binding-required", None));
    };
    if wire.audience != expected_audience {
        return Ok(denied("wrong-audience", None));
    }
    if *nonce != expected_nonce {
        return Ok(denied("challenge-mismatch", None));
    }
    let Ok(nonce_bytes) = Nonce::parse_b64url(nonce).map(|n| n.as_bytes().to_vec()) else {
        return Ok(denied(
            "bad-authorization-header",
            Some("malformed nonce".into()),
        ));
    };
    let Ok(signature_bytes) = B64_URL.decode(&wire.signature_b64) else {
        return Ok(denied(
            "bad-authorization-header",
            Some("malformed signature".into()),
        ));
    };
    let evidence: serde_json::Value = match serde_json::from_str(&evidence_json) {
        Ok(serde_json::Value::Object(map)) => serde_json::Value::Object(map),
        _ => return Ok(denied("evidence-required", None)),
    };

    #[allow(clippy::disallowed_methods)] // presentation boundary: wall clock injected here
    let now = now_iso.unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let nonce_std = B64_STD.encode(&nonce_bytes);
    let field = |name: &str| evidence.get(name).cloned().unwrap_or(serde_json::json!([]));
    let request = serde_json::json!({
        "schemaVersion": 1,
        "envelope": {
            "credentialSaid": wire.credential_said,
            "audience": wire.audience,
            "binding": { "mode": "challenge", "nonceB64": nonce_std },
            "signatureB64": B64_STD.encode(&signature_bytes),
        },
        "credential": evidence.get("credential").cloned().unwrap_or(serde_json::Value::Null),
        "issuerKel": field("issuerKel"),
        "issuerKelAttachmentsB64": field("issuerKelAttachmentsB64"),
        "subjectKel": field("subjectKel"),
        "subjectKelAttachmentsB64": field("subjectKelAttachmentsB64"),
        "delegatorKel": field("delegatorKel"),
        "delegatorKelAttachmentsB64": field("delegatorKelAttachmentsB64"),
        "tel": field("tel"),
        "receipts": [],
        "witnessPolicy": "warn",
        "audience": expected_audience,
        "expectedChallengeB64": nonce_std,
        "now": now,
    });

    // KEL replay + signature verification is CPU-bound: run it off the Node event
    // loop so a burst of agent logins cannot stall unrelated requests.
    let request_string = request.to_string();
    let verdict_json = tokio::task::spawn_blocking(move || {
        auths_verifier::verify_presentation_json(&request_string)
    })
    .await
    .map_err(|e| napi::Error::from_reason(format!("verification task failed: {e}")))?;
    let verdict: serde_json::Value = serde_json::from_str(&verdict_json)
        .unwrap_or_else(|_| serde_json::json!({ "kind": "malformedRequest" }));
    let kind = verdict["kind"].as_str().unwrap_or("malformedRequest");

    if kind != "valid" {
        let kebab: String = kind
            .chars()
            .flat_map(|c| {
                if c.is_ascii_uppercase() {
                    vec!['-', c.to_ascii_lowercase()]
                } else {
                    vec![c]
                }
            })
            .collect();
        let detail = verdict["detail"]
            .as_str()
            .or_else(|| verdict["message"].as_str())
            .or_else(|| verdict["field"].as_str())
            .map(str::to_string);
        return Ok(denied(&format!("presentation-{kebab}"), detail));
    }

    Ok(NapiAgentAuthReport {
        authorized: true,
        code: "ok".to_string(),
        subject: verdict["subject"].as_str().map(str::to_string),
        subject_root: verdict["subjectRoot"].as_str().map(str::to_string),
        issuer: verdict["issuer"].as_str().map(str::to_string),
        caps: verdict["caps"].as_array().map(|a| {
            a.iter()
                .filter_map(|c| c.as_str().map(str::to_string))
                .collect()
        }),
        detail: None,
    })
}
