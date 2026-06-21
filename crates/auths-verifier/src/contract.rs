//! The single cross-boundary verify contract: one JSON request in, one tagged verdict out.
//!
//! `verify_presentation`/`verify_credential` take up to twelve arguments — five of them
//! slices of KERI events, TEL events, and witness receipts — none individually
//! FFI-representable. This module bundles them into **one** JSON request that every
//! non-Rust target (C-ABI, WASM, Node, Python, Go) marshals once, and returns the verdict
//! as a **discriminated union** (`{ "schemaVersion": 1, "kind": "...", ... }`), never a
//! bare bool or magic int.
//!
//! It calls the executor-free [`verify_presentation_sync`]/[`verify_credential_sync`]
//! cores (no `block_on`, WASM-safe) and is panic-free: malformed, oversize, or
//! wrong-version input returns a typed error verdict rather than unwinding. The FFI/WASM
//! layers still wrap these in `catch_unwind` for defence in depth.
//!
//! ## Wire conventions
//!
//! - **All raw bytes are base64** (`signatureB64`, `nonceB64`, `expectedChallengeB64`) —
//!   never JSON int arrays — so the contract is ergonomic from JS/Python/Go.
//! - **Keys stay CESR-tagged inside the KEL/TEL JSON** (curve travels in-band; the
//!   verifier never dispatches on byte length).
//! - **`schemaVersion`** is carried on every request and every verdict. This is the one
//!   schema to version and fuzz; a request whose version this build does not understand is
//!   rejected with `unsupportedSchemaVersion`.
//!
//! ## Verdict schema (canonical; the TS union in fn-153.5 mirrors this)
//!
//! ```json
//! { "schemaVersion": 1, "kind": "valid", "issuer": "did:keri:…", "subject": "did:keri:…",
//!   "caps": ["sign"], "role": null, "expiresAt": null }
//! ```
//! Other `kind`s: `holderNotCurrentKey`, `wrongAudience`, `nonceMismatchOrConsumed`,
//! `expired`, `subjectKelInvalid`, `credentialNotValid` (nests a credential verdict),
//! plus the request-layer errors `malformedRequest`, `inputTooLarge`,
//! `unsupportedSchemaVersion`. Credential verdict `kind`s: `valid`, `saidMismatch`,
//! `schemaInvalid`, `issuerSignatureInvalid`, `registryNotEstablished`,
//! `credentialRevoked`, `expired`, `witnessQuorumNotMet`, `issuerKelDuplicitous`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use auths_keri::witness::StoredReceipt;
use auths_keri::{Acdc, Event, TelEvent};

use crate::commit_kel::VerifierWitnessPolicy;
use crate::credential::{CredentialVerdict, LifecycleEvent, SignedAcdc, verify_credential_sync};
use crate::presentation::{
    PresentationBinding, PresentationEnvelope, PresentationVerdict, verify_presentation_sync,
};

/// The contract version carried on every request and verdict. Bump on any breaking change
/// to the request or verdict shape; this is the single schema to version and fuzz.
pub const SCHEMA_VERSION: u32 = 1;

/// Maximum accepted request JSON size (1 MiB), matching the shipped FFI batch ceiling.
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// Maximum events in any single KEL slice (issuer/subject/delegator).
const MAX_KEL_EVENTS: usize = 1024;

/// Maximum events in the credential TEL slice.
const MAX_TEL_EVENTS: usize = 1024;

/// Maximum witness receipts handed to the quorum math.
const MAX_RECEIPTS: usize = 4096;

/// A last-resort verdict string used only if verdict serialization itself fails — it never
/// should, but the fallback keeps the surface panic-free and string-typed.
const SERIALIZE_FALLBACK: &str = "{\"schemaVersion\":1,\"kind\":\"malformedRequest\",\"message\":\"verdict serialization failed\"}";

// ── Verdict (out) ────────────────────────────────────────────────────────────────────

/// The serialized verdict envelope: the schema version flattened over the tagged verdict.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireEnvelope<V> {
    schema_version: u32,
    #[serde(flatten)]
    verdict: V,
}

/// The presentation verdict as a tagged discriminated union, including request-layer errors.
///
/// `rename_all_fields` is required alongside `rename_all`: the latter only camelCases the
/// variant tags, not the fields *inside* struct variants (so `expires_at` would otherwise ship
/// snake_case and drift from the TS union / bindings).
#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum WirePresentationVerdict {
    Valid {
        issuer: String,
        subject: String,
        caps: Vec<String>,
        role: Option<String>,
        expires_at: Option<String>,
    },
    HolderNotCurrentKey,
    WrongAudience,
    NonceMismatchOrConsumed,
    Expired,
    SubjectKelInvalid,
    CredentialNotValid {
        credential: WireCredentialVerdict,
    },
    MalformedRequest {
        message: String,
    },
    InputTooLarge {
        field: String,
        count: usize,
        limit: usize,
    },
    UnsupportedSchemaVersion {
        got: u32,
        expected: u32,
    },
}

/// The credential verdict as a tagged discriminated union, including request-layer errors.
///
/// `rename_all_fields` keeps struct-variant fields (`as_of`, `revoked_at`, `expired_at`)
/// camelCase on the wire — see [`WirePresentationVerdict`].
#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum WireCredentialVerdict {
    Valid {
        issuer: String,
        subject: String,
        caps: Vec<String>,
        as_of: u128,
    },
    SaidMismatch,
    SchemaInvalid,
    IssuerSignatureInvalid,
    RegistryNotEstablished,
    CredentialRevoked {
        revoked_at: u128,
    },
    Expired {
        expired_at: String,
        now: String,
    },
    WitnessQuorumNotMet {
        event: String,
        collected: usize,
        required: usize,
    },
    IssuerKelDuplicitous,
    MalformedRequest {
        message: String,
    },
    InputTooLarge {
        field: String,
        count: usize,
        limit: usize,
    },
    UnsupportedSchemaVersion {
        got: u32,
        expected: u32,
    },
}

impl From<PresentationVerdict> for WirePresentationVerdict {
    fn from(verdict: PresentationVerdict) -> Self {
        match verdict {
            PresentationVerdict::Valid {
                issuer,
                subject,
                caps,
                role,
                expires_at,
            } => WirePresentationVerdict::Valid {
                issuer: issuer.as_str().to_string(),
                subject: subject.as_str().to_string(),
                caps: caps.iter().map(|c| c.as_str().to_string()).collect(),
                role,
                expires_at: expires_at.map(|t| t.to_rfc3339()),
            },
            PresentationVerdict::HolderNotCurrentKey => {
                WirePresentationVerdict::HolderNotCurrentKey
            }
            PresentationVerdict::WrongAudience => WirePresentationVerdict::WrongAudience,
            PresentationVerdict::NonceMismatchOrConsumed => {
                WirePresentationVerdict::NonceMismatchOrConsumed
            }
            PresentationVerdict::Expired => WirePresentationVerdict::Expired,
            PresentationVerdict::SubjectKelInvalid => WirePresentationVerdict::SubjectKelInvalid,
            PresentationVerdict::CredentialNotValid(inner) => {
                WirePresentationVerdict::CredentialNotValid {
                    credential: inner.into(),
                }
            }
        }
    }
}

impl From<CredentialVerdict> for WireCredentialVerdict {
    fn from(verdict: CredentialVerdict) -> Self {
        match verdict {
            CredentialVerdict::Valid {
                issuer,
                subject,
                caps,
                as_of,
                ..
            } => WireCredentialVerdict::Valid {
                issuer: issuer.as_str().to_string(),
                subject: subject.as_str().to_string(),
                caps: caps.iter().map(|c| c.as_str().to_string()).collect(),
                as_of,
            },
            CredentialVerdict::SaidMismatch => WireCredentialVerdict::SaidMismatch,
            CredentialVerdict::SchemaInvalid => WireCredentialVerdict::SchemaInvalid,
            CredentialVerdict::IssuerSignatureInvalid => {
                WireCredentialVerdict::IssuerSignatureInvalid
            }
            CredentialVerdict::RegistryNotEstablished => {
                WireCredentialVerdict::RegistryNotEstablished
            }
            CredentialVerdict::CredentialRevoked { revoked_at } => {
                WireCredentialVerdict::CredentialRevoked { revoked_at }
            }
            CredentialVerdict::Expired { expired_at, now } => WireCredentialVerdict::Expired {
                expired_at: expired_at.to_rfc3339(),
                now: now.to_rfc3339(),
            },
            CredentialVerdict::WitnessQuorumNotMet {
                event,
                collected,
                required,
            } => WireCredentialVerdict::WitnessQuorumNotMet {
                event: lifecycle_tag(event).to_string(),
                collected,
                required,
            },
            CredentialVerdict::IssuerKelDuplicitous => WireCredentialVerdict::IssuerKelDuplicitous,
        }
    }
}

/// The wire tag for a lifecycle anchor (`vcp`/`iss`/`rev`).
fn lifecycle_tag(event: LifecycleEvent) -> &'static str {
    match event {
        LifecycleEvent::Vcp => "vcp",
        LifecycleEvent::Iss => "iss",
        LifecycleEvent::Rev => "rev",
    }
}

// ── Request (in) ─────────────────────────────────────────────────────────────────────

/// The single bundled presentation-verify request.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifyPresentationRequest {
    // Validated up front by `VersionPeek`; present here only so `deny_unknown_fields` accepts it.
    #[serde(rename = "schemaVersion")]
    _schema_version: u32,
    envelope: WireEnvelopeIn,
    credential: WireSignedAcdc,
    issuer_kel: Vec<Event>,
    subject_kel: Vec<Event>,
    #[serde(default)]
    delegator_kel: Vec<Event>,
    tel: Vec<TelEvent>,
    #[serde(default)]
    receipts: Vec<StoredReceipt>,
    witness_policy: WireWitnessPolicy,
    audience: String,
    #[serde(default)]
    expected_challenge_b64: Option<String>,
    now: DateTime<Utc>,
}

/// The single bundled credential-verify request (the F.5 inputs, no holder proof).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifyCredentialRequest {
    // Validated up front by `VersionPeek`; present here only so `deny_unknown_fields` accepts it.
    #[serde(rename = "schemaVersion")]
    _schema_version: u32,
    credential: WireSignedAcdc,
    issuer_kel: Vec<Event>,
    tel: Vec<TelEvent>,
    #[serde(default)]
    receipts: Vec<StoredReceipt>,
    witness_policy: WireWitnessPolicy,
    now: DateTime<Utc>,
}

/// The presentation envelope on the wire: bytes carried base64, binding carried tagged.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireEnvelopeIn {
    credential_said: String,
    audience: String,
    binding: WireBindingIn,
    signature_b64: String,
}

/// The binding mode on the wire (`{"mode":"challenge","nonceB64":…}` /
/// `{"mode":"ttl","nonceB64":…,"notAfter":…}`).
#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase")]
enum WireBindingIn {
    // Per-variant `rename_all` is required: the enum-level one only renames the variant
    // identifiers (`challenge`/`ttl`), not the fields inside each struct variant.
    #[serde(rename_all = "camelCase")]
    Challenge { nonce_b64: String },
    #[serde(rename_all = "camelCase")]
    Ttl {
        nonce_b64: String,
        not_after: DateTime<Utc>,
    },
}

/// A signed ACDC on the wire: the ACDC body plus the issuer signature, base64.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireSignedAcdc {
    acdc: Acdc,
    signature_b64: String,
}

/// A minimal peek at just `schemaVersion`, so a version this build cannot parse is rejected
/// with `unsupportedSchemaVersion` before the full (version-specific) shape is decoded.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionPeek {
    schema_version: u32,
}

/// The verifier-set witness policy on the wire (`"warn"` / `"requireWitnesses"`).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum WireWitnessPolicy {
    Warn,
    RequireWitnesses,
}

impl From<WireWitnessPolicy> for VerifierWitnessPolicy {
    fn from(policy: WireWitnessPolicy) -> Self {
        match policy {
            WireWitnessPolicy::Warn => VerifierWitnessPolicy::Warn,
            WireWitnessPolicy::RequireWitnesses => VerifierWitnessPolicy::RequireWitnesses,
        }
    }
}

/// A request that failed before the verify core could run — mapped to a tagged error verdict.
enum RequestError {
    Malformed(String),
    TooLarge {
        field: &'static str,
        count: usize,
        limit: usize,
    },
    UnsupportedSchemaVersion(u32),
}

impl From<RequestError> for WirePresentationVerdict {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::Malformed(message) => {
                WirePresentationVerdict::MalformedRequest { message }
            }
            RequestError::TooLarge {
                field,
                count,
                limit,
            } => WirePresentationVerdict::InputTooLarge {
                field: field.to_string(),
                count,
                limit,
            },
            RequestError::UnsupportedSchemaVersion(got) => {
                WirePresentationVerdict::UnsupportedSchemaVersion {
                    got,
                    expected: SCHEMA_VERSION,
                }
            }
        }
    }
}

impl From<RequestError> for WireCredentialVerdict {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::Malformed(message) => WireCredentialVerdict::MalformedRequest { message },
            RequestError::TooLarge {
                field,
                count,
                limit,
            } => WireCredentialVerdict::InputTooLarge {
                field: field.to_string(),
                count,
                limit,
            },
            RequestError::UnsupportedSchemaVersion(got) => {
                WireCredentialVerdict::UnsupportedSchemaVersion {
                    got,
                    expected: SCHEMA_VERSION,
                }
            }
        }
    }
}

// ── Public core functions ────────────────────────────────────────────────────────────

/// Verify a credential presentation from one bundled JSON request, returning a tagged
/// verdict JSON. Executor-free and panic-free — malformed/oversize/wrong-version input
/// yields a typed error verdict, never an unwind or a bare string.
///
/// Args:
/// * `request_json`: A `VerifyPresentationRequest` JSON document (see module docs).
///
/// Usage:
/// ```ignore
/// let verdict_json = verify_presentation_json(&request_json);
/// // -> {"schemaVersion":1,"kind":"valid","issuer":"did:keri:…",...}
/// ```
pub fn verify_presentation_json(request_json: &str) -> String {
    let verdict = run_presentation(request_json).unwrap_or_else(WirePresentationVerdict::from);
    serialize_verdict(verdict)
}

/// Verify an issued credential from one bundled JSON request, returning a tagged verdict
/// JSON. Same panic-free, executor-free contract as [`verify_presentation_json`].
///
/// Args:
/// * `request_json`: A `VerifyCredentialRequest` JSON document (see module docs).
///
/// Usage:
/// ```ignore
/// let verdict_json = verify_credential_json(&request_json);
/// ```
pub fn verify_credential_json(request_json: &str) -> String {
    let verdict = run_credential(request_json).unwrap_or_else(WireCredentialVerdict::from);
    serialize_verdict(verdict)
}

/// Serialize a verdict into the `{ schemaVersion, ... }` envelope, falling back to a fixed
/// error JSON if serialization itself fails (it never should — the fallback only guarantees
/// the surface stays string-typed).
fn serialize_verdict<V: Serialize>(verdict: V) -> String {
    serde_json::to_string(&WireEnvelope {
        schema_version: SCHEMA_VERSION,
        verdict,
    })
    .unwrap_or_else(|_| SERIALIZE_FALLBACK.to_string())
}

/// Parse, bound-check, and run the presentation verify; `Err` carries a request-layer error.
fn run_presentation(request_json: &str) -> Result<WirePresentationVerdict, RequestError> {
    check_request_size(request_json)?;
    check_schema_version(request_json)?;

    let request: VerifyPresentationRequest =
        serde_json::from_str(request_json).map_err(|e| RequestError::Malformed(e.to_string()))?;

    check_bound("issuerKel", request.issuer_kel.len(), MAX_KEL_EVENTS)?;
    check_bound("subjectKel", request.subject_kel.len(), MAX_KEL_EVENTS)?;
    check_bound("delegatorKel", request.delegator_kel.len(), MAX_KEL_EVENTS)?;
    check_bound("tel", request.tel.len(), MAX_TEL_EVENTS)?;
    check_bound("receipts", request.receipts.len(), MAX_RECEIPTS)?;

    let signature = decode_b64("credential.signatureB64", &request.credential.signature_b64)?;
    let signed = SignedAcdc {
        acdc: request.credential.acdc,
        signature,
    };
    let envelope = build_envelope(request.envelope)?;
    let expected_challenge = match &request.expected_challenge_b64 {
        Some(nonce) => Some(decode_b64("expectedChallengeB64", nonce)?),
        None => None,
    };

    Ok(verify_presentation_sync(
        &envelope,
        &signed,
        &request.issuer_kel,
        &request.tel,
        &request.receipts,
        request.witness_policy.into(),
        &request.subject_kel,
        &request.delegator_kel,
        &request.audience,
        expected_challenge.as_deref(),
        request.now,
    )
    .into())
}

/// Parse, bound-check, and run the credential verify; `Err` carries a request-layer error.
fn run_credential(request_json: &str) -> Result<WireCredentialVerdict, RequestError> {
    check_request_size(request_json)?;
    check_schema_version(request_json)?;

    let request: VerifyCredentialRequest =
        serde_json::from_str(request_json).map_err(|e| RequestError::Malformed(e.to_string()))?;

    check_bound("issuerKel", request.issuer_kel.len(), MAX_KEL_EVENTS)?;
    check_bound("tel", request.tel.len(), MAX_TEL_EVENTS)?;
    check_bound("receipts", request.receipts.len(), MAX_RECEIPTS)?;

    let signature = decode_b64("credential.signatureB64", &request.credential.signature_b64)?;
    let signed = SignedAcdc {
        acdc: request.credential.acdc,
        signature,
    };

    Ok(verify_credential_sync(
        &signed,
        &request.issuer_kel,
        &request.tel,
        &request.receipts,
        request.witness_policy.into(),
        request.now,
    )
    .into())
}

/// Reconstruct the typed [`PresentationEnvelope`] from its wire form, decoding base64 bytes.
fn build_envelope(wire: WireEnvelopeIn) -> Result<PresentationEnvelope, RequestError> {
    let signature = decode_b64("envelope.signatureB64", &wire.signature_b64)?;
    let binding = match wire.binding {
        WireBindingIn::Challenge { nonce_b64 } => PresentationBinding::Challenge {
            nonce: decode_b64("envelope.binding.nonceB64", &nonce_b64)?,
        },
        WireBindingIn::Ttl {
            nonce_b64,
            not_after,
        } => PresentationBinding::Ttl {
            nonce: decode_b64("envelope.binding.nonceB64", &nonce_b64)?,
            not_after,
        },
    };
    Ok(PresentationEnvelope {
        credential_said: wire.credential_said,
        audience: wire.audience,
        binding,
        signature,
    })
}

/// Reject a request whose raw JSON exceeds the byte ceiling before any parsing.
fn check_request_size(request_json: &str) -> Result<(), RequestError> {
    if request_json.len() > MAX_REQUEST_BYTES {
        return Err(RequestError::TooLarge {
            field: "request",
            count: request_json.len(),
            limit: MAX_REQUEST_BYTES,
        });
    }
    Ok(())
}

/// Peek at `schemaVersion` alone and reject an unsupported version before the full,
/// version-specific shape is decoded (so a future request never half-parses on this build).
fn check_schema_version(request_json: &str) -> Result<(), RequestError> {
    let peek: VersionPeek =
        serde_json::from_str(request_json).map_err(|e| RequestError::Malformed(e.to_string()))?;
    if peek.schema_version != SCHEMA_VERSION {
        return Err(RequestError::UnsupportedSchemaVersion(peek.schema_version));
    }
    Ok(())
}

/// Reject a slice whose element count exceeds its bound with a typed `inputTooLarge` error.
fn check_bound(field: &'static str, count: usize, limit: usize) -> Result<(), RequestError> {
    if count > limit {
        return Err(RequestError::TooLarge {
            field,
            count,
            limit,
        });
    }
    Ok(())
}

/// Decode a base64 field into bytes, mapping a decode failure to a typed malformed error.
fn decode_b64(field: &str, value: &str) -> Result<Vec<u8>, RequestError> {
    BASE64
        .decode(value)
        .map_err(|e| RequestError::Malformed(format!("{field}: invalid base64 ({e})")))
}
