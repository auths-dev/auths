//! Typed presentation/credential verify for Node (Epic D2 / fn-153.6).
//!
//! Thin, in-process binding over the executor-free verify contract
//! (`auths_verifier::contract`). The bundled JSON request crosses once; the verdict comes
//! back as a **typed** `#[napi(object)]` report with a `#[napi(string_enum)]` status — never
//! a `dict`/`any`. A denied or malformed request is a typed verdict (status), not a thrown
//! exception; napi still converts any unforeseen Rust panic into a JS exception as a backstop.
//!
//! This is a verify-only surface: it links `auths-verifier` and never touches git2/keychain,
//! even though the crate also links the full SDK.

use napi_derive::napi;
use serde_json::Value;

/// The outcome of [`verify_presentation`] — mirrors the Rust `PresentationVerdict` wire kinds.
#[napi(string_enum)]
pub enum PresentationStatus {
    /// Holder-binding proven: the credential is valid and the presentation is current-key signed.
    Valid,
    /// The presentation signature is not the subject AID's current key.
    HolderNotCurrentKey,
    /// Bound to a different audience than expected.
    WrongAudience,
    /// Challenge mismatched or already consumed (single-use replay protection).
    NonceMismatchOrConsumed,
    /// Non-interactive TTL presentation expired.
    Expired,
    /// The subject KEL could not be replayed.
    SubjectKelInvalid,
    /// The credential itself is not valid; see `credential` for the nested verdict.
    CredentialNotValid,
    /// The request JSON could not be parsed; see `message`.
    MalformedRequest,
    /// A request slice exceeded its bound; see `field`.
    InputTooLarge,
    /// The request schema version is not understood by this build.
    UnsupportedSchemaVersion,
    /// Unrecognized verdict kind (forward-compat guard).
    Unknown,
}

/// The outcome of [`verify_credential`] — mirrors the Rust `CredentialVerdict` wire kinds.
#[napi(string_enum)]
pub enum CredentialStatus {
    /// Authentic, anchored, witnessed per policy, unexpired, and not revoked.
    Valid,
    /// Recomputed ACDC SAID did not match the embedded one.
    SaidMismatch,
    /// Attributes failed schema validation, or the schema SAID is not the pinned one.
    SchemaInvalid,
    /// The issuance was unanchored or the issuer signature did not verify.
    IssuerSignatureInvalid,
    /// The registry (`vcp`) was never anchored in the issuer KEL.
    RegistryNotEstablished,
    /// A qualifying revocation is anchored at/before the presentation; see `revokedAt`.
    CredentialRevoked,
    /// The credential expired; see `expiredAt`.
    Expired,
    /// A lifecycle anchor missed witness quorum under `RequireWitnesses`.
    WitnessQuorumNotMet,
    /// The issuer KEL forks (fail-closed in both witness policies).
    IssuerKelDuplicitous,
    /// The request JSON could not be parsed; see `message`.
    MalformedRequest,
    /// A request slice exceeded its bound; see `field`.
    InputTooLarge,
    /// The request schema version is not understood by this build.
    UnsupportedSchemaVersion,
    /// Unrecognized verdict kind (forward-compat guard).
    Unknown,
}

/// A typed credential verdict report (the F.5 outcome).
#[napi(object)]
pub struct CredentialReport {
    /// The discriminated status.
    pub status: CredentialStatus,
    /// Issuer AID (`did:keri:`) — present on `Valid`.
    pub issuer: Option<String>,
    /// Subject (holder) AID — present on `Valid`.
    pub subject: Option<String>,
    /// Granted capabilities — present on `Valid`. Never silently dropped (fn-153.2).
    pub caps: Option<Vec<String>>,
    /// The KEL position the verdict is as-of — present on `Valid`.
    pub as_of: Option<f64>,
    /// The KEL position a revocation was anchored at — present on `CredentialRevoked`.
    pub revoked_at: Option<f64>,
    /// The expiry instant — present on `Expired`.
    pub expired_at: Option<String>,
    /// Failure detail — present on `MalformedRequest`.
    pub message: Option<String>,
    /// The offending request field — present on `InputTooLarge`.
    pub field: Option<String>,
}

/// A typed presentation verdict report (holder-binding outcome).
#[napi(object)]
pub struct PresentationReport {
    /// The discriminated status.
    pub status: PresentationStatus,
    /// Issuer AID (`did:keri:`) — present on `Valid`.
    pub issuer: Option<String>,
    /// Subject (holder) AID whose current key signed — present on `Valid`.
    pub subject: Option<String>,
    /// Granted capabilities — present on `Valid`. Never silently dropped (fn-153.2).
    pub caps: Option<Vec<String>>,
    /// Optional informational role claim — present on `Valid`.
    pub role: Option<String>,
    /// Optional credential expiry — present on `Valid`.
    pub expires_at: Option<String>,
    /// The nested credential verdict — present on `CredentialNotValid`.
    pub credential: Option<CredentialReport>,
    /// Failure detail — present on `MalformedRequest`.
    pub message: Option<String>,
    /// The offending request field — present on `InputTooLarge`.
    pub field: Option<String>,
}

/// Verify a credential **presentation** from a bundled JSON request, returning a typed report.
///
/// The request is the fn-153.3 `VerifyPresentationRequest` bundle (keys CESR-tagged inside).
/// Denials and malformed input are returned as a `status`, not thrown.
///
/// Args:
/// * `request_json`: A `VerifyPresentationRequest` JSON document.
///
/// Usage (TypeScript):
/// ```ignore
/// import { verifyPresentation, PresentationStatus } from "@auths-dev/sdk";
/// const report = verifyPresentation(bundleJson);
/// if (report.status === PresentationStatus.Valid) { /* report.subject, report.caps */ }
/// ```
#[napi]
pub fn verify_presentation(request_json: String) -> PresentationReport {
    let verdict = auths_verifier::contract::verify_presentation_json(&request_json);
    presentation_report(&parse_verdict(&verdict))
}

/// Verify an issued **credential** from a bundled JSON request, returning a typed report.
///
/// Args:
/// * `request_json`: A `VerifyCredentialRequest` JSON document.
///
/// Usage (TypeScript):
/// ```ignore
/// import { verifyCredential, CredentialStatus } from "@auths-dev/sdk";
/// const report = verifyCredential(bundleJson);
/// if (report.status === CredentialStatus.CredentialRevoked) { /* report.revokedAt */ }
/// ```
#[napi]
pub fn verify_credential(request_json: String) -> CredentialReport {
    let verdict = auths_verifier::contract::verify_credential_json(&request_json);
    credential_report(&parse_verdict(&verdict))
}

/// Parse the contract's verdict JSON, falling back to `Null` if (impossibly) malformed.
fn parse_verdict(verdict_json: &str) -> Value {
    serde_json::from_str(verdict_json).unwrap_or(Value::Null)
}

/// Read an optional string field from a verdict object.
fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Read an optional numeric field from a verdict object.
fn number_field(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}

/// Read an optional string-array field (capabilities) from a verdict object.
fn caps_field(value: &Value) -> Option<Vec<String>> {
    value.get("caps").and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect()
    })
}

/// The verdict's `kind` tag, or empty if absent.
fn kind_of(value: &Value) -> &str {
    value.get("kind").and_then(Value::as_str).unwrap_or("")
}

fn presentation_status(kind: &str) -> PresentationStatus {
    match kind {
        "valid" => PresentationStatus::Valid,
        "holderNotCurrentKey" => PresentationStatus::HolderNotCurrentKey,
        "wrongAudience" => PresentationStatus::WrongAudience,
        "nonceMismatchOrConsumed" => PresentationStatus::NonceMismatchOrConsumed,
        "expired" => PresentationStatus::Expired,
        "subjectKelInvalid" => PresentationStatus::SubjectKelInvalid,
        "credentialNotValid" => PresentationStatus::CredentialNotValid,
        "malformedRequest" => PresentationStatus::MalformedRequest,
        "inputTooLarge" => PresentationStatus::InputTooLarge,
        "unsupportedSchemaVersion" => PresentationStatus::UnsupportedSchemaVersion,
        _ => PresentationStatus::Unknown,
    }
}

fn credential_status(kind: &str) -> CredentialStatus {
    match kind {
        "valid" => CredentialStatus::Valid,
        "saidMismatch" => CredentialStatus::SaidMismatch,
        "schemaInvalid" => CredentialStatus::SchemaInvalid,
        "issuerSignatureInvalid" => CredentialStatus::IssuerSignatureInvalid,
        "registryNotEstablished" => CredentialStatus::RegistryNotEstablished,
        "credentialRevoked" => CredentialStatus::CredentialRevoked,
        "expired" => CredentialStatus::Expired,
        "witnessQuorumNotMet" => CredentialStatus::WitnessQuorumNotMet,
        "issuerKelDuplicitous" => CredentialStatus::IssuerKelDuplicitous,
        "malformedRequest" => CredentialStatus::MalformedRequest,
        "inputTooLarge" => CredentialStatus::InputTooLarge,
        "unsupportedSchemaVersion" => CredentialStatus::UnsupportedSchemaVersion,
        _ => CredentialStatus::Unknown,
    }
}

fn credential_report(value: &Value) -> CredentialReport {
    CredentialReport {
        status: credential_status(kind_of(value)),
        issuer: string_field(value, "issuer"),
        subject: string_field(value, "subject"),
        caps: caps_field(value),
        as_of: number_field(value, "asOf"),
        revoked_at: number_field(value, "revokedAt"),
        expired_at: string_field(value, "expiredAt"),
        message: string_field(value, "message"),
        field: string_field(value, "field"),
    }
}

fn presentation_report(value: &Value) -> PresentationReport {
    PresentationReport {
        status: presentation_status(kind_of(value)),
        issuer: string_field(value, "issuer"),
        subject: string_field(value, "subject"),
        caps: caps_field(value),
        role: string_field(value, "role"),
        expires_at: string_field(value, "expiresAt"),
        credential: value.get("credential").map(credential_report),
        message: string_field(value, "message"),
        field: string_field(value, "field"),
    }
}
