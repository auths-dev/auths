//! Typed presentation/credential verify for Python (Epic D2 / fn-153.7).
//!
//! Thin, in-process binding over the executor-free verify contract
//! (`auths_verifier::contract`). The bundled JSON request crosses once; the verdict comes
//! back as a typed `#[pyclass]` `Report` carrying a `#[pyclass(eq, eq_int)]` `Status` enum —
//! compared by enum identity (`report.status is Status.VALID`), never by magic strings.
//!
//! A denial or malformed request is a typed `Status`, not a raised exception; the consumer
//! decides whether to raise (e.g. an `UnverifiedPresentation`) at its own boundary.

use pyo3::prelude::*;
use serde_json::Value;

/// The outcome of [`verify_presentation`] — mirrors the Rust `PresentationVerdict` wire kinds.
#[pyclass(eq, eq_int, rename_all = "SCREAMING_SNAKE_CASE", skip_from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PresentationStatus {
    /// Holder-binding proven: credential valid and presentation current-key signed.
    Valid,
    /// The presentation signature is not the subject AID's current key.
    HolderNotCurrentKey,
    /// Bound to a different audience than expected.
    WrongAudience,
    /// Challenge mismatched or already consumed.
    NonceMismatchOrConsumed,
    /// Non-interactive TTL presentation expired.
    Expired,
    /// The subject KEL could not be replayed.
    SubjectKelInvalid,
    /// The credential itself is not valid; see `credential`.
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
#[pyclass(eq, eq_int, rename_all = "SCREAMING_SNAKE_CASE", skip_from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CredentialStatus {
    /// Authentic, anchored, witnessed per policy, unexpired, not revoked.
    Valid,
    /// Recomputed ACDC SAID did not match the embedded one.
    SaidMismatch,
    /// Attributes failed schema validation, or schema SAID is not the pinned one.
    SchemaInvalid,
    /// The issuance was unanchored or the issuer signature did not verify.
    IssuerSignatureInvalid,
    /// The registry (`vcp`) was never anchored in the issuer KEL.
    RegistryNotEstablished,
    /// A qualifying revocation is anchored at/before the presentation; see `revoked_at`.
    CredentialRevoked,
    /// The credential expired; see `expired_at`.
    Expired,
    /// A lifecycle anchor missed witness quorum under `RequireWitnesses`.
    WitnessQuorumNotMet,
    /// The issuer KEL forks (fail-closed).
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
#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct CredentialReport {
    /// The discriminated status.
    #[pyo3(get)]
    pub status: CredentialStatus,
    /// Issuer AID — present on `VALID`.
    #[pyo3(get)]
    pub issuer: Option<String>,
    /// Subject (holder) AID — present on `VALID`.
    #[pyo3(get)]
    pub subject: Option<String>,
    /// Granted capabilities — present on `VALID`. Never silently dropped (fn-153.2).
    #[pyo3(get)]
    pub caps: Option<Vec<String>>,
    /// The KEL position the verdict is as-of — present on `VALID`.
    #[pyo3(get)]
    pub as_of: Option<u64>,
    /// The KEL position a revocation was anchored at — present on `CREDENTIAL_REVOKED`.
    #[pyo3(get)]
    pub revoked_at: Option<u64>,
    /// The expiry instant — present on `EXPIRED`.
    #[pyo3(get)]
    pub expired_at: Option<String>,
    /// Failure detail — present on `MALFORMED_REQUEST`.
    #[pyo3(get)]
    pub message: Option<String>,
    /// The offending request field — present on `INPUT_TOO_LARGE`.
    #[pyo3(get)]
    pub field: Option<String>,
}

#[pymethods]
impl CredentialReport {
    fn __repr__(&self) -> String {
        format!("CredentialReport(status={:?})", self.status)
    }
}

/// A typed presentation verdict report (holder-binding outcome).
#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PresentationReport {
    /// The discriminated status.
    #[pyo3(get)]
    pub status: PresentationStatus,
    /// Issuer AID — present on `VALID`.
    #[pyo3(get)]
    pub issuer: Option<String>,
    /// Subject (holder) AID whose current key signed — present on `VALID`.
    #[pyo3(get)]
    pub subject: Option<String>,
    /// Granted capabilities — present on `VALID`. Never silently dropped (fn-153.2).
    #[pyo3(get)]
    pub caps: Option<Vec<String>>,
    /// Optional informational role claim — present on `VALID`.
    #[pyo3(get)]
    pub role: Option<String>,
    /// Optional credential expiry — present on `VALID`.
    #[pyo3(get)]
    pub expires_at: Option<String>,
    /// The nested credential verdict — present on `CREDENTIAL_NOT_VALID`.
    #[pyo3(get)]
    pub credential: Option<CredentialReport>,
    /// Failure detail — present on `MALFORMED_REQUEST`.
    #[pyo3(get)]
    pub message: Option<String>,
    /// The offending request field — present on `INPUT_TOO_LARGE`.
    #[pyo3(get)]
    pub field: Option<String>,
}

#[pymethods]
impl PresentationReport {
    fn __repr__(&self) -> String {
        format!("PresentationReport(status={:?})", self.status)
    }
}

/// Verify a credential **presentation** from a bundled JSON request, returning a typed report.
///
/// The request is the fn-153.3 `VerifyPresentationRequest` bundle (keys CESR-tagged inside).
/// Denials and malformed input are returned as a `status`, not raised.
///
/// Args:
/// * `request_json`: A `VerifyPresentationRequest` JSON document.
///
/// Usage:
/// ```ignore
/// from auths import verify_presentation, PresentationStatus
/// report = verify_presentation(bundle_json)
/// if report.status is not PresentationStatus.VALID:
///     raise UnverifiedPresentation(report.status)
/// ```
#[pyfunction]
pub fn verify_presentation(request_json: String) -> PresentationReport {
    let verdict = auths_verifier::contract::verify_presentation_json(&request_json);
    presentation_report(&parse_verdict(&verdict))
}

/// Verify an issued **credential** from a bundled JSON request, returning a typed report.
///
/// Args:
/// * `request_json`: A `VerifyCredentialRequest` JSON document.
///
/// Usage:
/// ```ignore
/// from auths import verify_credential, CredentialStatus
/// report = verify_credential(bundle_json)
/// if report.status is CredentialStatus.CREDENTIAL_REVOKED:
///     print(report.revoked_at)
/// ```
#[pyfunction]
pub fn verify_credential(request_json: String) -> CredentialReport {
    let verdict = auths_verifier::contract::verify_credential_json(&request_json);
    credential_report(&parse_verdict(&verdict))
}

/// Parse the contract's verdict JSON, falling back to `Null` if (impossibly) malformed.
fn parse_verdict(verdict_json: &str) -> Value {
    serde_json::from_str(verdict_json).unwrap_or(Value::Null)
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn u64_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn caps_field(value: &Value) -> Option<Vec<String>> {
    value.get("caps").and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect()
    })
}

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
        as_of: u64_field(value, "asOf"),
        revoked_at: u64_field(value, "revokedAt"),
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
