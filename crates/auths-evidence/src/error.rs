//! Typed errors for the evidence layer. Every failure mode is a named case —
//! no `anyhow`, no stringly-typed grab-bag at the domain boundary.

use thiserror::Error;

/// Errors the evidence layer can surface. Presentation layers (CLI, HTTP, MCP)
/// map these to their own status codes; nothing here is transport-specific.
#[derive(Debug, Error)]
pub enum EvidenceError {
    /// The spend log could not be read or parsed.
    #[error("could not read the spend log: {0}")]
    SpendLog(String),

    /// The registry / KELs could not be resolved.
    #[error("could not resolve the registry: {0}")]
    Registry(String),

    /// A remote registry fetch failed (network, git, or cache I/O).
    #[error("registry fetch failed: {0}")]
    Fetch(String),

    /// The durable counter could not be located.
    #[error("could not locate the durable counter: {0}")]
    Counter(String),

    /// A treasury checkpoint trail failed verification.
    #[error("treasury checkpoint trail invalid: {0}")]
    Treasury(String),

    /// Canonicalization of a signed body failed.
    #[error("could not canonicalize: {0}")]
    Canonical(String),

    /// Signing the bundle failed.
    #[error("could not sign the bundle: {0}")]
    Signing(String),

    /// A caller-supplied input was invalid.
    #[error("invalid input: {0}")]
    Input(String),

    /// The requested call could not be located in the resolved chain.
    #[error("call not found in the resolved chain: {0}")]
    CallNotFound(String),

    /// The available anchor does not cover the requested call and the caller
    /// refused the first-seen fallback.
    #[error("the anchor head does not cover the requested call: {0}")]
    AnchorLagging(String),

    /// An embedded quorum anchor failed a specific verification leg. `code` is a
    /// stable, machine-readable identifier of which leg failed, so a relying
    /// party can gate on it (the report is the only API); `detail` is the
    /// human-readable cause.
    #[error("embedded anchor invalid ({code}): {detail}")]
    AnchorInvalid {
        /// Stable kebab-case identifier of the failed check (e.g.
        /// `anchor-required`, `chain-mismatch`, `aggregate-mismatch`,
        /// `cosignature-invalid`, `threshold-not-met`, `party-key-not-current`).
        code: &'static str,
        /// The human-readable cause.
        detail: String,
    },
}
