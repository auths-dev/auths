//! Canonical-JSON signature suites — the in-band, curve-tagged suite identifier
//! self-contained signed documents carry (`"json-canon/p256"`), per the
//! wire-format curve-tagging rule: every signature on a wire names its curve
//! in-band, and this module is the one sanctioned home for that mapping.

use crate::CurveType;

/// A canonical-JSON (RFC-8785) signature suite, curve-tagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureSuite {
    /// RFC-8785 canonical JSON, ECDSA P-256 — the project default.
    P256,
    /// RFC-8785 canonical JSON, Ed25519.
    Ed25519,
}

impl SignatureSuite {
    /// The in-band wire string.
    ///
    /// Usage:
    /// ```ignore
    /// assert_eq!(SignatureSuite::P256.as_str(), "json-canon/p256");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureSuite::P256 => "json-canon/p256",
            SignatureSuite::Ed25519 => "json-canon/ed25519",
        }
    }

    /// Parse the wire string; `None` for an unknown suite (callers fail closed).
    ///
    /// Args:
    /// * `raw`: the in-band suite string.
    ///
    /// Usage:
    /// ```ignore
    /// let suite = SignatureSuite::parse(&doc.suite).ok_or(UnknownSuite)?;
    /// ```
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "json-canon/p256" => Some(SignatureSuite::P256),
            "json-canon/ed25519" => Some(SignatureSuite::Ed25519),
            _ => None,
        }
    }

    /// The suite's curve.
    pub fn curve(&self) -> CurveType {
        match self {
            SignatureSuite::P256 => CurveType::P256,
            SignatureSuite::Ed25519 => CurveType::Ed25519,
        }
    }
}
