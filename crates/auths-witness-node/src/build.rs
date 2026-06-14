//! The proof a node serves of which binary it runs — the operator-facing seam.
//!
//! A witness operator is vouching for the network; an operator must in turn be
//! *vouchable* — a relying party has to be able to confirm the node runs the
//! binary the platform shipped, not a silently-swapped one. This module owns the
//! operator-facing artifact that makes that confirmable: the node's
//! self-measurement of its own binary, paired with the signed build attestation
//! the operator produced over the released binary (`auths artifact sign`).
//!
//! It owns no protocol. The decision — does the attestation's signature hold,
//! and does it attest the digest the node measured of itself? — is made by the
//! platform verifier ([`auths_verifier::verify_build_attestation_offline`]),
//! composed here. The node crate only frames the served artifact and renders the
//! verdict an operator reads.

use auths_verifier::OfflineBuildVerdict;
use auths_verifier::core::Attestation;
use serde::{Deserialize, Serialize};

/// The `/build` document a node serves: its own measurement of the binary it
/// runs, paired with the signed attestation that vouches for it.
///
/// Parse-don't-validate: a returned `BuildAttestation` is fully formed (the
/// `attestation` parsed into the verifier's [`Attestation`] type), so nothing
/// downstream re-checks its shape — `verify` only decides the *trust* question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAttestation {
    /// Version string the running binary reports.
    pub version: String,
    /// SHA-256 (hex) the node measured of its own on-disk binary at startup.
    pub running_digest: String,
    /// The signed build attestation (`auths artifact sign` output) the operator
    /// produced over the released binary.
    pub attestation: Attestation,
}

/// What an operator (or any relying party) learns from checking a node's build
/// proof. `Trusted` is the only arm that means "this node provably runs the
/// attested binary"; every other arm names exactly what went wrong, so a forged
/// or unprovable build can never be read as a trusted one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeBuildVerdict {
    /// The node provably runs the attested binary: the attestation's signature
    /// holds and attests the very digest the node measured of itself.
    Trusted {
        /// The version the node reported.
        version: String,
        /// The digest both attested and self-measured (they agree).
        digest: String,
    },
    /// The attestation could not be interpreted as a signed build attestation.
    Unreadable {
        /// Why the attestation could not be read.
        reason: String,
    },
    /// The attestation's signature does not verify — altered, or not produced by
    /// its claimed signer.
    SignatureFailed {
        /// The issuer the signature was checked against.
        issuer: String,
    },
    /// The signature is valid but the attestation attests a DIFFERENT binary
    /// than the one running — a forged or mismatched attestation.
    DigestMismatch {
        /// The digest the attestation attests.
        attested: String,
        /// The digest the node measured of its running binary.
        running: String,
    },
}

impl NodeBuildVerdict {
    /// Whether the node provably runs the attested binary (the only trusted arm).
    pub fn is_trusted(&self) -> bool {
        matches!(self, NodeBuildVerdict::Trusted { .. })
    }

    /// A single operator-facing line describing the verdict — no protocol
    /// vocabulary, just "which binary does this node run, and can we trust it".
    pub fn summary(&self) -> String {
        match self {
            NodeBuildVerdict::Trusted { version, digest } => format!(
                "build verified: this node runs {version} (digest {}), signed and matching",
                short(digest)
            ),
            NodeBuildVerdict::Unreadable { reason } => {
                format!("build not verifiable: {reason}")
            }
            NodeBuildVerdict::SignatureFailed { issuer } => format!(
                "build rejected: the build attestation's signature does not verify (signer {})",
                short(issuer)
            ),
            NodeBuildVerdict::DigestMismatch { attested, running } => format!(
                "build rejected: the attestation is for a different binary \
                 (attested {}, running {}) — this node is not running what it attests",
                short(attested),
                short(running)
            ),
        }
    }
}

/// Shorten a long hex/DID to a readable head for one-line operator output.
fn short(s: &str) -> String {
    if s.len() > 16 {
        format!("{}…", &s[..16])
    } else {
        s.to_string()
    }
}

impl BuildAttestation {
    /// Parse a build document from its served JSON, failing loudly on malformed
    /// input (parse-don't-validate).
    ///
    /// Args:
    /// * `json`: the `/build` response bytes.
    pub fn from_json(json: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(json)
    }

    /// Decide whether this node provably runs the attested binary.
    ///
    /// Composes the platform verifier: the signature is checked against the
    /// issuer's embedded key, and the attested digest is checked against the
    /// node's self-measured `running_digest`. A forged attestation (a valid
    /// signature over a different binary) lands on
    /// [`NodeBuildVerdict::DigestMismatch`], never on `Trusted`.
    pub async fn verify(&self) -> NodeBuildVerdict {
        match auths_verifier::verify_build_attestation_offline(
            &self.attestation,
            &self.running_digest,
        )
        .await
        {
            OfflineBuildVerdict::Verified { digest } => NodeBuildVerdict::Trusted {
                version: self.version.clone(),
                digest,
            },
            OfflineBuildVerdict::Unreadable { reason } => NodeBuildVerdict::Unreadable { reason },
            OfflineBuildVerdict::SignatureFailed { issuer } => {
                NodeBuildVerdict::SignatureFailed { issuer }
            }
            OfflineBuildVerdict::DigestMismatch { attested, running } => {
                NodeBuildVerdict::DigestMismatch { attested, running }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A build document whose attestation carries NO digest payload — it parses
    /// into a well-formed attestation (real key/signature shapes), but with
    /// nothing to compare against the running binary it verifies to `Unreadable`,
    /// never `Trusted`. (The signed-and-matching and forged arms are covered end
    /// to end against a real `artifact sign` output in the integration suite.)
    const NO_DIGEST_BUILD: &str = r#"{
        "version": "0.1.3",
        "running_digest": "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
        "attestation": {
            "version": 1,
            "rid": "sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
            "issuer": "did:key:zDnaev8Ae55oCNc38Ha6gFkuYGG4zxH1quDCpd5veWrQUHf8C",
            "subject": "did:key:zDnaev8Ae55oCNc38Ha6gFkuYGG4zxH1quDCpd5veWrQUHf8C",
            "device_public_key": {
                "curve": "p256",
                "key": "03b92f4329b76bec0f02c28b37e16a4fd9803129d22943ff53d5b5472f123fd349"
            },
            "device_signature": "944b5ba55f517db44abac03b27b31f4dd596e7a335af5082d09c43601ddd09565d1e3e6a1c21a28ae8ef5d1b405240ea3420f18e42a3300dade341d9a9ff767d",
            "payload": { "artifact_type": "file" }
        }
    }"#;

    #[test]
    fn parses_a_served_build_document() {
        let build = BuildAttestation::from_json(NO_DIGEST_BUILD.as_bytes()).unwrap();
        assert_eq!(build.version, "0.1.3");
        assert_eq!(
            build.running_digest,
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
        );
    }

    #[tokio::test]
    async fn a_build_with_no_attested_digest_is_not_trusted() {
        let build = BuildAttestation::from_json(NO_DIGEST_BUILD.as_bytes()).unwrap();
        let verdict = build.verify().await;
        assert!(!verdict.is_trusted());
        assert!(matches!(verdict, NodeBuildVerdict::Unreadable { .. }));
    }

    #[test]
    fn verdict_summary_carries_no_protocol_vocabulary() {
        // The operator-facing line must never leak protocol jargon — operators
        // see "which binary, and can we trust it", never the wire vocabulary.
        // Held to the one canonical rule (crate::scan_for_protocol_vocabulary),
        // not a copy maintained here.
        let verdicts = [
            NodeBuildVerdict::Trusted {
                version: "0.1.3".into(),
                digest: "7ce84d53b3b63323deadbeef".into(),
            },
            NodeBuildVerdict::DigestMismatch {
                attested: "296078e6633559c0aa".into(),
                running: "7ce84d53b3b63323bb".into(),
            },
            NodeBuildVerdict::SignatureFailed {
                issuer: "did:key:zForged".into(),
            },
            NodeBuildVerdict::Unreadable {
                reason: "no digest".into(),
            },
        ];
        for v in verdicts {
            assert_eq!(
                crate::scan_for_protocol_vocabulary(&v.summary()),
                None,
                "verdict summary leaked protocol vocabulary: {}",
                v.summary()
            );
        }
    }
}
