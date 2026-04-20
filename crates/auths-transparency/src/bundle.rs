use auths_verifier::{DeviceDID, IdentityDID, Role};
use serde::{Deserialize, Serialize};

use crate::checkpoint::SignedCheckpoint;
use crate::entry::{Entry, EntryType};
use crate::proof::InclusionProof;

/// An offline verification bundle containing an entry, its inclusion proof,
/// and a signed checkpoint.
///
/// Allows clients to verify that an entry was logged without contacting the
/// transparency log server.
///
/// Args:
/// * `entry` — The log entry being proven.
/// * `inclusion_proof` — Merkle proof that the entry is included in the log.
/// * `signed_checkpoint` — Signed checkpoint attesting to the log state.
/// * `delegation_chain` — Optional chain of delegation links.
///
/// Usage:
/// ```ignore
/// let bundle = OfflineBundle {
///     entry,
///     inclusion_proof: proof,
///     signed_checkpoint: checkpoint,
///     delegation_chain: vec![],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct OfflineBundle {
    pub entry: Entry,
    pub inclusion_proof: InclusionProof,
    pub signed_checkpoint: SignedCheckpoint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<DelegationChainLink>,
}

/// A single link in a delegation chain, containing the logged entry
/// and its Merkle inclusion proof.
///
/// Each link proves that a delegation event (e.g., org member add) was
/// recorded in the transparency log.
///
/// Args:
/// * `link_type` — The type of delegation event this link represents.
/// * `entry` — The full log entry for the delegation event.
/// * `inclusion_proof` — Merkle proof that the entry is included in the log.
///
/// Usage:
/// ```ignore
/// let link = DelegationChainLink {
///     link_type: EntryType::OrgMemberAdd,
///     entry,
///     inclusion_proof: proof,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct DelegationChainLink {
    pub link_type: EntryType,
    pub entry: Entry,
    pub inclusion_proof: InclusionProof,
}

/// Result of verifying an [`OfflineBundle`].
///
/// Reports the outcome of each verification dimension independently,
/// allowing consumers to make nuanced trust decisions.
///
/// Args:
/// * `signature` — Whether the entry's actor signature verified.
/// * `inclusion` — Whether the Merkle inclusion proof verified.
/// * `checkpoint` — Whether the signed checkpoint verified.
/// * `witnesses` — Witness cosignature quorum status.
/// * `namespace` — Whether the actor is authorized for the namespace.
/// * `delegation` — Delegation chain verification status.
/// * `warnings` — Non-fatal issues encountered during verification.
///
/// Usage:
/// ```ignore
/// let report = BundleVerificationReport {
///     signature: SignatureStatus::Verified,
///     inclusion: InclusionStatus::Verified,
///     checkpoint: CheckpointStatus::Verified,
///     witnesses: WitnessStatus::NotProvided,
///     namespace: NamespaceStatus::Authorized,
///     delegation: DelegationStatus::NoDelegationData,
///     warnings: vec![],
/// };
/// assert!(report.is_valid());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct BundleVerificationReport {
    pub signature: SignatureStatus,
    pub inclusion: InclusionStatus,
    pub checkpoint: CheckpointStatus,
    pub witnesses: WitnessStatus,
    pub namespace: NamespaceStatus,
    pub delegation: DelegationStatus,
    pub warnings: Vec<String>,
}

impl BundleVerificationReport {
    /// Whether the bundle passed all verification checks.
    ///
    /// Returns `true` when signature, inclusion, and checkpoint are all verified,
    /// witnesses meet quorum (or are not provided), namespace is authorized or owned,
    /// and delegation is not broken.
    ///
    /// **Trust note:** `NoDelegationData` is accepted as valid because many bundles
    /// (e.g., direct-signing, early Epic 1 bundles) lack delegation chains. This is
    /// a weaker trust signal than `ChainVerified` — callers needing full provenance
    /// should check `delegation` explicitly rather than relying solely on `is_valid()`.
    pub fn is_valid(&self) -> bool {
        let sig_ok = matches!(self.signature, SignatureStatus::Verified);
        let inc_ok = matches!(self.inclusion, InclusionStatus::Verified);
        let chk_ok = matches!(
            self.checkpoint,
            CheckpointStatus::Verified | CheckpointStatus::NotProvided
        );
        let wit_ok = matches!(
            self.witnesses,
            WitnessStatus::Quorum { .. } | WitnessStatus::NotProvided
        );
        let ns_ok = matches!(
            self.namespace,
            NamespaceStatus::Authorized | NamespaceStatus::Owned
        );
        let del_ok = !matches!(self.delegation, DelegationStatus::ChainBroken { .. });

        sig_ok && inc_ok && chk_ok && wit_ok && ns_ok && del_ok
    }
}

/// Outcome of verifying the entry's actor signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignatureStatus {
    /// The signature verified against the actor's public key.
    Verified,
    /// The signature did not verify.
    Failed {
        /// Description of the failure.
        reason: String,
    },
    /// No signature data was available for verification.
    NotProvided,
}

/// Outcome of verifying the Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum InclusionStatus {
    /// The inclusion proof verified against the checkpoint root.
    Verified,
    /// The inclusion proof did not verify.
    Failed {
        /// Description of the failure.
        reason: String,
    },
    /// No inclusion proof was available for verification.
    NotProvided,
}

/// Outcome of verifying the signed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckpointStatus {
    /// The checkpoint signature verified against the log's public key.
    Verified,
    /// The checkpoint signature did not verify.
    InvalidSignature,
    /// The trust config declared `EcdsaP256` but the checkpoint did not
    /// carry the ECDSA signature bytes. Distinct from `InvalidSignature`
    /// so operators can tell a protocol mis-configuration apart from a
    /// crypto failure.
    MissingEcdsaSignature,
    /// The trust config declared `EcdsaP256` but the checkpoint did not
    /// carry the ECDSA public-key bytes.
    MissingEcdsaKey,
    /// No checkpoint was available for verification.
    NotProvided,
}

/// Outcome of verifying witness cosignatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum WitnessStatus {
    /// Witness quorum was met.
    Quorum {
        /// Number of witnesses that verified.
        verified: usize,
        /// Number of witnesses required for quorum.
        required: usize,
    },
    /// Witness quorum was not met.
    Insufficient {
        /// Number of witnesses that verified.
        verified: usize,
        /// Number of witnesses required for quorum.
        required: usize,
    },
    /// No witness data was available for verification.
    NotProvided,
}

/// Outcome of verifying the actor's namespace authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum NamespaceStatus {
    /// The actor is authorized for the namespace via delegation.
    Authorized,
    /// The actor owns the namespace directly.
    Owned,
    /// The namespace has no owner on record.
    Unowned,
    /// The actor is not authorized for the namespace.
    Unauthorized,
}

/// Outcome of verifying the delegation chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DelegationStatus {
    /// The actor signed directly (no delegation needed).
    Direct,
    /// The delegation chain verified successfully.
    ChainVerified {
        /// The organization identity that issued the delegation.
        org_did: IdentityDID,
        /// The member identity that received the delegation.
        member_did: IdentityDID,
        /// The role granted to the member.
        member_role: Role,
        /// The device that performed the action on behalf of the member.
        device_did: DeviceDID,
    },
    /// The delegation chain could not be verified.
    ChainBroken {
        /// Description of why the chain is broken.
        reason: String,
    },
    /// No delegation data was present in the bundle.
    NoDelegationData,
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn signature_status_serializes() {
        let status = SignatureStatus::Verified;
        let json = serde_json::to_string(&status).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "verified");
    }

    #[test]
    fn witness_status_quorum_serializes() {
        let status = WitnessStatus::Quorum {
            verified: 3,
            required: 2,
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "quorum");
        assert_eq!(parsed["verified"], 3);
        assert_eq!(parsed["required"], 2);
    }

    #[test]
    fn witness_status_insufficient_serializes() {
        let status = WitnessStatus::Insufficient {
            verified: 1,
            required: 3,
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "insufficient");
        assert_eq!(parsed["verified"], 1);
        assert_eq!(parsed["required"], 3);
    }

    #[test]
    fn report_is_valid_all_verified() {
        let report = BundleVerificationReport {
            signature: SignatureStatus::Verified,
            inclusion: InclusionStatus::Verified,
            checkpoint: CheckpointStatus::Verified,
            witnesses: WitnessStatus::Quorum {
                verified: 2,
                required: 2,
            },
            namespace: NamespaceStatus::Authorized,
            delegation: DelegationStatus::Direct,
            warnings: vec![],
        };
        assert!(report.is_valid());
    }

    #[test]
    fn report_is_valid_with_not_provided_optionals() {
        let report = BundleVerificationReport {
            signature: SignatureStatus::Verified,
            inclusion: InclusionStatus::Verified,
            checkpoint: CheckpointStatus::NotProvided,
            witnesses: WitnessStatus::NotProvided,
            namespace: NamespaceStatus::Owned,
            delegation: DelegationStatus::NoDelegationData,
            warnings: vec![],
        };
        assert!(report.is_valid());
    }

    #[test]
    fn report_invalid_on_failed_signature() {
        let report = BundleVerificationReport {
            signature: SignatureStatus::Failed {
                reason: "bad sig".into(),
            },
            inclusion: InclusionStatus::Verified,
            checkpoint: CheckpointStatus::Verified,
            witnesses: WitnessStatus::NotProvided,
            namespace: NamespaceStatus::Authorized,
            delegation: DelegationStatus::Direct,
            warnings: vec![],
        };
        assert!(!report.is_valid());
    }

    #[test]
    fn report_invalid_on_broken_delegation() {
        let report = BundleVerificationReport {
            signature: SignatureStatus::Verified,
            inclusion: InclusionStatus::Verified,
            checkpoint: CheckpointStatus::Verified,
            witnesses: WitnessStatus::NotProvided,
            namespace: NamespaceStatus::Authorized,
            delegation: DelegationStatus::ChainBroken {
                reason: "missing link".into(),
            },
            warnings: vec![],
        };
        assert!(!report.is_valid());
    }

    #[test]
    fn delegation_status_chain_verified_serializes() {
        let status = DelegationStatus::ChainVerified {
            org_did: IdentityDID::new_unchecked("did:keri:EOrg123"),
            member_did: IdentityDID::new_unchecked("did:keri:EMember456"),
            member_role: Role::Admin,
            device_did: DeviceDID::new_unchecked("did:key:z6MkDevice789"),
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "chain_verified");
        assert_eq!(parsed["org_did"], "did:keri:EOrg123");
        assert_eq!(parsed["member_did"], "did:keri:EMember456");
    }
}
