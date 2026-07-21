//! Release attestations anchored in the org KEL — the signing position as log
//! fact, not caller assertion.
//!
//! At signing time the org anchors a [`ReleaseAttestation`] (artifact digest +
//! signer) in its KEL via the standard ixn seal ([`try_stage_anchor`]) and
//! stores the canonical blob content-addressed by its SAID — one atomic commit,
//! so a crash can never leave a dangling seal or an orphaned blob. At report
//! time [`discover_releases`] walks the org KEL's anchors, resolves each SAID
//! back to its blob, and parses only the blobs that are release attestations —
//! every discovered row's `signed_at` **is** the anchoring KEL position, so the
//! evidence pack derives "what the log proves it shipped" instead of trusting a
//! caller-supplied list.

use std::sync::Arc;

use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::KeyAlias;
use auths_id::attestation::enriched::canonical_said;
use auths_id::keri::types::{Prefix, Said};
use auths_id::keri::{resolve_anchored_saids_via_backend, try_stage_anchor};
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::registry::backend::AtomicWriteBatch;
use serde::{Deserialize, Serialize};

use crate::context::AuthsContext;
use crate::domains::compliance::query::{ComplianceQueryError, ReleaseRecord};

/// A parsed `sha256:<64 lowercase hex>` artifact digest. Construction goes
/// through [`ArtifactDigest::parse`]; a malformed digest is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ArtifactDigest(String);

impl ArtifactDigest {
    /// Parse a `sha256:<64 hex>` digest, normalizing hex to lowercase.
    pub fn parse(s: &str) -> Result<Self, ComplianceQueryError> {
        let hex = s.strip_prefix("sha256:").ok_or_else(|| {
            ComplianceQueryError::InvalidRelease(format!(
                "artifact digest must start with 'sha256:' (got '{s}')"
            ))
        })?;
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ComplianceQueryError::InvalidRelease(format!(
                "artifact digest must be 64 hex characters after 'sha256:' (got {} chars)",
                hex.len()
            )));
        }
        Ok(Self(format!("sha256:{}", hex.to_ascii_lowercase())))
    }

    /// The canonical `sha256:<hex>` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the canonical `sha256:<hex>` string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<String> for ArtifactDigest {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s).map_err(|e| e.to_string())
    }
}

impl From<ArtifactDigest> for String {
    fn from(d: ArtifactDigest) -> Self {
        d.0
    }
}

impl std::fmt::Display for ArtifactDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Schema discriminator for [`ReleaseAttestation`]. Parsing any other anchored
/// blob (membership attestation, ACDC credential, …) fails here, so discovery
/// can never mistake a foreign blob for a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReleaseAttestationKind {
    /// Version 1 org release attestation.
    #[serde(rename = "auths/org-release/v1")]
    OrgReleaseV1,
}

/// The release fact the org anchors in its KEL at signing time: which artifact,
/// signed by which member. The anchoring ixn's sequence number — not any field
/// in here — is the release's signing position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAttestation {
    /// Schema discriminator (always `auths/org-release/v1`).
    pub kind: ReleaseAttestationKind,
    /// The artifact content digest.
    pub artifact_digest: ArtifactDigest,
    /// The signing member's KEL prefix.
    pub signer: Prefix,
}

impl ReleaseAttestation {
    /// Parse a stored blob back into a release attestation. Non-release blobs
    /// (wrong/missing `kind`, unknown fields) fail closed.
    pub fn parse(bytes: &[u8]) -> Result<Self, ComplianceQueryError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ComplianceQueryError::InvalidRelease(e.to_string()))
    }
}

/// A release attestation that is anchored in the org KEL: the proof-carrying
/// result of [`attest_release`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchoredRelease {
    /// The artifact content digest.
    pub artifact_digest: ArtifactDigest,
    /// The signing member's KEL prefix.
    pub signer: Prefix,
    /// The org-KEL position of the anchoring ixn — the release's signing
    /// position, derived from the log, never caller input.
    pub signed_at: u128,
    /// The SAID of the anchored attestation (the ixn's seal digest).
    pub attestation_said: Said,
}

/// Anchor a release attestation in the org KEL at signing time.
///
/// Builds the canonical [`ReleaseAttestation`], seals its SAID into a new org
/// ixn event, and stores the blob content-addressed by that SAID — all staged
/// into one atomic registry commit. The returned `signed_at` is the ixn's KEL
/// position; [`discover_releases`] re-derives exactly this value at report
/// time.
///
/// Args:
/// * `ctx`: Auths context (registry, key storage, passphrase provider).
/// * `org_prefix`: The org's KEL prefix (the controller that signs the ixn).
/// * `org_alias`: Keychain alias of the org's signing key.
/// * `artifact_digest`: The parsed artifact digest.
/// * `signer`: The signing member's KEL prefix.
///
/// Usage:
/// ```ignore
/// let anchored = attest_release(&ctx, &org_prefix, &org_alias, digest, member)?;
/// println!("anchored at org KEL seq {}", anchored.signed_at);
/// ```
pub fn attest_release(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    org_alias: &KeyAlias,
    artifact_digest: ArtifactDigest,
    signer: Prefix,
) -> Result<AnchoredRelease, ComplianceQueryError> {
    let attestation = ReleaseAttestation {
        kind: ReleaseAttestationKind::OrgReleaseV1,
        artifact_digest,
        signer,
    };
    let canonical = json_canon::to_string(&attestation)
        .map_err(|e| ComplianceQueryError::Canonicalize(e.to_string()))?;

    let org_signer = StorageSigner::new(Arc::clone(&ctx.key_storage));
    let mut batch = AtomicWriteBatch::new();
    let (attestation_said, ixn, _attachment) = try_stage_anchor(
        ctx.registry.as_ref(),
        &org_signer,
        org_alias,
        ctx.passphrase_provider.as_ref(),
        org_prefix,
        &attestation,
        &mut batch,
    )?;
    batch.stage_credential(
        org_prefix.clone(),
        attestation_said.clone(),
        canonical.into_bytes(),
    );
    ctx.registry
        .commit_batch(&batch)
        .map_err(|e| ComplianceQueryError::Registry(e.to_string()))?;

    Ok(AnchoredRelease {
        artifact_digest: attestation.artifact_digest,
        signer: attestation.signer,
        signed_at: ixn.s.value(),
        attestation_said,
    })
}

/// Discover the org's releases from its own KEL anchors.
///
/// Walks every ixn digest seal in the org KEL, resolves each SAID to its
/// content-addressed blob, and keeps exactly the blobs that parse as
/// [`ReleaseAttestation`]s — anchors for other facts (membership, device links)
/// are skipped because their blobs are absent or fail the `kind` parse. Each
/// returned row's `signed_at` is the anchoring KEL position. A blob that parses
/// as a release but does not hash back to its seal digest is registry
/// corruption and fails closed.
///
/// Args:
/// * `backend`: The org's registry backend.
/// * `org_prefix`: The org's KEL prefix.
///
/// Usage:
/// ```ignore
/// let records = discover_releases(ctx.registry.as_ref(), &org_prefix)?;
/// let pack = build_evidence_pack(&ctx, org, &org_prefix, period, fw, &records, &policy, now)?;
/// ```
pub fn discover_releases(
    backend: &dyn RegistryBackend,
    org_prefix: &Prefix,
) -> Result<Vec<ReleaseRecord>, ComplianceQueryError> {
    let anchored = resolve_anchored_saids_via_backend(backend, org_prefix, None)?;

    let mut records = Vec::new();
    for (seq, said) in anchored {
        let Some(bytes) = backend
            .load_credential(org_prefix, &said)
            .map_err(|e| ComplianceQueryError::Registry(e.to_string()))?
        else {
            continue; // anchor for some other fact — no content-addressed blob
        };
        let Ok(attestation) = ReleaseAttestation::parse(&bytes) else {
            continue; // a credential of another kind shares the store — skip
        };
        // The blob must hash back to the seal digest that anchors it.
        if canonical_said(&attestation).as_ref() != Some(&said) {
            return Err(ComplianceQueryError::TamperedRelease(
                said.as_str().to_string(),
            ));
        }
        records.push(ReleaseRecord {
            artifact_digest: attestation.artifact_digest.into_inner(),
            signer_prefix: attestation.signer,
            signed_at: Some(seq),
            transparency: None,
        });
    }
    Ok(records)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const HEX64: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn artifact_digest_parses_and_normalizes() {
        let upper = format!("sha256:{}", HEX64.to_ascii_uppercase());
        let d = ArtifactDigest::parse(&upper).unwrap();
        assert_eq!(d.as_str(), format!("sha256:{HEX64}"));
    }

    #[test]
    fn artifact_digest_rejects_malformed_input() {
        for bad in [
            "aaaa",
            "sha256:",
            "sha256:zz",
            "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(
                ArtifactDigest::parse(bad).is_err(),
                "'{bad}' must be rejected"
            );
        }
    }

    #[test]
    fn release_attestation_round_trips_canonically() {
        let att = ReleaseAttestation {
            kind: ReleaseAttestationKind::OrgReleaseV1,
            artifact_digest: ArtifactDigest::parse(&format!("sha256:{HEX64}")).unwrap(),
            signer: Prefix::new_unchecked("EMember".to_string()),
        };
        let canonical = json_canon::to_string(&att).unwrap();
        let back = ReleaseAttestation::parse(canonical.as_bytes()).unwrap();
        assert_eq!(att, back);
        assert_eq!(canonical, json_canon::to_string(&back).unwrap());
    }

    #[test]
    fn parse_rejects_foreign_blobs() {
        // Wrong kind tag.
        let wrong_kind = format!(
            r#"{{"kind":"auths/device-link/v1","artifact_digest":"sha256:{HEX64}","signer":"EMember"}}"#
        );
        assert!(ReleaseAttestation::parse(wrong_kind.as_bytes()).is_err());

        // A membership-attestation-shaped blob (no kind at all).
        let foreign = br#"{"subject":"did:keri:EMember","org_role":"member"}"#;
        assert!(ReleaseAttestation::parse(foreign).is_err());

        // Unknown extra fields fail closed.
        let extra = format!(
            r#"{{"kind":"auths/org-release/v1","artifact_digest":"sha256:{HEX64}","signer":"EMember","x":1}}"#
        );
        assert!(ReleaseAttestation::parse(extra.as_bytes()).is_err());
    }
}
