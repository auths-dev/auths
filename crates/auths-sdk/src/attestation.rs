//! Re-exports of attestation types and operations from `auths-id`.

pub use auths_id::attestation::create::{AttestationInput, create_signed_attestation};
pub use auths_id::attestation::enriched::{
    EnrichedAttestation, build_anchor_set, canonical_said, enrich_all, load_enriched_attestations,
};
pub use auths_id::attestation::export::AttestationSink;
pub use auths_id::attestation::group::{AttestationGroup, EnrichedAttestationGroup};
pub use auths_id::attestation::revoke::{RevocationInput, create_signed_revocation};
