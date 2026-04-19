//! Re-exports of attestation types and operations from `auths-id`.
//!
//! fn-114.20 / Acceptance #7: `verify_with_resolver` was deleted. The single
//! verifier path is `auths_verifier::verify_with_keys`. Callers that need
//! resolver-based lookup resolve the DID first and then call verify_with_keys.

pub use auths_id::attestation::create::create_signed_attestation;
pub use auths_id::attestation::enriched::{
    EnrichedAttestation, build_anchor_set, canonical_said, enrich_all, load_enriched_attestations,
};
pub use auths_id::attestation::export::AttestationSink;
pub use auths_id::attestation::group::{AttestationGroup, EnrichedAttestationGroup};
pub use auths_id::attestation::revoke::create_signed_revocation;
