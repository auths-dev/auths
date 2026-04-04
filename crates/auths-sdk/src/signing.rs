//! Re-exports from the signing domain for backwards compatibility.

pub use crate::domains::signing::service::{
    ArtifactSigningError, ArtifactSigningParams, ArtifactSigningResult, SigningConfig,
    SigningError, SigningKeyMaterial, construct_signature_payload, sign_artifact,
    sign_artifact_raw, sign_with_seed, validate_commit_sha, validate_freeze_state,
};
