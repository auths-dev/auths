//! Re-exports of attestation types and operations from `auths-id`.

pub use auths_id::attestation::create::create_signed_attestation;
pub use auths_id::attestation::export::AttestationSink;
pub use auths_id::attestation::group::AttestationGroup;
pub use auths_id::attestation::revoke::create_signed_revocation;
pub use auths_id::attestation::verify::verify_with_resolver;
