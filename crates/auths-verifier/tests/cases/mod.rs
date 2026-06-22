mod authorization_summary;
mod capability_fromstr;
mod commit_kel;
mod commit_verify;
mod credential;
#[cfg(feature = "ffi")]
mod cross_surface_parity;
mod did_parsing;
mod expiration_skew;
#[cfg(feature = "ffi")]
mod ffi_smoke;
mod freshness_honesty;
mod issuer_signature_required;
mod kel_verification;
mod newtypes;
#[cfg(feature = "ffi")]
mod parity_cases;
mod presentation;
mod proptest_core;
mod revocation_adversarial;
mod serialization_pinning;
mod ssh_sig;
mod verdict_typing;
