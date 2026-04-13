//! fn-114.20 / Acceptance #7: the duplicate `verify_with_resolver` entry point
//! was deleted. The single verifier path in the workspace is
//! `auths_verifier::verify_with_keys`. Callers resolve the issuer DID first
//! (via `DidResolver`) and pass the typed key directly.
//!
//! Caller migration pattern:
//!
//! ```ignore
//! let resolved = resolver.resolve(&att.issuer)?;
//! let issuer_pk = auths_verifier::decode_public_key_bytes(&resolved.public_key_bytes())?;
//! auths_verifier::verify_with_keys(&att, &issuer_pk).await?;
//! // Optional max_age check:
//! if let Some(max) = max_age
//!     && let Some(ts) = att.timestamp
//!     && (now - ts) > max
//! {
//!     return Err(AttestationError::AttestationTooOld { .. });
//! }
//! ```
//!
//! This module remains as a documentation stop — the original body was removed
//! in fn-114.20 per the epic's single-verifier invariant.
