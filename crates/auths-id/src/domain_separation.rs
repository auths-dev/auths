//! HKDF info labels and signature-context tags used by the auths-id
//! crate. Mirrors the shape of `auths_pairing_protocol::domain_separation`
//! but scoped to identity-level constructions.
//!
//! Each crate owns the labels it uses — `auths-id` does not (and
//! must not) depend on `auths-pairing-protocol`, so its domain-
//! separation constants cannot live there. Globally-unambiguous
//! naming (`auths-revocation-*`, `auths-pairing-*`, `auths-daemon-*`)
//! avoids the need for a shared registry crate.
//!
//! # Invariants
//!
//! Every byte string here is NORMATIVE. Changing any byte invalidates
//! every signature / key ever produced under that label; a change
//! requires a NEW label (e.g. `…-v2`), not an edit.

/// Canonical context byte string for revocations created at the
/// moment of revocation (controller signs "now please revoke X").
pub const REVOCATION_LIVE_CONTEXT: &[u8] = b"auths-revocation-v1";

/// Canonical context byte string for revocations PRE-signed at
/// pair time and held by the controller for emergency use. The
/// distinct label prevents a pre-signed revocation from being
/// replayed in a live-revocation context (or vice versa) even
/// though the signing key is the same controller identity.
pub const REVOCATION_PRESIGNED_CONTEXT: &[u8] = b"auths-revocation-presigned-v1";
