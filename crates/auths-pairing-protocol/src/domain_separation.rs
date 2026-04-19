//! HKDF `info` registry for the pairing protocol (fn-129.T3).
//!
//! Single source of truth for every domain-separating byte string used as
//! an HKDF `info` input in this crate. Moved out of bare byte literals at
//! call sites so an audit can enumerate them in one place.
//!
//! # Invariants
//!
//! - These byte strings are NORMATIVE. Changing any byte invalidates every
//!   derived key produced under the old label. A change requires a new
//!   label (e.g. `…-v2`), not an edit to an existing one.
//! - Every caller MUST use these constants; no bare byte literals at
//!   derivation sites. The compile-time tests in `tests/cases/domain_separation.rs`
//!   pin the bytes and fail CI if they drift.
//! - Naming convention: `auths-pairing-<purpose>-v<n>`. Sticking to this
//!   shape keeps collisions with other crates in the workspace impossible
//!   (they use `auths-daemon-*`, `auths-revocation-*`, etc.).
//!
//! # Adding a new label
//!
//! 1. Add a `pub const <PURPOSE>_INFO: &[u8] = b"auths-pairing-<purpose>-v1";`.
//! 2. Use the constant at the HKDF call site.
//! 3. Add a snapshot test in `tests/cases/domain_separation.rs`.
//! 4. Regenerate any affected golden vectors.

/// SAS derivation label. Binds the shared ECDH secret + ephemeral pubkeys +
/// session id + short code into the 8-byte (T5: 10-byte) Short
/// Authentication String.
pub const SAS_INFO: &[u8] = b"auths-pairing-sas-v1";

/// Transport key derivation label. Produces a fresh 32-byte symmetric key
/// for wrapping session payloads (ChaCha20-Poly1305 under default build,
/// AES-256-GCM under `--features cnsa`).
pub const TRANSPORT_INFO: &[u8] = b"auths-pairing-transport-v1";

/// `SecureEnvelope` key derivation label (fn-129.T7). Derives a fresh
/// envelope key from the `TransportKey` via HKDF so that envelope
/// ciphertexts use key material distinct from the transport layer's
/// bulk-encryption key.
pub const ENVELOPE_INFO: &[u8] = b"auths-pairing-envelope-v1";

/// Hybrid `(P-256 || ML-KEM-768)` transport-key derivation label (fn-129.T10).
///
/// Distinct from `TRANSPORT_INFO` so the classical-only path and the
/// hybrid path never share a derived key even when all other inputs are
/// identical. Activated only under the `pq-hybrid` Cargo feature; on
/// default builds the label is present but unused, and the constant
/// stays pinned here so cross-build wire stability is visible in one file.
///
/// The `v1` suffix is the hybrid-construction version. Any change to the
/// combiner order (classical-first `ss_c || ss_p` per NIST SP 800-227 §4.6)
/// or to the underlying KEM parameter set requires a `v2` label and a
/// parallel migration of any persisted keys.
pub const TRANSPORT_HYBRID_INFO: &[u8] = b"auths-pairing-transport-hybrid-v1";
