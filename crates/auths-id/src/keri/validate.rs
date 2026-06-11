//! KEL validation re-exported from auths-keri.
//!
//! `validate_kel` is a thin LOCAL wrapper, not a bare re-export: auths-id is the
//! trusted-local boundary — it owns and reads the local identity registry — so it
//! legitimately mints a [`TrustedKel`] to drive auths-keri's structural replay,
//! which is `pub(crate)` there (RT-002 / #263). Untrusted input never reaches this
//! path; bundles, `--remote`/`--oobi`, and WASM authenticate through
//! `auths_keri::validate_signed_kel` instead.
use auths_keri::{Event, KeyState, TrustedKel};

pub use auths_keri::{
    ValidationError, compute_event_said, finalize_dip_event, finalize_drt_event,
    finalize_icp_event, find_seal_in_kel, parse_kel_json, serialize_for_signing,
    validate_delegation, validate_for_append, verify_event_crypto, verify_event_said,
};

/// Replay a KEL read from the local (trusted) registry to its [`KeyState`].
///
/// auths-id reads only its own identity store, so the events are trusted; this
/// asserts that by minting a [`TrustedKel`] over auths-keri's `pub(crate)`
/// structural replay. Untrusted input (bundles, remote/oobi, WASM) must instead go
/// through `auths_keri::validate_signed_kel`.
///
/// Args:
/// * `events`: A KEL from the local identity store, oldest first.
pub fn validate_kel(events: &[Event]) -> Result<KeyState, ValidationError> {
    TrustedKel::from_trusted_source(events).replay()
}
