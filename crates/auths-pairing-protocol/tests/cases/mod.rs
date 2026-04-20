//! Integration-test case submodules for `auths-pairing-protocol`.
//!
//! Subsequent fn-129 tasks add cases here:
//! - T3 → `domain_separation`
//! - T6 → `confirmation_required`, `typestate`
//! - T7 → `secure_envelope`
//! - T9 → `replay_rejected`

mod confirmation_required;
mod domain_separation;
#[cfg(feature = "pq-hybrid")]
mod pq_hybrid;
mod pq_slot_wire_compat;
mod replay_rejected;
