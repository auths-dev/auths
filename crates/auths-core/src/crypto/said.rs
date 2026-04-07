//! SAID (Self-Addressing Identifier) computation for KERI.
//!
//! Delegates to `auths-keri` — the single authoritative implementation.
//! This module exists for backwards-compatibility; it will be removed in Task 8.

pub use auths_keri::{compute_next_commitment, compute_said, verify_commitment};
