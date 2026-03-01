//! Trust policy and resolution for verifying identity root keys.
//!
//! This module provides the trust bootstrapping infrastructure that determines
//! how a verifier obtains, trusts, and updates root public keys for identities.
//!
//! ## Key Types
//!
//! - [`TrustPolicy`] - How the verifier decides to trust (TOFU vs explicit)
//! - [`KelContinuityChecker`] - Trait for verifying key rotation chains
//! - [`RotationProof`] - Evidence that a key rotation is valid
//! - [`PinnedIdentity`] - A pinned identity root with rotation context
//! - [`TrustLevel`] - How a pin was established (TOFU, Manual, OrgPolicy)
//! - [`TrustDecision`] - What the trust engine decided
//! - [`check_trust`] - Check trust for a presented identity
//! - [`resolve_trust`] - Apply policy to get final resolved key

pub mod continuity;
pub mod pinned;
pub mod policy;
pub mod resolve;
pub mod roots_file;

pub use continuity::{KelContinuityChecker, RotationProof};
pub use pinned::{PinnedIdentity, PinnedIdentityStore, TrustLevel};
pub use policy::TrustPolicy;
pub use resolve::{TrustDecision, check_trust, resolve_trust};
pub use roots_file::{RootEntry, RootsFile};
