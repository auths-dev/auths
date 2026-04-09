//! CI environment detection types.
//!
//! Lightweight types for identifying CI platforms during identity initialization.
//! No signing, no tokens, no key material.

pub mod environment;
pub mod types;

pub use environment::map_ci_environment;
pub use types::{CiEnvironment, CiIdentityConfig};
