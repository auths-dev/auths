//! CI domain — shared types, errors, and environment detection for CI workflows.

pub mod environment;
pub mod error;
pub mod types;

pub use environment::map_ci_environment;
pub use error::CiError;
pub use types::{CiEnvironment, CiIdentityConfig};
