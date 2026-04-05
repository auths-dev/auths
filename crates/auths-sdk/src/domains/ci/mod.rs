//! CI domain — shared types, errors, and environment detection for CI workflows.

pub mod bundle;
pub mod environment;
pub mod error;
pub mod forge;
pub mod token;
pub mod types;

pub use bundle::{build_identity_bundle, generate_ci_passphrase};
pub use environment::map_ci_environment;
pub use error::CiError;
pub use forge::Forge;
pub use token::CiToken;
pub use types::{CiEnvironment, CiIdentityConfig};
