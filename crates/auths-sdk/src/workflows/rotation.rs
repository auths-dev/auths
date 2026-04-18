//! Re-exports from [`crate::domains::identity::rotation`].
//!
//! All rotation logic lives in `domains::identity::rotation`. This module
//! exists only to keep existing `use auths_sdk::workflows::rotation::*`
//! imports working across CLI and other crates.

pub use crate::domains::identity::rotation::*;
