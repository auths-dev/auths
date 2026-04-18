//! Re-exports from [`crate::domains::org::service`].
//!
//! All org workflow logic lives in `domains::org::service`. This module
//! exists only to keep existing `use auths_sdk::workflows::org::*` imports
//! working across CLI, Node, and Python crates.

pub use crate::domains::org::service::*;
