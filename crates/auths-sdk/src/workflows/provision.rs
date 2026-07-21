//! Re-exports from [`crate::domains::identity::provision`].
//!
//! All provisioning logic lives in `domains::identity::provision`. This module
//! exists only to keep existing `use auths_sdk::workflows::provision::*`
//! imports working across CLI and other crates.

pub use crate::domains::identity::provision::*;
