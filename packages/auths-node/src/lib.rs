// fn-114: crate-level allow during curve-agnostic refactor. Removed or narrowed in fn-114.40 after Phase 4 sweeps.
#![allow(clippy::disallowed_methods)]
#![deny(clippy::all)]

pub mod artifact;
pub mod attestation_query;
pub mod audit;
pub mod commit_sign;
pub mod device;
pub mod diagnostics;
pub mod error;
pub mod helpers;
pub mod identity;
pub mod org;
pub mod pairing;
pub mod policy;
pub mod sign;
pub mod trust;
pub mod types;
pub mod verify;
pub mod witness;

use napi_derive::napi;

#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
