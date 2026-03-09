#![deny(clippy::all)]

pub mod device;
pub mod error;
pub mod helpers;
pub mod identity;
pub mod sign;
pub mod types;
pub mod verify;

use napi_derive::napi;

#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
