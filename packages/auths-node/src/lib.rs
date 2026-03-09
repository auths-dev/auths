#![deny(clippy::all)]

pub mod error;
pub mod helpers;
pub mod types;

use napi_derive::napi;

#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
