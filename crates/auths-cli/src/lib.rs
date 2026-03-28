// CLI is the presentation boundary — printing and exit are expected here.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::exit)]
pub mod adapters;
pub mod cli;
pub mod commands;
pub mod config;
pub mod constants;
pub mod core;
pub mod errors;
pub mod factories;
pub mod telemetry;
pub mod ux;

pub use core::pubkey_cache::{cache_pubkey, clear_cached_pubkey, get_cached_pubkey};
pub use core::types::ExportFormat;
pub use ux::format::{Output, set_json_mode};
