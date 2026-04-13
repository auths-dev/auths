// fn-114: crate-level allow during curve-agnostic refactor. Removed or narrowed in fn-114.40 after Phase 4 sweeps.
#![allow(clippy::disallowed_methods)]
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
pub mod subprocess;
pub mod telemetry;
pub mod ux;

pub use core::pubkey_cache::{cache_pubkey, clear_cached_pubkey, get_cached_pubkey};
pub use core::types::ExportFormat;
pub use ux::format::{Output, set_json_mode};
