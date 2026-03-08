//! Embeddable LAN pairing daemon for Auths.
//!
//! Provides an HTTP server, rate limiting, mDNS discovery, and network
//! interface detection for device pairing over a local network. Designed
//! for embedding in CLI tools, IDE extensions, and Tauri apps.
//!
//! ## Feature flags
//!
//! - `server` (default): Axum HTTP server, rate limiting, token validation, IP detection
//! - `mdns` (default): mDNS advertisement and discovery via `mdns-sd`
//!
//! Without features, only the core types (`DaemonError`, `DaemonState`) are available.

mod error;
mod state;

pub use error::DaemonError;
pub use state::DaemonState;
