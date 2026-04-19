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

mod discovery;
pub mod entropy_probe;
mod error;
#[cfg(feature = "server")]
mod handlers;
mod network;
mod rate_limiter;
#[cfg(feature = "server")]
mod router;
#[cfg(feature = "server")]
mod server;
mod state;
mod token;

pub use discovery::{AdvertiseHandle, MockNetworkDiscovery, NetworkDiscovery, SERVICE_TYPE};
pub use error::DaemonError;
pub use network::{MockNetworkInterfaces, NetworkInterfaces};
pub use rate_limiter::RateLimiter;
pub use state::{DaemonState, SessionError};

#[cfg(feature = "mdns")]
pub use discovery::MdnsDiscovery;

#[cfg(feature = "server")]
pub use network::IfAddrsNetworkInterfaces;
#[cfg(feature = "server")]
pub use rate_limiter::middleware::rate_limit_middleware;
#[cfg(feature = "server")]
pub use router::build_pairing_router;
#[cfg(feature = "server")]
pub use server::{PairingDaemon, PairingDaemonBuilder, PairingDaemonHandle};
#[cfg(feature = "server")]
pub use token::{generate_transport_token, validate_pairing_token};
