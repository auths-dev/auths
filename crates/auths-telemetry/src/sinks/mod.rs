//! Telemetry sink implementations.

pub mod composite;
#[cfg(feature = "sink-http")]
pub mod http;
pub mod stdout;
