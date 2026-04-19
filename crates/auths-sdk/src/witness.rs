//! Re-exports of witness server and config types.

pub use auths_id::witness_config::{WitnessConfig, WitnessParams};

#[cfg(feature = "witness-server")]
pub use auths_core::witness::{WitnessServerConfig, WitnessServerState, run_server};
