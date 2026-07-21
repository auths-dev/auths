//! Re-exports of witness server and config types.

pub use auths_core::witness::AsyncWitnessProvider;
pub use auths_id::witness_config::{WitnessConfig, WitnessParams, WitnessRef};

// Operator-independence + honesty-ceiling model (shared across CLI, verify, badge).
pub use auths_keri::witness::independence::{
    EquivocationDetection, HonestyCeiling, Independence, IndependencePolicy, honesty_ceiling,
};

#[cfg(feature = "witness-server")]
pub use auths_core::witness::{
    BuildProof, WitnessIdentityError, WitnessServerConfig, WitnessServerState,
    generate_and_persist_witness_signer, load_witness_signer, run_server,
    witness_signer_from_seed_hex,
};

#[cfg(feature = "witness-client")]
pub use auths_id::keri::witness_integration::{
    WitnessIntegrationError, publish_kel_to_backers, solicit_receipts_for_event,
};
