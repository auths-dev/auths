mod helpers;

mod auth_flow;
mod session_contract;

// These integration tests assert the pre-refactor model where capabilities were carried on the
// attestation chain (`Attestation.role`/`.capabilities`, `verify_chain_with_capability`). The
// verifier moved capability scoping to commit/agent verification, so they need rewriting against
// the current attestation/verifier APIs before they can be re-enabled.
// mod air_gapped;
// mod client_registration;
// mod robustness;
