// PyO3 0.21 generates unsafe calls inside macro-expanded code that Edition 2024
// flags; fixed in PyO3 0.22+. Suppress until we upgrade.
#![allow(unsafe_op_in_unsafe_fn)]

use pyo3::prelude::*;

pub mod audit;
pub mod artifact_publish;
pub mod artifact_sign;
pub mod attestation_query;
pub mod commit_sign;
pub mod commit_verify;
pub mod device_ext;
pub mod git_integration;
pub mod identity;
pub mod identity_sign;
pub mod org;
pub mod policy;
pub mod rotation;
pub mod runtime;
pub mod sign;
pub mod token;
pub mod trust;
pub mod types;
pub mod verify;
pub mod witness;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;

    m.add_class::<types::VerificationResult>()?;
    m.add_class::<types::VerificationStatus>()?;
    m.add_class::<types::ChainLink>()?;
    m.add_class::<types::VerificationReport>()?;

    m.add_function(wrap_pyfunction!(verify::verify_attestation, m)?)?;
    m.add_function(wrap_pyfunction!(verify::verify_chain, m)?)?;
    m.add_function(wrap_pyfunction!(verify::verify_device_authorization, m)?)?;
    m.add_function(wrap_pyfunction!(
        verify::verify_attestation_with_capability,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(verify::verify_chain_with_capability, m)?)?;
    m.add_function(wrap_pyfunction!(verify::verify_at_time, m)?)?;
    m.add_function(wrap_pyfunction!(verify::verify_at_time_with_capability, m)?)?;
    m.add_function(wrap_pyfunction!(verify::verify_chain_with_witnesses, m)?)?;

    m.add_function(wrap_pyfunction!(sign::sign_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(sign::sign_action, m)?)?;
    m.add_function(wrap_pyfunction!(sign::verify_action_envelope, m)?)?;

    m.add_function(wrap_pyfunction!(token::get_token, m)?)?;

    m.add_class::<identity::DelegatedAgentBundle>()?;
    m.add_class::<identity::AgentIdentityBundle>()?;
    m.add_function(wrap_pyfunction!(identity::create_identity, m)?)?;
    m.add_function(wrap_pyfunction!(identity::create_agent_identity, m)?)?;
    m.add_function(wrap_pyfunction!(identity::delegate_agent, m)?)?;
    m.add_function(wrap_pyfunction!(identity::link_device_to_identity, m)?)?;
    m.add_function(wrap_pyfunction!(identity::revoke_device_from_identity, m)?)?;

    m.add_function(wrap_pyfunction!(identity_sign::sign_as_identity, m)?)?;
    m.add_function(wrap_pyfunction!(identity_sign::sign_action_as_identity, m)?)?;
    m.add_function(wrap_pyfunction!(identity_sign::get_identity_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(identity_sign::sign_as_agent, m)?)?;
    m.add_function(wrap_pyfunction!(identity_sign::sign_action_as_agent, m)?)?;

    m.add_class::<rotation::PyIdentityRotationResult>()?;
    m.add_function(wrap_pyfunction!(rotation::rotate_identity_ffi, m)?)?;

    m.add_class::<device_ext::PyDeviceExtension>()?;
    m.add_function(wrap_pyfunction!(
        device_ext::extend_device_authorization_ffi,
        m
    )?)?;

    m.add_class::<policy::PyCompiledPolicy>()?;
    m.add_class::<policy::PyEvalContext>()?;
    m.add_class::<policy::PyDecision>()?;
    m.add_function(wrap_pyfunction!(policy::compile_policy, m)?)?;

    m.add_class::<artifact_publish::PyArtifactPublishResult>()?;
    m.add_function(wrap_pyfunction!(artifact_publish::publish_artifact, m)?)?;

    m.add_class::<artifact_sign::PyArtifactResult>()?;
    m.add_function(wrap_pyfunction!(artifact_sign::sign_artifact, m)?)?;
    m.add_function(wrap_pyfunction!(artifact_sign::sign_artifact_bytes, m)?)?;

    m.add_class::<commit_sign::PyCommitSignResult>()?;
    m.add_function(wrap_pyfunction!(commit_sign::sign_commit, m)?)?;

    m.add_class::<commit_verify::PyCommitVerificationResult>()?;
    m.add_function(wrap_pyfunction!(commit_verify::verify_commit_native, m)?)?;

    m.add_function(wrap_pyfunction!(
        git_integration::generate_allowed_signers_file,
        m
    )?)?;

    m.add_class::<attestation_query::PyAttestation>()?;
    m.add_function(wrap_pyfunction!(attestation_query::list_attestations, m)?)?;
    m.add_function(wrap_pyfunction!(
        attestation_query::list_attestations_by_device,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        attestation_query::get_latest_attestation,
        m
    )?)?;

    m.add_function(wrap_pyfunction!(audit::generate_audit_report, m)?)?;

    m.add_function(wrap_pyfunction!(org::create_org, m)?)?;
    m.add_function(wrap_pyfunction!(org::add_org_member, m)?)?;
    m.add_function(wrap_pyfunction!(org::revoke_org_member, m)?)?;
    m.add_function(wrap_pyfunction!(org::list_org_members, m)?)?;

    m.add_function(wrap_pyfunction!(trust::pin_identity, m)?)?;
    m.add_function(wrap_pyfunction!(trust::remove_pinned_identity, m)?)?;
    m.add_function(wrap_pyfunction!(trust::list_pinned_identities, m)?)?;
    m.add_function(wrap_pyfunction!(trust::get_pinned_identity, m)?)?;

    m.add_function(wrap_pyfunction!(witness::add_witness, m)?)?;
    m.add_function(wrap_pyfunction!(witness::remove_witness, m)?)?;
    m.add_function(wrap_pyfunction!(witness::list_witnesses, m)?)?;

    Ok(())
}
