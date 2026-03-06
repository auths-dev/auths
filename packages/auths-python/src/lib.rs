// PyO3 0.21 generates unsafe calls inside macro-expanded code that Edition 2024
// flags; fixed in PyO3 0.22+. Suppress until we upgrade.
#![allow(unsafe_op_in_unsafe_fn)]

use pyo3::prelude::*;

pub mod runtime;
pub mod sign;
pub mod token;
pub mod types;
pub mod verify;

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

    m.add_function(wrap_pyfunction!(sign::sign_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(sign::sign_action, m)?)?;
    m.add_function(wrap_pyfunction!(sign::verify_action_envelope, m)?)?;

    m.add_function(wrap_pyfunction!(token::get_token, m)?)?;

    Ok(())
}
