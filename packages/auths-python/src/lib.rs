// PyO3 0.21 generates unsafe calls inside macro-expanded code that Edition 2024
// flags; fixed in PyO3 0.22+. Suppress until we upgrade.
#![allow(unsafe_op_in_unsafe_fn)]

use pyo3::prelude::*;

pub mod runtime;
pub mod types;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
    m.add_class::<types::VerificationResult>()?;
    m.add_class::<types::VerificationStatus>()?;
    m.add_class::<types::ChainLink>()?;
    m.add_class::<types::VerificationReport>()?;
    Ok(())
}
