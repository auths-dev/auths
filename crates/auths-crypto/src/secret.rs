//! The `Secret` marker trait — type-level annotation for secret-bearing types.
//!
//! A type that implements `Secret` is declaring two invariants:
//! 1. Its in-memory representation MUST be zeroized on drop. This is
//!    enforced at the type level via the `ZeroizeOnDrop` supertrait bound
//!    (sealed so the workspace owns every implementor).
//! 2. Its `Debug` / `Display` / `Serialize` impls MUST NOT emit the inner
//!    bytes. This is enforced by convention + an xtask scanner rule
//!    (`check-constant-time`, extended in fn-128.T5) that flags:
//!    - `#[derive(PartialEq)]` / `#[derive(Eq)]` on `Secret` types
//!      (equality on secrets must go through `subtle::ConstantTimeEq`)
//!    - `==` / `!=` on `Secret`-typed operands
//!    - any `impl Secret for T` that lacks a parallel `ZeroizeOnDrop` impl
//!
//! Sealed: the super-trait `sealed::Sealed` lives in a private module, so
//! downstream crates cannot unilaterally extend the `Secret` family. New
//! secret types are added by editing the `sealed::Sealed` impl block in
//! this crate.
//!
//! Usage:
//! ```ignore
//! use auths_crypto::{Secret, SecureSeed};
//!
//! fn drop_secret_safely<S: Secret>(_s: S) {
//!     // `S` is ZeroizeOnDrop by the trait bound.
//!     // Compiler + xtask scanner enforce the rest.
//! }
//! ```

use zeroize::ZeroizeOnDrop;

mod sealed {
    /// Super-trait closing the `Secret` family to this crate. External
    /// code cannot implement `Secret` because they cannot implement
    /// `Sealed` — the trait is private.
    pub trait Sealed {}
}

/// Marker trait for types holding secret key material.
///
/// Implementors MUST:
/// - Be listed in the `sealed::Sealed` impls in this module (enforced).
/// - Implement [`zeroize::ZeroizeOnDrop`] (enforced at the trait level).
/// - Not derive `PartialEq` / `Eq` / `Ord` (enforced by xtask scanner).
/// - Redact their `Debug` output (convention; scanner WIP).
///
/// The trait has no methods — its presence is the declaration.
pub trait Secret: sealed::Sealed + ZeroizeOnDrop {}

// -------------------------------------------------------------------------
// Implementors (every secret-bearing type in this crate). Adding a new one:
// 1) Derive `ZeroizeOnDrop` (or wrap in `Zeroizing<T>` at field level).
// 2) Add an `impl sealed::Sealed for T {}` below.
// 3) Add an `impl Secret for T {}` below.
// 4) Ensure xtask `check-constant-time` does not flag the type (no
//    derived PartialEq/Eq; no raw `==` / `!=` on the type).
// -------------------------------------------------------------------------

impl sealed::Sealed for crate::provider::SecureSeed {}
impl Secret for crate::provider::SecureSeed {}

impl sealed::Sealed for crate::key_ops::TypedSeed {}
impl Secret for crate::key_ops::TypedSeed {}

impl sealed::Sealed for crate::pkcs8::Pkcs8Der {}
impl Secret for crate::pkcs8::Pkcs8Der {}

impl sealed::Sealed for crate::key_ops::TypedSignerKey {}
impl Secret for crate::key_ops::TypedSignerKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::SecureSeed;

    /// Compile-time assertion that the types we expect to be `Secret` actually
    /// implement the trait. If someone removes the impl, this fails at
    /// compile time — not at runtime.
    fn _assert_impl<T: Secret>() {}

    #[test]
    fn secret_marker_is_implemented_by_expected_types() {
        _assert_impl::<SecureSeed>();
        _assert_impl::<crate::key_ops::TypedSeed>();
        _assert_impl::<crate::pkcs8::Pkcs8Der>();
        _assert_impl::<crate::key_ops::TypedSignerKey>();
    }
}
