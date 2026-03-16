//! Namespace verifier adapter registry.
//!
//! Maps [`Ecosystem`] variants to their corresponding [`NamespaceVerifier`]
//! implementations. The SDK uses this to dispatch verification requests
//! to the correct adapter.

use std::collections::HashMap;
use std::sync::Arc;

use auths_core::ports::namespace::{Ecosystem, NamespaceVerifier, NamespaceVerifyError};
use auths_infra_http::namespace::{CargoVerifier, NpmVerifier, PypiVerifier};

/// Registry mapping ecosystems to their verification adapters.
///
/// Usage:
/// ```ignore
/// let registry = NamespaceVerifierRegistry::with_defaults();
/// let verifier = registry.require(Ecosystem::Cargo)?;
/// ```
pub struct NamespaceVerifierRegistry {
    verifiers: HashMap<Ecosystem, Arc<dyn NamespaceVerifier>>,
}

impl NamespaceVerifierRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    /// Register a verifier adapter. Keyed by `verifier.ecosystem()`.
    ///
    /// Args:
    /// * `verifier`: The adapter to register.
    pub fn register(&mut self, verifier: Arc<dyn NamespaceVerifier>) {
        self.verifiers.insert(verifier.ecosystem(), verifier);
    }

    /// Look up a verifier for the given ecosystem.
    ///
    /// Args:
    /// * `ecosystem`: The ecosystem to look up.
    pub fn get(&self, ecosystem: Ecosystem) -> Option<&Arc<dyn NamespaceVerifier>> {
        self.verifiers.get(&ecosystem)
    }

    /// Look up a verifier, returning an error if the ecosystem is not registered.
    ///
    /// Args:
    /// * `ecosystem`: The ecosystem to look up.
    pub fn require(
        &self,
        ecosystem: Ecosystem,
    ) -> Result<&Arc<dyn NamespaceVerifier>, NamespaceVerifyError> {
        self.verifiers
            .get(&ecosystem)
            .ok_or_else(|| NamespaceVerifyError::UnsupportedEcosystem {
                ecosystem: ecosystem.as_str().to_string(),
            })
    }

    /// Create a registry pre-populated with all built-in adapters.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(CargoVerifier::new()));
        registry.register(Arc::new(NpmVerifier::new()));
        registry.register(Arc::new(PypiVerifier::new()));
        registry
    }
}

impl Default for NamespaceVerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_require_missing_ecosystem() {
        let registry = NamespaceVerifierRegistry::new();
        let result = registry.require(Ecosystem::Cargo);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(
            err,
            NamespaceVerifyError::UnsupportedEcosystem { .. }
        ));
    }

    #[test]
    fn registry_with_defaults_has_cargo_npm_pypi() {
        let registry = NamespaceVerifierRegistry::with_defaults();
        assert!(registry.get(Ecosystem::Cargo).is_some());
        assert!(registry.get(Ecosystem::Npm).is_some());
        assert!(registry.get(Ecosystem::Pypi).is_some());
        assert!(registry.get(Ecosystem::Docker).is_none());
        assert!(registry.get(Ecosystem::Go).is_none());
    }

    #[test]
    fn registry_require_registered_ecosystem() {
        let registry = NamespaceVerifierRegistry::with_defaults();
        let verifier = registry.require(Ecosystem::Cargo).unwrap();
        assert_eq!(verifier.ecosystem(), Ecosystem::Cargo);
    }
}
