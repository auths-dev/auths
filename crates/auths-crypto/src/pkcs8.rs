//! Type-safe wrapper for PKCS#8 DER-encoded private key material.
// allow during curve-agnostic refactor
#![allow(clippy::disallowed_methods)]

use zeroize::{Zeroize, ZeroizeOnDrop};

/// DER-encoded PKCS#8 private key material.
///
/// Wraps the raw bytes in a zeroize-on-drop container so key material
/// is scrubbed from memory when the value goes out of scope. Use this
/// type at module boundaries instead of raw `&[u8]` or `Vec<u8>` to
/// prevent accidental misuse (passing a public key, seed, or garbage
/// where PKCS#8 is expected).
///
/// Usage:
/// ```ignore
/// let pkcs8 = Pkcs8Der::new(ring_doc.as_ref());
/// let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())?;
/// // pkcs8 is zeroed when dropped
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Pkcs8Der(Vec<u8>);

impl Pkcs8Der {
    /// Wrap raw PKCS#8 DER bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns `true` if the inner buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for Pkcs8Der {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Pkcs8Der {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pkcs8Der([REDACTED; {} bytes])", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_as_ref() {
        let bytes = vec![1u8, 2, 3];
        let pkcs8 = Pkcs8Der::new(bytes.clone());
        assert_eq!(pkcs8.as_ref(), &bytes[..]);
    }

    #[test]
    fn debug_redacts() {
        let pkcs8 = Pkcs8Der::new(vec![0u8; 48]);
        let debug = format!("{:?}", pkcs8);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("0, 0, 0"));
    }

    #[test]
    fn is_empty() {
        assert!(Pkcs8Der::new(vec![]).is_empty());
        assert!(!Pkcs8Der::new(vec![1]).is_empty());
    }
}
