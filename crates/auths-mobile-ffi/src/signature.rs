//! Canonical helper for converting SE-emitted ECDSA signatures to the
//! raw `r || s` form that KERI / CESR wire formats expect.
//!
//! iOS Secure Enclave emits `ecdsaSignatureMessageX962SHA256` as ASN.1
//! DER. Downstream wire formats (including KERI indexed signatures and
//! the pairing response body) expect a fixed 64-byte concatenation of
//! the two big-endian scalars. Rolling the conversion inline at each
//! call site is the silent-correctness hazard — different encodings
//! sneak through as `InvalidSignature`, which masks the real bug.

use crate::MobileError;

/// Convert a DER-encoded P-256 ECDSA signature to the raw 64-byte `r||s`
/// form used by KERI and the pairing wire format.
///
/// Args:
/// * `der`: ASN.1 DER ECDSA signature bytes (`SEQUENCE { r, s }`).
///
/// Usage:
/// ```ignore
/// let raw = ecdsa_p256_der_to_raw(&der_bytes)?;
/// ```
pub(crate) fn ecdsa_p256_der_to_raw(der: &[u8]) -> Result<[u8; 64], MobileError> {
    let sig = p256::ecdsa::Signature::from_der(der)
        .map_err(|e| MobileError::PairingFailed(format!("invalid DER signature: {e}")))?;
    Ok(sig.to_bytes().into())
}
