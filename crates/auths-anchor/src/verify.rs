//! Pure, WASM-safe signature verification, dispatched on an in-band curve tag.
//!
//! The verify path mirrors the shipped verifier exactly: Ed25519 via
//! `ed25519-dalek` (`verify_strict`, rejecting non-canonical `R`/weak keys),
//! P-256 via the `p256` crate (SHA-256 prehash, low-S parity). Curve is always
//! a [`CurveType`] tag — dispatch never looks at byte length (CLAUDE.md
//! wire-format rule).

use auths_crypto::CurveType;

use crate::error::AnchorError;

/// Verify a signature over `message` under `(curve, public_key)`.
///
/// Returns `Ok(true)` for a valid signature, `Ok(false)` for a well-formed but
/// non-matching signature, and `Err` only when the key or signature bytes are
/// malformed for the named curve.
///
/// Args:
/// * `curve`: the in-band curve tag.
/// * `public_key`: 32-byte Ed25519 or 33-byte compressed P-256 verifying key.
/// * `message`: the exact bytes that were signed.
/// * `signature`: the raw signature (64 bytes for both curves).
///
/// Usage:
/// ```ignore
/// if verify_signature(CurveType::Ed25519, &pk, &msg, &sig)? {
///     // authentic
/// }
/// ```
pub fn verify_signature(
    curve: CurveType,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, AnchorError> {
    match curve {
        CurveType::Ed25519 => verify_ed25519(public_key, message, signature),
        CurveType::P256 => verify_p256(public_key, message, signature),
    }
}

/// Ed25519 strict verification via `ed25519-dalek`.
fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, AnchorError> {
    let key_bytes: [u8; 32] = public_key.try_into().map_err(|_| {
        AnchorError::MalformedMaterial(format!("ed25519 key len {}", public_key.len()))
    })?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| AnchorError::MalformedMaterial(format!("ed25519 key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|e| AnchorError::MalformedMaterial(format!("ed25519 sig: {e}")))?;
    Ok(vk.verify_strict(message, &sig).is_ok())
}

/// P-256 verification via the pure-Rust `p256` crate (SHA-256 prehash).
fn verify_p256(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, AnchorError> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let vk = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| AnchorError::MalformedMaterial(format!("p256 key: {e}")))?;
    let sig = Signature::from_slice(signature)
        .map_err(|e| AnchorError::MalformedMaterial(format!("p256 sig: {e}")))?;
    Ok(vk.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn ed25519_round_trip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let msg = b"anchor bytes";
        let sig = sk.sign(msg);
        assert!(verify_signature(CurveType::Ed25519, vk.as_bytes(), msg, &sig.to_bytes()).unwrap());
        assert!(
            !verify_signature(
                CurveType::Ed25519,
                vk.as_bytes(),
                b"tampered",
                &sig.to_bytes()
            )
            .unwrap()
        );
    }

    #[test]
    fn malformed_key_is_error_not_false() {
        let err = verify_signature(CurveType::Ed25519, &[0u8; 10], b"x", &[0u8; 64]).unwrap_err();
        assert!(matches!(err, AnchorError::MalformedMaterial(_)));
    }
}
