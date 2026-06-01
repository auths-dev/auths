//! CESR-correct primitive encoding via `cesride` — the byte-interoperable wire format.
//!
//! These wrappers produce qb64 strings that are **byte-identical to keripy** (proven by
//! `codec::tests::cesr_primitives_match_keripy_reference`), replacing the legacy naive
//! `format!("D{}", base64url(raw))` scheme that diverged from CESR's qb64 alignment.
//!
//! `cesride` is a non-optional dependency, so unlike the feature-gated `codec` module these
//! helpers are always available — they are the default encoding for verkeys, digests, and SAIDs.

use cesride::{Diger, Matter, Verfer, matter};

use crate::keys::KeriDecodeError;

/// Encode raw verkey bytes as a CESR-qualified qb64 string under the given matter code.
///
/// Args:
/// * `raw`: Raw public-key bytes (32 for Ed25519, 33 for compressed P-256).
/// * `code`: The cesride matter code (e.g. `matter::Codex::Ed25519`, `ECDSA_256r1`).
///
/// Usage:
/// ```ignore
/// let qb64 = encode_verkey(&pubkey, cesride::matter::Codex::Ed25519)?;
/// ```
pub(crate) fn encode_verkey(raw: &[u8], code: &str) -> Result<String, KeriDecodeError> {
    Verfer::new(Some(code), Some(raw), None, None, None)
        .and_then(|v| v.qb64())
        .map_err(|e| KeriDecodeError::DecodeError(e.to_string()))
}

/// Decode a CESR-qualified verkey qb64 into its raw bytes and matter code.
///
/// Args:
/// * `qb64`: The CESR-qualified verkey string (e.g. `"DAAB…"`, `"1AAJ…"`).
// Wired into `KeriPublicKey::parse` when the encoding flip lands; kept here so the
// encode/decode pair is defined and keripy-pinned together.
#[allow(dead_code)]
pub(crate) fn decode_verkey(qb64: &str) -> Result<(Vec<u8>, String), KeriDecodeError> {
    let verfer = Verfer::new(None, None, None, Some(qb64), None)
        .map_err(|e| KeriDecodeError::DecodeError(e.to_string()))?;
    Ok((verfer.raw(), verfer.code()))
}

/// CESR-encode a 32-byte Blake3-256 digest as a qb64 SAID/commitment (`E…`).
///
/// Args:
/// * `digest`: The 32-byte Blake3-256 hash.
pub(crate) fn encode_blake3_digest(digest: &[u8]) -> Result<String, KeriDecodeError> {
    Diger::new(
        None,
        Some(matter::Codex::Blake3_256),
        Some(digest),
        None,
        None,
        None,
    )
    .and_then(|d| d.qb64())
    .map_err(|e| KeriDecodeError::DecodeError(e.to_string()))
}

/// The cesride matter code for a verkey of the given curve and transferability.
///
/// Ed25519 uses `D` (transferable) / `B` (non-transferable); P-256 uses `1AAJ` /
/// `1AAI` (`ECDSA_256r1` / `ECDSA_256r1N`).
pub(crate) fn verkey_code(curve: auths_crypto::CurveType, transferable: bool) -> &'static str {
    match (curve, transferable) {
        (auths_crypto::CurveType::Ed25519, true) => matter::Codex::Ed25519,
        (auths_crypto::CurveType::Ed25519, false) => matter::Codex::Ed25519N,
        (auths_crypto::CurveType::P256, true) => matter::Codex::ECDSA_256r1,
        (auths_crypto::CurveType::P256, false) => matter::Codex::ECDSA_256r1N,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// keripy 1.3.4 reference for the 32-byte Ed25519 key `bytes(0..32)`:
    /// `Verfer(raw, Ed25519).qb64` and `Diger(ser=verfer.qb64b).qb64`.
    #[test]
    fn encode_decode_matches_keripy() {
        let raw: Vec<u8> = (0u8..32).collect();
        let qb64 = encode_verkey(&raw, matter::Codex::Ed25519).unwrap();
        assert_eq!(qb64, "DAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f");

        let (decoded, code) = decode_verkey(&qb64).unwrap();
        assert_eq!(decoded, raw, "round-trip must recover the raw bytes");
        assert_eq!(code, matter::Codex::Ed25519);

        let commitment = encode_blake3_digest(blake3::hash(qb64.as_bytes()).as_bytes()).unwrap();
        assert_eq!(commitment, "EF_M_u7ASVHXfI8QzdWLq3V9ocSKqxkbujXGbi9QMtP9");
    }
}
