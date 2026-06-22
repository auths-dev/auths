//! CESR-correct primitive encoding via `cesride` — the byte-interoperable wire format.
//!
//! These wrappers produce qb64 strings that are **byte-identical to keripy** (proven by
//! `codec::tests::cesr_primitives_match_keripy_reference`), replacing the legacy naive
//! `format!("D{}", base64url(raw))` scheme that diverged from CESR's qb64 alignment.
//!
//! `cesride` is a non-optional dependency, so unlike the feature-gated `codec` module these
//! helpers are always available — they are the default encoding for verkeys, digests, and SAIDs.

use cesride::{Diger, Matter, Salter, Verfer, matter};

use crate::keys::KeriDecodeError;

/// CESR-encode a 16-byte salt as a qb64 `Salt_128` (`0A…`) primitive.
///
/// This is the nonce encoding keripy uses for a registry's `vcp.n` — a
/// 128-bit salt under the `0A` matter code, byte-identical to
/// `coring.Salter(raw=…).qb64`.
///
/// Args:
/// * `raw`: The 16 random salt bytes.
///
/// Usage:
/// ```ignore
/// let nonce = encode_salt_128(&[0u8; 16])?;
/// assert!(nonce.starts_with("0A"));
/// ```
pub fn encode_salt_128(raw: &[u8; 16]) -> Result<String, KeriDecodeError> {
    Salter::new_with_raw(raw, Some(matter::Codex::Salt_128), None)
        .and_then(|s| s.qb64())
        .map_err(|e| KeriDecodeError::DecodeError(e.to_string()))
}

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
/// The inverse of [`encode_verkey`]; drives [`crate::keys::KeriPublicKey::parse`].
///
/// Args:
/// * `qb64`: The CESR-qualified verkey string (e.g. `"DAAB…"`, `"1AAJ…"`).
pub(crate) fn decode_verkey(qb64: &str) -> Result<(Vec<u8>, String), KeriDecodeError> {
    // cesride derives a primitive's length from its derivation code and indexes
    // into the qb64 by that length, so a truncated or malformed code slices out
    // of bounds and panics. Contain the panic at this untrusted-input boundary so
    // a bad verkey fails closed with a typed error instead of crashing the caller.
    std::panic::catch_unwind(|| {
        Verfer::new(None, None, None, Some(qb64), None).map(|v| (v.raw(), v.code()))
    })
    .map_err(|_| KeriDecodeError::DecodeError("malformed CESR verkey primitive".into()))?
    .map_err(|e| KeriDecodeError::DecodeError(e.to_string()))
}

/// CESR Matter hard-code character length, keyed by the code's first character
/// (mirrors cesride's `matter::hardage`, whose tables are `pub(crate)`). Returns
/// `None` for a counter (`-`), op (`_`), or otherwise non-Matter start byte.
fn matter_hard_len(first: u8) -> Option<usize> {
    Some(match first {
        b'A'..=b'Z' | b'a'..=b'z' => 1,
        b'0' | b'4' | b'5' | b'6' => 2,
        b'1' | b'2' | b'3' | b'7' | b'8' | b'9' => 4,
        _ => return None,
    })
}

/// Full qb64 character length for the CESR Matter codes auths parses (mirrors
/// cesride's `matter` sizage for these codes). Returns `None` for any other code,
/// so an unrecognized primitive fails closed rather than being handed to the
/// length-slicing decoder.
fn matter_full_len(code: &str) -> Option<usize> {
    Some(match code {
        "D" | "B" | "E" => 44,
        "0B" | "0I" => 88,
        "1AAI" | "1AAJ" => 48,
        _ => return None,
    })
}

/// Take the leading CESR Matter primitive off `s`, returning its exact qb64
/// substring without consuming the remainder.
///
/// cesride's qb64 decoder reads the derivation code, computes the primitive's full
/// size, and slices the input to it — so a truncated input slices out of bounds and
/// a non-ASCII input slices off a char boundary, both panicking. This validates the
/// code is known and the input holds the full primitive (and is ASCII through it)
/// *before* the decoder runs, so the panic is unreachable and a malformed primitive
/// fails closed with a typed error.
///
/// Args:
/// * `s`: A qb64 string positioned at the start of a Matter primitive (a verkey,
///   signature, or digest); trailing bytes after the primitive are left for the
///   caller to consume.
pub(crate) fn take_matter_qb64(s: &str) -> Result<&str, KeriDecodeError> {
    let bytes = s.as_bytes();
    let first = *bytes.first().ok_or(KeriDecodeError::EmptyInput)?;
    let hs = matter_hard_len(first).ok_or_else(|| {
        KeriDecodeError::DecodeError(format!("not a CESR primitive: {:?}", first as char))
    })?;
    if bytes.len() < hs || !bytes[..hs].is_ascii() {
        return Err(KeriDecodeError::DecodeError(
            "truncated or non-ASCII CESR hard code".into(),
        ));
    }
    let code = &s[..hs];
    let fs =
        matter_full_len(code).ok_or_else(|| KeriDecodeError::UnsupportedKeyType(code.into()))?;
    if bytes.len() < fs || !bytes[..fs].is_ascii() {
        return Err(KeriDecodeError::DecodeError(format!(
            "{code} primitive needs {fs} ASCII chars, have {}",
            bytes.len()
        )));
    }
    Ok(&s[..fs])
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

    #[test]
    fn matter_full_len_matches_cesride_encoding() {
        use cesride::{Cigar, Matter};
        // The full-size table mirrors cesride's matter sizage for the codes auths
        // parses. Pin each entry to what cesride actually emits, so a cesride bump
        // that shifts a primitive's size fails here loudly instead of drifting the
        // length-guard against the decoder.
        let cases: [(&str, String); 7] = [
            ("D", encode_verkey(&[0u8; 32], matter::Codex::Ed25519).unwrap()),
            ("B", encode_verkey(&[0u8; 32], matter::Codex::Ed25519N).unwrap()),
            ("1AAJ", encode_verkey(&[0u8; 33], matter::Codex::ECDSA_256r1).unwrap()),
            ("1AAI", encode_verkey(&[0u8; 33], matter::Codex::ECDSA_256r1N).unwrap()),
            ("E", encode_blake3_digest(&[0u8; 32]).unwrap()),
            (
                "0B",
                Cigar::new_with_raw(&[0u8; 64], None, Some(matter::Codex::Ed25519_Sig))
                    .and_then(|c| c.qb64())
                    .unwrap(),
            ),
            (
                "0I",
                Cigar::new_with_raw(&[0u8; 64], None, Some(matter::Codex::ECDSA_256r1_Sig))
                    .and_then(|c| c.qb64())
                    .unwrap(),
            ),
        ];
        for (code, encoded) in cases {
            assert!(
                encoded.starts_with(code),
                "{code} primitive must encode under its own code, got {encoded:?}"
            );
            assert_eq!(
                matter_full_len(code),
                Some(encoded.len()),
                "matter_full_len({code:?}) drifted from cesride's {} chars",
                encoded.len()
            );
        }
    }
}
