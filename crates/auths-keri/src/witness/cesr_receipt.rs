//! CESR receipt attachment groups for keripy interop (genus `KERICESR` v1).
//!
//! Witness receipts travel on the wire / OOBI `keri.cesr` stream as CESR counter
//! groups, byte-aligned with keripy 1.3.x:
//!
//! - **`-L` NonTransReceiptCouples** — `(witness-AID, signature)` couples where the
//!   witness AID is a non-transferable verkey prefix (the prefix *is* the key:
//!   Ed25519 `B…`, P-256 `1AAI…`). The canonical witness-receipt form.
//! - **`-K` WitnessIdxSigs** — witness signatures carried by *index* into the
//!   designated `b[]` set.
//!
//! > Note on code letters: keripy 1.3.x (the genus this aligns to) emits `-L` /
//! > `-K` for these groups. Older CESR tables labelled them `-C` / `-B`; the bytes
//! > below match the installed keripy, proven by `cesr_receipt::tests` against a
//! > keripy-generated fixture.
//!
//! The JSON/base64 git-trailer form ([`crate::witness::SignedReceipt::to_trailer_value`])
//! remains the convenience encoding for the git-commit surface only; these CESR
//! couplets are the canonical interop form.

use auths_crypto::CurveType;
use cesride::{Cigar, Matter, Verfer, matter};

use crate::keys::KeriDecodeError;
use crate::types::Prefix;

/// keripy `Codens.NonTransReceiptCouples` selector (genus KERICESR v1).
const NONTRANS_RECEIPT_COUPLES: &str = "-L";
/// keripy `Codens.WitnessIdxSigs` selector (genus KERICESR v1).
const WITNESS_IDX_SIGS: &str = "-K";

/// CESR (URL-safe base64) alphabet, in value order.
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode a counter group code + a 2-character big-endian base64 count (`-LAB`, …).
fn counter(code: &str, count: usize) -> String {
    let n = count as u32;
    let hi = B64[((n >> 6) & 0x3f) as usize] as char;
    let lo = B64[(n & 0x3f) as usize] as char;
    format!("{code}{hi}{lo}")
}

/// Decode the 2-character base64 count that follows a 2-character counter code.
fn decode_counter<'a>(s: &'a str, code: &str) -> Result<(usize, &'a str), KeriDecodeError> {
    let rest = s
        .strip_prefix(code)
        .ok_or_else(|| KeriDecodeError::DecodeError(format!("expected counter {code}")))?;
    let b = rest.as_bytes();
    if b.len() < 2 {
        return Err(KeriDecodeError::DecodeError(
            "truncated counter count".into(),
        ));
    }
    let val = |c: u8| {
        B64.iter()
            .position(|&x| x == c)
            .map(|p| p as u32)
            .ok_or_else(|| KeriDecodeError::DecodeError("invalid base64 count digit".into()))
    };
    let count = ((val(b[0])? << 6) | val(b[1])?) as usize;
    Ok((count, &rest[2..]))
}

/// Encode a witness signature as CESR qb64, dispatching the matter code on the
/// signing curve (Ed25519 → `0B…`, P-256 → `0I…`).
///
/// Args:
/// * `curve`: The witness key's curve (taken from its in-band CESR tag).
/// * `sig`: The raw signature bytes (64 for Ed25519 / P-256).
///
/// Usage:
/// ```ignore
/// let qb64 = encode_sig(CurveType::Ed25519, &sig)?; // "0B…", 88 chars
/// ```
pub fn encode_sig(curve: CurveType, sig: &[u8]) -> Result<String, KeriDecodeError> {
    let code = match curve {
        CurveType::Ed25519 => matter::Codex::Ed25519_Sig,
        CurveType::P256 => matter::Codex::ECDSA_256r1_Sig,
    };
    Cigar::new_with_raw(sig, None, Some(code))
        .and_then(|c| c.qb64())
        .map_err(|e| KeriDecodeError::DecodeError(e.to_string()))
}

/// The signing curve a witness AID names, from its in-band CESR verkey code.
fn curve_of_aid(aid: &str) -> Result<CurveType, KeriDecodeError> {
    let primitive = crate::cesr_encode::take_matter_qb64(aid)?;
    let (_raw, code) = crate::cesr_encode::decode_verkey(primitive)?;
    if code == matter::Codex::Ed25519 || code == matter::Codex::Ed25519N {
        Ok(CurveType::Ed25519)
    } else if code == matter::Codex::ECDSA_256r1 || code == matter::Codex::ECDSA_256r1N {
        Ok(CurveType::P256)
    } else {
        Err(KeriDecodeError::DecodeError(format!(
            "unsupported witness verkey code {code}"
        )))
    }
}

/// Emit a `-L` NonTransReceiptCouples attachment group, byte-aligned with keripy.
///
/// Each couple is `(witness AID, signature)`: the witness AID is appended as its
/// CESR verkey prefix (already curve-tagged in-band) followed by the Ed25519
/// signature qb64.
///
/// Args:
/// * `couples`: `(witness_aid, signature_bytes)` pairs, in attachment order.
///
/// Usage:
/// ```ignore
/// let attachment = encode_nontrans_receipt_couples(&[(&witness_aid, &sig)])?;
/// ```
pub fn encode_nontrans_receipt_couples(
    couples: &[(&Prefix, &[u8])],
) -> Result<String, KeriDecodeError> {
    let mut out = counter(NONTRANS_RECEIPT_COUPLES, couples.len());
    for (aid, sig) in couples {
        out.push_str(aid.as_str());
        out.push_str(&encode_sig(curve_of_aid(aid.as_str())?, sig)?);
    }
    Ok(out)
}

/// Parse a `-L` NonTransReceiptCouples attachment group back into
/// `(witness AID, signature)` pairs.
///
/// Args:
/// * `s`: A CESR string beginning with the `-L` counter.
pub fn parse_nontrans_receipt_couples(s: &str) -> Result<Vec<(Prefix, Vec<u8>)>, KeriDecodeError> {
    let (count, mut cur) = decode_counter(s, NONTRANS_RECEIPT_COUPLES)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        // Witness AID: the curve-tagged verkey prefix, kept verbatim. Take its exact
        // qb64 width before the decoder runs so a malformed code cannot slice out of
        // bounds.
        let aid_qb64 = crate::cesr_encode::take_matter_qb64(cur)?;
        Verfer::new_with_qb64(aid_qb64).map_err(|e| KeriDecodeError::DecodeError(e.to_string()))?;
        let aid = Prefix::new_unchecked(aid_qb64.to_string());
        cur = &cur[aid_qb64.len()..];
        // Signature: recover the raw bytes from its exact qb64 width.
        let sig_qb64 = crate::cesr_encode::take_matter_qb64(cur)?;
        let cigar = Cigar::new_with_qb64(sig_qb64, None)
            .map_err(|e| KeriDecodeError::DecodeError(format!("Cigar decode: {e}")))?;
        out.push((aid, cigar.raw()));
        cur = &cur[sig_qb64.len()..];
    }
    Ok(out)
}

/// Emit a `-K` WitnessIdxSigs counter for `count` indexed witness signatures.
///
/// The indexed signatures themselves are appended by the caller (an indexed-signer
/// concern); this provides the keripy-aligned counter prefix.
///
/// Args:
/// * `count`: The number of indexed witness signatures that follow.
pub fn witness_idx_sigs_counter(count: usize) -> String {
    counter(WITNESS_IDX_SIGS, count)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // Deterministic keripy 1.3.5 reference (genus KERICESR v1) for a fixed
    // non-transferable Ed25519 witness verkey (raw 0x11×32) and Ed25519 signature
    // (raw 0x22×64). Generated via `keri.core.{coring,counting,indexing}`.
    const WITNESS_QB64: &str = "BBERERERERERERERERERERERERERERERERERERERERER";
    const SIG_QB64: &str =
        "0BAiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi";
    const ATTACH_1: &str = "-LABBBERERERERERERERERERERERERERERERERERERERERER0BAiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi";
    const COUNTER_NONTRANS_2: &str = "-LAC";
    const COUNTER_WITIDX_1: &str = "-KAB";

    fn sig_raw() -> Vec<u8> {
        vec![0x22u8; 64]
    }

    #[test]
    fn receipt_matches_keripy_fixture() {
        let witness = Prefix::new_unchecked(WITNESS_QB64.to_string());
        let sig = sig_raw();

        // Signature encodes byte-for-byte to keripy's Cigar(0B…).
        assert_eq!(
            encode_sig(auths_crypto::CurveType::Ed25519, &sig).unwrap(),
            SIG_QB64
        );

        // The full -L couple group matches keripy's attachment bytes.
        let attach = encode_nontrans_receipt_couples(&[(&witness, &sig)]).unwrap();
        assert_eq!(attach, ATTACH_1);

        // Counters match keripy's selectors.
        assert_eq!(counter(NONTRANS_RECEIPT_COUPLES, 2), COUNTER_NONTRANS_2);
        assert_eq!(witness_idx_sigs_counter(1), COUNTER_WITIDX_1);
    }

    #[test]
    fn receipt_cesr_couplet_roundtrip() {
        let w1 = Prefix::new_unchecked(WITNESS_QB64.to_string());
        let w2 = Prefix::new_unchecked(
            // A second distinct non-trans Ed25519 witness (raw 0x33×32) via cesride.
            crate::cesr_encode::encode_verkey(&[0x33u8; 32], matter::Codex::Ed25519N).unwrap(),
        );
        let s1 = vec![0x22u8; 64];
        let s2 = vec![0x44u8; 64];

        let attach = encode_nontrans_receipt_couples(&[(&w1, &s1), (&w2, &s2)]).unwrap();
        let parsed = parse_nontrans_receipt_couples(&attach).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0.as_str(), w1.as_str());
        assert_eq!(parsed[0].1, s1);
        assert_eq!(parsed[1].0.as_str(), w2.as_str());
        assert_eq!(parsed[1].1, s2);
    }

    #[test]
    fn parse_rejects_malformed_couple_without_panicking() {
        // A -L group (count 1) whose first primitive is a truncated/variable-length
        // code must fail closed, not panic on an out-of-bounds slice inside the CESR
        // decoder.
        assert!(parse_nontrans_receipt_couples("-LAB6AAA1IAA").is_err());
        // A non-ASCII byte where a primitive is expected is rejected too.
        assert!(parse_nontrans_receipt_couples("-LABD\u{42c}").is_err());
        // A valid witness AID prefix but a truncated body is rejected, not sliced
        // past the end.
        assert!(parse_nontrans_receipt_couples("-LABBBERER").is_err());
    }

    #[test]
    fn receipt_couplet_witness_pre_is_curve_tagged() {
        // The witness AID in each couple carries its curve in-band via the CESR
        // code, so it round-trips and parses back to the right curve. (keripy's
        // non-transferable `B…`/`1AAI…` couple convention encodes byte-identically
        // — proven by `receipt_matches_keripy_fixture`; aligning auths witness AIDs
        // to the non-transferable code is a D.1 witness-identity follow-up.)
        let ed = Prefix::new_unchecked(
            crate::cesr_encode::encode_verkey(&[0x11u8; 32], matter::Codex::Ed25519).unwrap(),
        );
        let p256 = Prefix::new_unchecked(
            crate::cesr_encode::encode_verkey(&[0x02u8; 33], matter::Codex::ECDSA_256r1N).unwrap(),
        );
        let sig = vec![0x22u8; 64];

        let attach = encode_nontrans_receipt_couples(&[(&ed, &sig), (&p256, &sig)]).unwrap();
        let parsed = parse_nontrans_receipt_couples(&attach).unwrap();

        let k0 = crate::KeriPublicKey::parse(parsed[0].0.as_str()).unwrap();
        let k1 = crate::KeriPublicKey::parse(parsed[1].0.as_str()).unwrap();
        assert_eq!(k0.curve(), auths_crypto::CurveType::Ed25519);
        assert_eq!(k1.curve(), auths_crypto::CurveType::P256);
    }
}
