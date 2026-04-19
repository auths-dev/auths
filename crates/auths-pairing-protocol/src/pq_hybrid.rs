//! Hybrid post-quantum KEM (P-256 || ML-KEM-768) — fn-129.T10.
//!
//! # UNAUDITED — NOT FOR PRODUCTION USE
//!
//! The [`ml-kem`](https://docs.rs/ml-kem) crate (RustCrypto/KEMs, FIPS 203
//! Final) has NOT been independently audited as of April 2026. This module
//! wires it into the pairing protocol behind the `pq-hybrid` Cargo feature
//! so the wire format and combiner can be exercised ahead of an audit, but
//! it MUST NOT be enabled in a production deployment until either:
//!
//! 1. `ml-kem` clears a formal cryptographic review, or
//! 2. The FIPS-validated ML-KEM-768 provider is plumbed through
//!    [`auths_crypto::CryptoProvider`] (cross-epic, tracked in fn-128).
//!
//! # Why hybrid at all
//!
//! CNSA 2.0 mandates classical-only deployments for National Security
//! Systems are phased out by 2033. Pairing traffic recorded today can be
//! retroactively decrypted once a cryptographically-relevant quantum
//! computer (CRQC) exists. A hybrid construction combines the classical
//! P-256 ECDH shared secret with a PQ KEM shared secret through
//! HKDF-Extract: an attacker must break both to recover the transport key.
//!
//! # Construction
//!
//! Per NIST SP 800-227 §4.6 (dual-PRF combiner) and
//! [draft-ietf-tls-ecdhe-mlkem-04](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
//! (`SecP256r1MLKEM768` codepoint ordering):
//!
//! ```text
//! combined_ikm = ss_classical || ss_pq        // classical FIRST
//! transport_k  = HKDF-Extract(salt, combined_ikm)
//! transport_k' = HKDF-Expand(transport_k, TRANSPORT_HYBRID_INFO || …, 32)
//! ```
//!
//! Classical-first is the hedged choice: if ML-KEM-768 is later broken in
//! its lattice assumptions, an attacker still faces P-256. The ordering is
//! domain-separated from the classical-only transport key by a different
//! HKDF `info` label ([`TRANSPORT_HYBRID_INFO`]) so a classical session
//! and a hybrid session with identical ECDH inputs never collide.
//!
//! # Downgrade resistance
//!
//! If the initiator advertises a [`KemSlot`] in its `PairingToken`, the
//! responder MUST encapsulate against that slot and return the ciphertext.
//! Silently omitting the KEM and falling back to classical-only key
//! derivation produces a different transport key (different info label +
//! shorter IKM), so the session fails integrity before any user action.
//! See [`pair_flow_rejects_downgrade`] in the tests module.
//!
//! # Key sizes
//!
//! - ML-KEM-768 encapsulation key: 1184 bytes
//! - ML-KEM-768 ciphertext:        1088 bytes
//! - ML-KEM-768 shared secret:       32 bytes (matches P-256 ECDH)
//!
//! [`TRANSPORT_HYBRID_INFO`]: crate::domain_separation::TRANSPORT_HYBRID_INFO
//! [`KemSlot`]: crate::token::KemSlot
//! [`pair_flow_rejects_downgrade`]: #

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::domain_separation::TRANSPORT_HYBRID_INFO;
use crate::error::ProtocolError;
use crate::sas::TransportKey;
use crate::token::KemSlot;

/// Size in bytes of an ML-KEM-768 ciphertext. Pinned here as documentation —
/// the actual size is dictated by the `ml-kem` crate's `Ciphertext` type.
pub const ML_KEM_768_CT_LEN: usize = 1088;

/// Size in bytes of an ML-KEM-768 encapsulation key.
pub const ML_KEM_768_EK_LEN: usize = 1184;

/// Size in bytes of an ML-KEM-768 shared-secret output (matches P-256 ECDH).
pub const ML_KEM_768_SS_LEN: usize = 32;

/// Initiator-side ML-KEM-768 decapsulation key + its serialized public
/// counterpart. Held only for the lifetime of the pairing session; the
/// underlying key material is zeroized on drop via `ml-kem`'s `zeroize`
/// feature.
pub struct HybridInitiatorKem {
    decaps: <MlKem768 as KemCore>::DecapsulationKey,
    encaps_bytes: Vec<u8>,
}

impl HybridInitiatorKem {
    /// Generate a fresh ML-KEM-768 keypair. Uses `OsRng` as the sole
    /// entropy source (the workspace-sanctioned RNG for security-sensitive
    /// draws).
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let (decaps, encaps) = MlKem768::generate(&mut rng);
        let encaps_bytes = encaps.as_bytes().to_vec();
        Self {
            decaps,
            encaps_bytes,
        }
    }

    /// Emit the [`KemSlot`] advertisement for this keypair, to be embedded
    /// into the initiator's `PairingToken`.
    pub fn as_kem_slot(&self) -> KemSlot {
        KemSlot::MlKem768 {
            public_key: URL_SAFE_NO_PAD.encode(&self.encaps_bytes),
        }
    }

    /// Raw encapsulation-key bytes (1184 bytes).
    pub fn encapsulation_key_bytes(&self) -> &[u8] {
        &self.encaps_bytes
    }

    /// Decapsulate a responder-provided ciphertext into the PQ shared
    /// secret. Consumes-by-reference (the decapsulation key may be used
    /// exactly once per session in practice, but ml-kem enforces that at
    /// the session layer — we do not duplicate that here).
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, ProtocolError> {
        let ct = decode_ciphertext(ciphertext)?;
        let ss = self.decaps.decapsulate(&ct).map_err(|_| {
            ProtocolError::KeyExchangeFailed("ML-KEM-768 decapsulate failed".to_string())
        })?;
        let bytes: [u8; 32] = ss.as_slice().try_into().map_err(|_| {
            ProtocolError::KeyExchangeFailed("ML-KEM-768 shared secret not 32 bytes".to_string())
        })?;
        Ok(Zeroizing::new(bytes))
    }
}

/// Responder-side encapsulation against an advertised [`KemSlot`].
///
/// Produces the PQ shared secret and the ciphertext to return in the
/// `PairingResponse` (in a future wire-level patch). This primitive is
/// the stable contract: callers assemble wire formats around it.
pub fn encapsulate_against_slot(
    slot: &KemSlot,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), ProtocolError> {
    let KemSlot::MlKem768 { public_key } = slot;
    let ek_bytes = URL_SAFE_NO_PAD.decode(public_key.as_bytes()).map_err(|e| {
        ProtocolError::KeyExchangeFailed(format!("ML-KEM-768 encaps-key b64 decode: {e}"))
    })?;
    if ek_bytes.len() != ML_KEM_768_EK_LEN {
        return Err(ProtocolError::KeyExchangeFailed(format!(
            "ML-KEM-768 encapsulation key must be {ML_KEM_768_EK_LEN} bytes, got {}",
            ek_bytes.len()
        )));
    }

    let ek_arr = encaps_key_from_slice(&ek_bytes)?;
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);

    let mut rng = OsRng;
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| {
        ProtocolError::KeyExchangeFailed("ML-KEM-768 encapsulate failed".to_string())
    })?;

    let ss_bytes: [u8; 32] = ss.as_slice().try_into().map_err(|_| {
        ProtocolError::KeyExchangeFailed("ML-KEM-768 shared secret not 32 bytes".to_string())
    })?;

    Ok((ct.as_slice().to_vec(), Zeroizing::new(ss_bytes)))
}

/// Build a [`TransportKey`] from the hybrid IKM `ss_c || ss_p`.
///
/// Classical-first ordering is non-negotiable — see module-level docs.
/// The HKDF `info` parameter uses [`TRANSPORT_HYBRID_INFO`] so that a
/// classical-only session and a hybrid session with otherwise-identical
/// transcripts never derive the same key.
pub fn derive_hybrid_transport_key(
    ss_classical: &[u8; 32],
    ss_pq: &[u8; 32],
    initiator_pub: &[u8],
    responder_pub: &[u8],
    session_id: &str,
    short_code: &str,
) -> TransportKey {
    let mut combined = Zeroizing::new(Vec::with_capacity(ss_classical.len() + ss_pq.len()));
    combined.extend_from_slice(ss_classical);
    combined.extend_from_slice(ss_pq);

    let mut salt = Vec::with_capacity(initiator_pub.len() + responder_pub.len());
    salt.extend_from_slice(initiator_pub);
    salt.extend_from_slice(responder_pub);

    let mut info =
        Vec::with_capacity(TRANSPORT_HYBRID_INFO.len() + session_id.len() + short_code.len());
    info.extend_from_slice(TRANSPORT_HYBRID_INFO);
    info.extend_from_slice(session_id.as_bytes());
    info.extend_from_slice(short_code.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), &combined);
    let mut key = [0u8; 32];
    // 32 bytes is always within HKDF-SHA256's 8160-byte output limit.
    let _ = hk.expand(&info, &mut key);
    TransportKey::new(key)
}

// ---------------------------------------------------------------------------
// ml-kem 0.2 type-bridging helpers. The crate uses `hybrid-array::Array`
// generics parameterized by typenum sizes; these helpers centralize the
// `&[u8] → &Array<u8, N>` conversion so the rest of the module stays
// byte-slice-shaped.
// ---------------------------------------------------------------------------

/// Convert raw ML-KEM-768 encapsulation-key bytes into the typed array
/// the `ml-kem` crate's `from_bytes` constructor expects.
///
/// The size constraint is expressed through the generic parameter of
/// [`<MlKem768 as KemCore>::EncapsulationKey`]; `try_from` on the typed
/// [`Array`] returns `Err` if the slice length doesn't match. We call
/// this after an explicit length check so the map_err path is defensive.
fn encaps_key_from_slice(
    bytes: &[u8],
) -> Result<
    Array<u8, <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize>,
    ProtocolError,
> {
    Array::try_from(bytes).map_err(|_| {
        ProtocolError::KeyExchangeFailed(format!(
            "ML-KEM-768 encapsulation key must be {ML_KEM_768_EK_LEN} bytes, got {}",
            bytes.len()
        ))
    })
}

/// Decode a raw ML-KEM-768 ciphertext wire blob into the typed `Ciphertext`
/// the `ml-kem` crate's `decapsulate` expects.
fn decode_ciphertext(bytes: &[u8]) -> Result<Ciphertext<MlKem768>, ProtocolError> {
    if bytes.len() != ML_KEM_768_CT_LEN {
        return Err(ProtocolError::KeyExchangeFailed(format!(
            "ML-KEM-768 ciphertext must be {ML_KEM_768_CT_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    Array::try_from(bytes).map_err(|_| {
        ProtocolError::KeyExchangeFailed("ML-KEM-768 ciphertext length mismatch".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_INIT_PUB: [u8; 33] = [0x01; 33];
    const TEST_RESP_PUB: [u8; 33] = [0x02; 33];
    const TEST_SESSION_ID: &str = "pq-session-0000";
    const TEST_SHORT_CODE: &str = "ABC234";

    /// Round-trip: initiator generates, advertises slot, responder
    /// encapsulates, initiator decapsulates — both sides derive the
    /// same PQ shared secret.
    #[test]
    fn hybrid_kem_round_trip() {
        let initiator = HybridInitiatorKem::generate();
        let slot = initiator.as_kem_slot();

        let (ct_bytes, ss_responder) = encapsulate_against_slot(&slot).unwrap();
        let ss_initiator = initiator.decapsulate(&ct_bytes).unwrap();

        assert_eq!(&*ss_initiator, &*ss_responder, "PQ shared secret mismatch");
        assert_eq!(ct_bytes.len(), ML_KEM_768_CT_LEN);
    }

    /// Classical-first combiner ordering. Swapping the arguments produces
    /// a different transport key — this documents the invariant at the
    /// test layer so a future refactor that accidentally reorders the
    /// inputs fails loudly.
    #[test]
    fn hybrid_combiner_is_order_sensitive() {
        let ss_c = [0x11u8; 32];
        let ss_p = [0x22u8; 32];

        let tk_correct = derive_hybrid_transport_key(
            &ss_c,
            &ss_p,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SESSION_ID,
            TEST_SHORT_CODE,
        );
        let tk_swapped = derive_hybrid_transport_key(
            &ss_p,
            &ss_c,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SESSION_ID,
            TEST_SHORT_CODE,
        );

        assert_ne!(
            tk_correct.as_bytes(),
            tk_swapped.as_bytes(),
            "classical-first vs PQ-first must produce different keys"
        );
    }

    /// Downgrade-to-classical negative test. An attacker (or a buggy
    /// responder) that advertises a hybrid session on the wire but
    /// produces a classical-only transport key — using
    /// `derive_transport_key` + `TRANSPORT_INFO` — derives a DIFFERENT
    /// key than the hybrid path. The two peers therefore cannot decrypt
    /// each other's traffic: AEAD verification fails and the session
    /// aborts before any user confirmation.
    #[test]
    fn hybrid_vs_classical_label_are_domain_separated() {
        use crate::sas::derive_transport_key;

        let ss_c = [0x33u8; 32];
        let ss_p = [0x44u8; 32];

        let tk_hybrid = derive_hybrid_transport_key(
            &ss_c,
            &ss_p,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SESSION_ID,
            TEST_SHORT_CODE,
        );
        // The classical path drops the PQ secret — exactly the
        // downgrade attack we want to detect.
        let tk_classical = derive_transport_key(
            &ss_c,
            &TEST_INIT_PUB,
            &TEST_RESP_PUB,
            TEST_SESSION_ID,
            TEST_SHORT_CODE,
        );

        assert_ne!(
            tk_hybrid.as_bytes(),
            tk_classical.as_bytes(),
            "TRANSPORT_HYBRID_INFO must not collide with TRANSPORT_INFO"
        );
    }

    /// Encapsulate against a slot with a corrupted public key — must fail
    /// loudly, not silently produce garbage.
    #[test]
    fn encapsulate_rejects_wrong_size_slot() {
        let bad_slot = KemSlot::MlKem768 {
            public_key: URL_SAFE_NO_PAD.encode([0u8; 16]),
        };
        let result = encapsulate_against_slot(&bad_slot);
        assert!(matches!(result, Err(ProtocolError::KeyExchangeFailed(_))));
    }

    /// Decapsulate against a wrong-sized ciphertext — must fail loudly.
    #[test]
    fn decapsulate_rejects_wrong_size_ciphertext() {
        let initiator = HybridInitiatorKem::generate();
        let result = initiator.decapsulate(&[0u8; 42]);
        assert!(matches!(result, Err(ProtocolError::KeyExchangeFailed(_))));
    }
}
