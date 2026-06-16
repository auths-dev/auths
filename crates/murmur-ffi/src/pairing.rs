//! Cross-device pairing over the FFI — the transport-agnostic P-256 ECDH + SAS
//! handshake from `auths-pairing-protocol`, driven over QR so a new device joins
//! an identity it scans in person. The app supplies the transport (QR codes); this
//! layer is the cryptography, reused rather than re-implemented.
//!
//! Flow (two devices, in person):
//! ```text
//!   initiator (has the identity)              responder (the new device)
//!   ----------------------------              --------------------------
//!   PairingInitiator::new → token_qr() ──QR1──▶ PairingResponder::respond(token)
//!                                                  → response_bytes + SAS
//!   complete(response_bytes) ◀──────────QR2──── (show response_bytes as a QR)
//!     → SAS                                        compare the SAS in person
//! ```
//! Both sides independently derive the **same** 10-byte SAS from the ECDH
//! transcript; the user comparing them in person is what defeats a
//! man-in-the-middle on the QR hop.

use std::sync::{Arc, Mutex};

use auths_keri::Capability;
use auths_pairing_protocol::{respond_to_pairing, sas, PairingProtocol};

use crate::MurmurError;

/// Build an injected `now` from app wall-clock millis (UTC). Time is injected, not
/// fetched, so the handshake stays deterministic and testable.
fn at(now_ms: i64) -> Result<chrono::DateTime<chrono::Utc>, MurmurError> {
    chrono::DateTime::from_timestamp_millis(now_ms)
        .ok_or_else(|| MurmurError::Malformed("invalid pairing timestamp".into()))
}

/// What the initiator learns once pairing completes.
#[derive(uniffi::Record)]
pub struct PairingOutcome {
    /// The raw 10-byte Short Authentication String (compare across devices).
    pub sas: Vec<u8>,
    /// The SAS rendered as emoji for the confirmation screen.
    pub sas_display: String,
    /// The newly-paired device's DID.
    pub peer_did: String,
    /// The newly-paired device's signing public key (to anchor as a delegation).
    pub peer_signing_pubkey: Vec<u8>,
}

/// What the responder produces: the bytes to show as the second QR, plus its SAS.
#[derive(uniffi::Record)]
pub struct PairingResponse {
    /// Serialized response; the initiator scans this and calls `complete`.
    pub response_bytes: Vec<u8>,
    pub sas: Vec<u8>,
    pub sas_display: String,
}

/// The device that already holds the identity. It generates the pairing offer and
/// completes the handshake. Holds the ephemeral ECDH secret, so it is single-use.
#[derive(uniffi::Object)]
pub struct PairingInitiator {
    inner: Mutex<Option<PairingProtocol>>,
    token_bytes: Vec<u8>,
}

#[uniffi::export]
impl PairingInitiator {
    /// Begin pairing: generate the offer for `controller_did` (the identity this
    /// device controls). `now_ms` is the app's wall clock in UTC milliseconds.
    #[uniffi::constructor]
    pub fn new(controller_did: String, now_ms: i64) -> Result<Arc<Self>, MurmurError> {
        let now = at(now_ms)?;
        let (protocol, token) = PairingProtocol::initiate(
            now,
            controller_did,
            String::new(),
            vec![Capability::sign_commit()],
        )
        .map_err(|e| MurmurError::Rejected(format!("pairing initiate: {e}")))?;
        let token_bytes =
            serde_json::to_vec(&token).map_err(|e| MurmurError::Malformed(e.to_string()))?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(protocol)),
            token_bytes,
        }))
    }

    /// The offer bytes to render as the first QR (shown to the new device).
    pub fn token_qr(&self) -> Vec<u8> {
        self.token_bytes.clone()
    }

    /// Complete pairing with the new device's scanned-back response. Returns the
    /// SAS to compare in person and the device's authenticated identity. Single-use:
    /// the ephemeral secret is consumed, so a second call fails closed.
    pub fn complete(
        &self,
        response_bytes: Vec<u8>,
        now_ms: i64,
    ) -> Result<PairingOutcome, MurmurError> {
        let now = at(now_ms)?;
        let protocol = self
            .inner
            .lock()
            .map_err(|_| MurmurError::Rejected("pairing state poisoned".into()))?
            .take()
            .ok_or_else(|| MurmurError::Rejected("pairing already completed".into()))?;
        let completed = protocol
            .complete(now, &response_bytes)
            .map_err(|e| MurmurError::Rejected(format!("pairing complete: {e}")))?;
        Ok(PairingOutcome {
            sas: completed.sas.to_vec(),
            sas_display: sas::format_sas_emoji(&completed.sas),
            peer_did: completed.peer_did,
            peer_signing_pubkey: completed.peer_signing_pubkey,
        })
    }
}

/// The new device joining an identity. It mints its own signing key and produces a
/// response to a scanned offer. (In production the device key is Secure-Enclave-held
/// and signing happens off-Rust; here it is generated in software so the handshake
/// is exercisable end-to-end.)
#[derive(uniffi::Object)]
pub struct PairingResponder {
    seed: auths_crypto::TypedSeed,
    pubkey: Vec<u8>,
    device_did: String,
}

#[uniffi::export]
impl PairingResponder {
    /// A fresh joining device identified by `device_did`, minting a P-256 key.
    #[uniffi::constructor]
    pub fn new(device_did: String) -> Result<Arc<Self>, MurmurError> {
        let (seed, pubkey) = generate_device_key()?;
        Ok(Arc::new(Self {
            seed,
            pubkey,
            device_did,
        }))
    }

    /// Respond to a scanned offer: returns the response (to show as the second QR)
    /// plus this device's SAS to compare against the other device.
    pub fn respond(
        &self,
        token_bytes: Vec<u8>,
        now_ms: i64,
    ) -> Result<PairingResponse, MurmurError> {
        let now = at(now_ms)?;
        let result = respond_to_pairing(
            now,
            &token_bytes,
            &self.seed,
            &self.pubkey,
            self.device_did.clone(),
            None,
        )
        .map_err(|e| MurmurError::Rejected(format!("pairing respond: {e}")))?;
        let response_bytes = serde_json::to_vec(&result.response)
            .map_err(|e| MurmurError::Malformed(e.to_string()))?;
        Ok(PairingResponse {
            response_bytes,
            sas: result.sas.to_vec(),
            sas_display: sas::format_sas_emoji(&result.sas),
        })
    }
}

/// Mint a P-256 signing keypair for a joining device. Software-generated here; the
/// shipped app holds the device key in the Secure Enclave.
fn generate_device_key() -> Result<(auths_crypto::TypedSeed, Vec<u8>), MurmurError> {
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePrivateKey;
    let sk = SigningKey::random(&mut OsRng);
    let pkcs8 = sk
        .to_pkcs8_der()
        .map_err(|e| MurmurError::Malformed(format!("device key encode: {e}")))?;
    let parsed = auths_crypto::parse_key_material(pkcs8.as_bytes())
        .map_err(|e| MurmurError::Malformed(format!("device key parse: {e}")))?;
    Ok((parsed.seed, parsed.public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_qr_handshake_derives_matching_sas() {
        let now_ms = 1_700_000_000_000;
        // The Mac (identity holder) creates the offer (QR1).
        let initiator = PairingInitiator::new("did:keri:mac".into(), now_ms).unwrap();
        let qr1 = initiator.token_qr();
        assert!(!qr1.is_empty());

        // The phone (new device) scans QR1 and responds (QR2) + shows its SAS.
        let responder = PairingResponder::new("did:key:phone".into()).unwrap();
        let resp = responder.respond(qr1, now_ms).unwrap();

        // The Mac scans QR2 and completes — both sides must derive the SAME SAS,
        // and the Mac learns the phone's authentic identity.
        let outcome = initiator.complete(resp.response_bytes, now_ms).unwrap();
        assert_eq!(outcome.sas, resp.sas, "both devices must derive the same SAS");
        assert!(!outcome.sas_display.is_empty());
        assert_eq!(outcome.peer_did, "did:key:phone");
        assert!(!outcome.peer_signing_pubkey.is_empty());

        // Single-use: the ephemeral secret is spent, so a second complete fails.
        assert!(initiator.complete(vec![1, 2, 3], now_ms).is_err());
    }
}
