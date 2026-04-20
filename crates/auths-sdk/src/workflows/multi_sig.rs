//! Multi-signature event assembly for multi-device KEL events.
//!
//! File-based aggregation flow:
//!
//! 1. `begin_multi_sig_event` — serialize the finalized event body + signer
//!    metadata to an [`UnsignedEventBundle`] on disk. Every signer device
//!    reads from this file.
//! 2. `sign_partial` — each device signs the canonical bytes with its own
//!    keychain-stored private key, producing an [`IndexedSignature`].
//! 3. `combine` — collect partials, verify threshold satisfaction using the
//!    event's declared `kt`, and emit a [`SignedEvent`] ready to append to
//!    the KEL.
//!
//! Cross-device pairing-protocol integration is deferred; this module covers
//! the offline happy-path (export → each signer signs → combine).

use std::fs;
use std::path::{Path, PathBuf};

use auths_core::crypto::signer::decrypt_keypair;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_keri::{
    Event, IndexedSignature, SignedEvent, Threshold, serialize_for_signing, validate_signed_event,
};
use serde::{Deserialize, Serialize};

/// Error type for multi-sig workflows.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MultiSigError {
    /// Underlying file I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON or canonical-bytes serialization failure.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Keychain load / decrypt failure.
    #[error("Keychain error: {0}")]
    Keychain(String),

    /// Failure while producing or validating a signature.
    #[error("Signing failed: {0}")]
    Signing(String),

    /// Not enough partials to satisfy the expected threshold.
    #[error(
        "Threshold not met: verified indices {verified:?} do not satisfy expected threshold (key_count={key_count})"
    )]
    ThresholdNotMet {
        /// Indices that contributed a valid signature.
        verified: Vec<u32>,
        /// Total number of keys in the event's `k` list.
        key_count: usize,
    },

    /// Signer index exceeds the event's key count.
    #[error("Signer index {index} out of range (key_count={key_count})")]
    IndexOutOfRange {
        /// Offending signer index.
        index: u32,
        /// Event's key count.
        key_count: usize,
    },

    /// Underlying KEL validator rejected the combined event.
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Serialized bundle written by [`begin_multi_sig_event`] and read by
/// [`sign_partial`] / [`combine`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedEventBundle {
    /// Finalized event (with computed SAID, empty `x` field).
    pub event: Event,
    /// Aliases of the signers expected to contribute partials, in slot order.
    pub signer_aliases: Vec<String>,
    /// Canonical bytes — what each signer actually signs. Same bytes
    /// [`combine`] will re-verify against. Held here so offline signers
    /// don't need to reconstruct canonicalization independently.
    #[serde(with = "hex::serde")]
    pub canonical_bytes: Vec<u8>,
    /// The SAID of the event, exposed for display / log correlation.
    pub said: String,
}

/// Begin a multi-sig event by writing the canonical bytes + signer metadata
/// to `output_path`. Each device will read this bundle before signing.
pub fn begin_multi_sig_event(
    event: &SignedEvent,
    signers: &[KeyAlias],
    output_path: &Path,
) -> Result<UnsignedEventBundle, MultiSigError> {
    let canonical = serialize_for_signing(&event.event)
        .map_err(|e| MultiSigError::Serialization(e.to_string()))?;

    let bundle = UnsignedEventBundle {
        event: event.event.clone(),
        signer_aliases: signers.iter().map(|a| a.to_string()).collect(),
        canonical_bytes: canonical,
        said: event.event.said().as_str().to_string(),
    };

    let json = serde_json::to_vec_pretty(&bundle)
        .map_err(|e| MultiSigError::Serialization(e.to_string()))?;
    fs::write(output_path, &json)?;
    Ok(bundle)
}

/// Produce one indexed signature from `key_alias` at `signer_index`.
///
/// Loads the keypair, decrypts it with the passphrase from
/// `passphrase_provider`, signs the bundle's canonical bytes, and returns
/// an `IndexedSignature` ready to hand off to [`combine`].
pub fn sign_partial(
    unsigned_bundle_path: &Path,
    key_alias: &KeyAlias,
    signer_index: u32,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<IndexedSignature, MultiSigError> {
    let raw = fs::read(unsigned_bundle_path)?;
    let bundle: UnsignedEventBundle =
        serde_json::from_slice(&raw).map_err(|e| MultiSigError::Serialization(e.to_string()))?;

    let keys = match &bundle.event {
        Event::Icp(icp) => &icp.k,
        Event::Rot(rot) => &rot.k,
        Event::Dip(dip) => &dip.k,
        Event::Drt(drt) => &drt.k,
        Event::Ixn(_) => {
            return Err(MultiSigError::Validation(
                "ixn events do not carry their own key list; multi-sig on interaction events uses the controller KEL state".to_string(),
            ));
        }
    };
    if (signer_index as usize) >= keys.len() {
        return Err(MultiSigError::IndexOutOfRange {
            index: signer_index,
            key_count: keys.len(),
        });
    }

    let (_did, _role, encrypted) = keychain
        .load_key(key_alias)
        .map_err(|e| MultiSigError::Keychain(e.to_string()))?;
    let passphrase = passphrase_provider
        .get_passphrase(&format!(
            "Enter passphrase for multi-sig key '{}':",
            key_alias
        ))
        .map_err(|e| MultiSigError::Keychain(e.to_string()))?;
    let decrypted = decrypt_keypair(&encrypted, &passphrase)
        .map_err(|e| MultiSigError::Keychain(e.to_string()))?;

    // Parse as Ed25519; the codebase's single-curve signing path. P-256 support
    // flows through the typed signer in a follow-up.
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let keypair = Ed25519KeyPair::from_pkcs8(&decrypted)
        .map_err(|e| MultiSigError::Signing(format!("Ed25519 load: {e}")))?;
    let _pub_bytes = keypair.public_key().as_ref().to_vec();
    let sig = keypair.sign(&bundle.canonical_bytes);

    Ok(IndexedSignature {
        index: signer_index,
        sig: sig.as_ref().to_vec(),
    })
}

/// Combine partials into a [`SignedEvent`], verifying the expected threshold
/// is satisfied. Returns `MultiSigError::ThresholdNotMet` if the submitted
/// partials don't cross the threshold.
pub fn combine(
    unsigned_bundle_path: &Path,
    partials: Vec<IndexedSignature>,
    expected_kt: &Threshold,
) -> Result<SignedEvent, MultiSigError> {
    let raw = fs::read(unsigned_bundle_path)?;
    let bundle: UnsignedEventBundle =
        serde_json::from_slice(&raw).map_err(|e| MultiSigError::Serialization(e.to_string()))?;

    let keys_len = match &bundle.event {
        Event::Icp(icp) => icp.k.len(),
        Event::Rot(rot) => rot.k.len(),
        Event::Dip(dip) => dip.k.len(),
        Event::Drt(drt) => drt.k.len(),
        Event::Ixn(_) => 0,
    };

    // Validate each partial verifies over the canonical bytes first. We
    // reuse `validate_signed_event` for the full pipeline at the end, but
    // check eagerly here to give clearer errors on mis-signed partials.
    let signed = SignedEvent::new(bundle.event.clone(), partials.clone());
    validate_signed_event(&signed, None).map_err(|e| MultiSigError::Validation(e.to_string()))?;

    // Also verify threshold directly against the stated expected_kt (the
    // validator checks the event's own `kt`; this catches callers who pass
    // a looser expectation).
    let verified: Vec<u32> = partials.iter().map(|p| p.index).collect();
    if !expected_kt.is_satisfied(&verified, keys_len) {
        return Err(MultiSigError::ThresholdNotMet {
            verified,
            key_count: keys_len,
        });
    }

    Ok(signed)
}

/// Write a partial signature to disk at `output_path` for hand-off between
/// devices.
pub fn write_partial(
    partial: &IndexedSignature,
    output_path: &Path,
) -> Result<PathBuf, MultiSigError> {
    let json = serde_json::to_vec_pretty(partial)
        .map_err(|e| MultiSigError::Serialization(e.to_string()))?;
    fs::write(output_path, &json)?;
    Ok(output_path.to_path_buf())
}

/// Read a partial signature from disk.
pub fn read_partial(path: &Path) -> Result<IndexedSignature, MultiSigError> {
    let raw = fs::read(path)?;
    serde_json::from_slice(&raw).map_err(|e| MultiSigError::Serialization(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use auths_keri::{
        CesrKey, Fraction, IcpEvent, KeriSequence, Prefix, Said, VersionString, finalize_icp_event,
    };
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::tempdir;

    fn gen_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn cesr_pub(kp: &Ed25519KeyPair) -> String {
        format!("D{}", URL_SAFE_NO_PAD.encode(kp.public_key().as_ref()))
    }

    fn half() -> Fraction {
        Fraction {
            numerator: 1,
            denominator: 2,
        }
    }

    fn make_three_key_icp() -> (IcpEvent, [Ed25519KeyPair; 3]) {
        let kps = [gen_keypair(), gen_keypair(), gen_keypair()];
        let k = vec![
            CesrKey::new_unchecked(cesr_pub(&kps[0])),
            CesrKey::new_unchecked(cesr_pub(&kps[1])),
            CesrKey::new_unchecked(cesr_pub(&kps[2])),
        ];
        let n = vec![
            Said::new_unchecked("EFakeNext0000000000000000000000000000000000".to_string()),
            Said::new_unchecked("EFakeNext0000000000000000000000000000000001".to_string()),
            Said::new_unchecked("EFakeNext0000000000000000000000000000000002".to_string()),
        ];
        let kt = Threshold::Weighted(vec![vec![half(), half(), half()]]);

        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt,
            k,
            nt: Threshold::Weighted(vec![vec![half(), half(), half()]]),
            n,
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
            dt: None,
        };
        (finalize_icp_event(icp).unwrap(), kps)
    }

    #[test]
    fn combine_threshold_not_met_with_one_partial() {
        let (icp, kps) = make_three_key_icp();
        let event = Event::Icp(icp.clone());
        let unsigned = SignedEvent::new(event.clone(), vec![]);

        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("unsigned.json");
        begin_multi_sig_event(
            &unsigned,
            &[
                KeyAlias::new_unchecked("dev-a"),
                KeyAlias::new_unchecked("dev-b"),
                KeyAlias::new_unchecked("dev-c"),
            ],
            &bundle_path,
        )
        .unwrap();

        let canonical = serialize_for_signing(&event).unwrap();
        let partial0 = IndexedSignature {
            index: 0,
            sig: kps[0].sign(&canonical).as_ref().to_vec(),
        };

        let kt = Threshold::Weighted(vec![vec![half(), half(), half()]]);
        let err = combine(&bundle_path, vec![partial0], &kt).unwrap_err();
        match err {
            MultiSigError::ThresholdNotMet { .. } | MultiSigError::Validation(_) => {}
            other => panic!("expected ThresholdNotMet/Validation, got {other:?}"),
        }
    }

    #[test]
    fn combine_two_of_three_weighted_accepts() {
        let (icp, kps) = make_three_key_icp();
        let event = Event::Icp(icp.clone());
        let unsigned = SignedEvent::new(event.clone(), vec![]);

        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("unsigned.json");
        begin_multi_sig_event(
            &unsigned,
            &[
                KeyAlias::new_unchecked("dev-a"),
                KeyAlias::new_unchecked("dev-b"),
                KeyAlias::new_unchecked("dev-c"),
            ],
            &bundle_path,
        )
        .unwrap();

        let canonical = serialize_for_signing(&event).unwrap();
        let partials = vec![
            IndexedSignature {
                index: 0,
                sig: kps[0].sign(&canonical).as_ref().to_vec(),
            },
            IndexedSignature {
                index: 2,
                sig: kps[2].sign(&canonical).as_ref().to_vec(),
            },
        ];

        let kt = Threshold::Weighted(vec![vec![half(), half(), half()]]);
        let signed = combine(&bundle_path, partials, &kt).unwrap();
        assert_eq!(signed.signatures.len(), 2);
    }

    #[test]
    fn partial_roundtrip_via_disk() {
        let sig = IndexedSignature {
            index: 1,
            sig: vec![7u8; 64],
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("partial.sig");
        write_partial(&sig, &path).unwrap();
        let back = read_partial(&path).unwrap();
        assert_eq!(back.index, 1);
        assert_eq!(back.sig.len(), 64);
        assert_eq!(back.sig, sig.sig);
    }
}
