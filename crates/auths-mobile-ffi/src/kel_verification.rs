//! Read-only KEL verification for registry state the app displays.
//!
//! Every other surface in this crate is write-side: it BUILDS payloads
//! the Secure Enclave signs. This module is the read side. A registry
//! sync hands the app an identity's KEL (the ordered event JSONs plus
//! one CESR indexed-signature group per event) and the app authenticates
//! it on-device before rendering it — the same authenticated replay the
//! WASM verifier exposes as `validateKelJson`, over the same auths-keri
//! core (`pair_kel_attachments` + `validate_signed_kel`). No private key
//! material is involved; the inputs are public registry bytes.
//!
//! Fail-closed properties, inherited from the core:
//! - An absent or short attachment list is an UNAUTHENTICATED KEL and is
//!   refused outright — there is no structural-only fallback.
//! - A delegated (`dip`/`drt`) KEL is refused here: a single-KEL
//!   entrypoint cannot supply the delegator's anchoring seals, so it
//!   must resolve through a path that carries the delegator KEL too.

use crate::MobileError;

/// Upper bound per JSON input. Registry KELs are small (a handful of
/// events); anything near this size is malformed or hostile input.
const MAX_KEL_INPUT_BYTES: usize = 1024 * 1024;

/// The authenticated key-state a verified KEL resolves to.
///
/// Returned only after every event's signature verified against the
/// in-force key-state, so callers can treat each field as proven —
/// e.g. compare `did` against the controller DID a registry claimed.
#[derive(Debug, Clone, uniffi::Record)]
pub struct VerifiedKeyState {
    /// The KERI identifier prefix the KEL self-addresses.
    pub prefix: String,

    /// The full DID: `did:keri:{prefix}`.
    pub did: String,

    /// Sequence number of the latest verified event.
    pub sequence: u64,

    /// Current signing key(s), CESR-encoded.
    pub current_keys: Vec<String>,

    /// SAID of the latest verified event.
    pub last_event_said: String,
}

/// Authenticate a KERI Key Event Log and return the resulting key state.
///
/// Args:
/// * `kel_json`: JSON array of KEL events (inception, rotation, interaction).
/// * `attachments_json`: JSON array of CESR text-domain `-A##` indexed-signature
///   groups, one per event — the registry's `<seq>.attachments.cesr` content,
///   verbatim.
///
/// Usage:
/// ```ignore
/// // iOS Swift
/// let state = try validateKelJson(kelJson: kelJson, attachmentsJson: attachmentsJson)
/// guard state.did == claimedControllerDid else { /* registry lied */ }
/// ```
#[uniffi::export]
pub fn validate_kel_json(
    kel_json: String,
    attachments_json: String,
) -> Result<VerifiedKeyState, MobileError> {
    if kel_json.len() > MAX_KEL_INPUT_BYTES || attachments_json.len() > MAX_KEL_INPUT_BYTES {
        return Err(MobileError::Serialization(format!(
            "KEL input too large: max {MAX_KEL_INPUT_BYTES} bytes per field"
        )));
    }

    let events = auths_keri::parse_kel_json(&kel_json)
        .map_err(|e| MobileError::Serialization(format!("Invalid KEL JSON: {e}")))?;
    let attachments: Vec<String> = serde_json::from_str(&attachments_json)
        .map_err(|e| MobileError::Serialization(format!("Invalid attachments JSON: {e}")))?;

    // Pairing fails closed on a count mismatch (an unauthenticated KEL never
    // degrades to a structural-only replay); the rule lives in auths-keri.
    let signed = auths_keri::pair_kel_attachments(events, &attachments)
        .map_err(|e| MobileError::KelVerificationFailed(e.to_string()))?;

    let state = auths_keri::validate_signed_kel(&signed, None)
        .map_err(|e| MobileError::KelVerificationFailed(e.to_string()))?;

    let prefix = state.prefix.as_str().to_string();
    Ok(VerifiedKeyState {
        did: format!("did:keri:{prefix}"),
        prefix,
        sequence: u64::try_from(state.sequence)
            .map_err(|_| MobileError::KelVerificationFailed("sequence exceeds u64".to_string()))?,
        current_keys: state
            .current_keys
            .iter()
            .map(|k| k.as_str().to_string())
            .collect(),
        last_event_said: state.last_event_said.as_str().to_string(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use auths_keri::{
        CesrKey, Event, IcpEvent, IndexedSignature, IxnEvent, KeriSequence, Prefix, Said, Seal,
        Threshold, VersionString, finalize_icp_event, finalize_ixn_event, serialize_attachment,
        serialize_for_signing,
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::elliptic_curve::rand_core::OsRng;

    /// Build a finalized single-key P-256 inception event plus its signer.
    fn signed_icp() -> (IcpEvent, SigningKey) {
        let sk = SigningKey::random(&mut OsRng);
        let compressed = sk.verifying_key().to_encoded_point(true);
        let key_encoded = format!("1AAJ{}", URL_SAFE_NO_PAD.encode(compressed.as_bytes()));

        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(key_encoded)],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("ENextCommitment".to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
        };
        (finalize_icp_event(icp).unwrap(), sk)
    }

    /// Sign `event` with `sk` and return the CESR attachment group as text.
    fn cesr_attachment(event: &Event, sk: &SigningKey) -> String {
        let payload = serialize_for_signing(event).unwrap();
        let sig: p256::ecdsa::Signature = sk.sign(&payload);
        let att = serialize_attachment(&[IndexedSignature {
            index: 0,
            prior_index: None,
            sig: sig.to_bytes().to_vec(),
        }])
        .unwrap();
        String::from_utf8(att).unwrap()
    }

    fn to_json(events: &[Event], attachments: &[String]) -> (String, String) {
        (
            serde_json::to_string(events).unwrap(),
            serde_json::to_string(attachments).unwrap(),
        )
    }

    #[test]
    fn verifies_signed_icp_and_returns_key_state() {
        let (icp, sk) = signed_icp();
        let event = Event::Icp(icp.clone());
        let att = cesr_attachment(&event, &sk);
        let (kel_json, attachments_json) = to_json(&[event], &[att]);

        let state = validate_kel_json(kel_json, attachments_json)
            .expect("a correctly signed KEL must verify");
        assert_eq!(state.prefix, icp.i.as_str());
        assert_eq!(state.did, format!("did:keri:{}", icp.i.as_str()));
        assert_eq!(state.sequence, 0);
        assert_eq!(state.current_keys, vec![icp.k[0].as_str().to_string()]);
        assert_eq!(state.last_event_said, icp.d.as_str());
    }

    #[test]
    fn verifies_icp_then_ixn() {
        let (icp, sk) = signed_icp();
        let ixn = finalize_ixn_event(IxnEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: icp.i.clone(),
            s: KeriSequence::new(1),
            p: icp.d.clone(),
            a: vec![Seal::digest("EAttest")],
        })
        .unwrap();

        let events = [Event::Icp(icp), Event::Ixn(ixn)];
        let atts = [
            cesr_attachment(&events[0], &sk),
            cesr_attachment(&events[1], &sk),
        ];
        let (kel_json, attachments_json) = to_json(&events, &atts);

        let state = validate_kel_json(kel_json, attachments_json).unwrap();
        assert_eq!(state.sequence, 1);
    }

    #[test]
    fn rejects_missing_attachments_as_unauthenticated() {
        // RT-002 shape: a structurally valid KEL with NO attachments must be
        // refused, never replayed structurally.
        let (icp, _sk) = signed_icp();
        let (kel_json, attachments_json) = to_json(&[Event::Icp(icp)], &[]);

        let err = validate_kel_json(kel_json, attachments_json).unwrap_err();
        assert!(
            matches!(err, MobileError::KelVerificationFailed(ref msg) if msg.contains("unauthenticated")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_signer() {
        let (icp, _sk) = signed_icp();
        let attacker = SigningKey::random(&mut OsRng);
        let event = Event::Icp(icp);
        let att = cesr_attachment(&event, &attacker);
        let (kel_json, attachments_json) = to_json(&[event], &[att]);

        let err = validate_kel_json(kel_json, attachments_json).unwrap_err();
        assert!(
            matches!(err, MobileError::KelVerificationFailed(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_tampered_event() {
        let (icp, sk) = signed_icp();
        let event = Event::Icp(icp);
        let att = cesr_attachment(&event, &sk);
        let kel_json = serde_json::to_string(&[event])
            .unwrap()
            .replace("\"s\":\"0\"", "\"s\":\"1\"");
        let attachments_json = serde_json::to_string(&[att]).unwrap();

        assert!(validate_kel_json(kel_json, attachments_json).is_err());
    }

    #[test]
    fn rejects_malformed_inputs() {
        assert!(matches!(
            validate_kel_json("not json".into(), "[]".into()),
            Err(MobileError::Serialization(_))
        ));
        assert!(matches!(
            validate_kel_json("[]".into(), "not json".into()),
            Err(MobileError::Serialization(_))
        ));
        let oversized = " ".repeat(MAX_KEL_INPUT_BYTES + 1);
        assert!(matches!(
            validate_kel_json(oversized, "[]".into()),
            Err(MobileError::Serialization(_))
        ));
    }
}
