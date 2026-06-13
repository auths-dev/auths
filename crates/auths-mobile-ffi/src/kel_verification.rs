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
//! - A delegated (`dip`/`drt`) KEL is refused by [`validate_kel_json`]: a
//!   single-KEL entrypoint cannot supply the delegator's anchoring seals.
//!   The device-link path that *can* verify it — [`validate_delegated_kel_json`]
//!   — carries the delegator (root) KEL alongside the device KEL, authenticates
//!   both, and resolves each delegated event against the delegator's
//!   independently-proven anchoring seals.

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
    // Pairing fails closed on a count mismatch (an unauthenticated KEL never
    // degrades to a structural-only replay); the rule lives in auths-keri.
    let signed = authenticate_kel(&kel_json, &attachments_json)?;

    // No delegator lookup: a delegated (`dip`/`drt`) KEL fails closed here, by
    // design — use `validate_delegated_kel_json`, which carries the delegator KEL.
    let state = auths_keri::validate_signed_kel(&signed, None)
        .map_err(|e| MobileError::KelVerificationFailed(e.to_string()))?;

    verified_key_state(state)
}

/// Authenticate a **delegated device KEL** against its delegator's KEL and
/// return the device's key state.
///
/// A delegated identifier's inception (`dip`) and rotations (`drt`) are only
/// authorized when the delegator anchored them — its KEL must carry an `ixn`
/// seal back-referencing each delegated event. A single-KEL entrypoint
/// ([`validate_kel_json`]) therefore fails closed on a `dip`/`drt`: it has no
/// delegator KEL to resolve those anchoring seals against. This is the
/// device-link path the app's *device rows* need — it carries the delegator
/// (root) KEL alongside the device KEL, the same shape the WASM verifier's
/// `verifyDeviceLink` resolves.
///
/// Both KELs are authenticated, not asserted-trusted: the delegator KEL is
/// replayed signature-by-signature first ([`auths_keri::validate_signed_kel`]),
/// and only its proven events seed the [`auths_keri::KelSealIndex`] the device
/// KEL's delegated events resolve through. A forged delegator KEL, a delegator
/// with no anchoring seal for the device's `dip`, or a device event whose `-G`
/// back-reference doesn't match the delegator's seal all fail closed — there is
/// no structural-only fallback on either side.
///
/// Args:
/// * `device_kel_json`: JSON array of the delegated device's KEL events
///   (`dip` first, then `drt`/`ixn`).
/// * `device_attachments_json`: JSON array of the device KEL's per-event CESR
///   `-A##` indexed-signature groups, one per event.
/// * `delegator_kel_json`: JSON array of the delegator (root) KEL events.
/// * `delegator_attachments_json`: JSON array of the delegator KEL's per-event
///   CESR signature groups, one per event.
///
/// Usage:
/// ```ignore
/// // iOS Swift — device rows flip amber→green once proven on-device:
/// let device = try validateDelegatedKelJson(
///     deviceKelJson: deviceKel, deviceAttachmentsJson: deviceAtts,
///     delegatorKelJson: rootKel, delegatorAttachmentsJson: rootAtts)
/// guard device.did == claimedDeviceDid else { /* registry lied */ }
/// ```
#[uniffi::export]
pub fn validate_delegated_kel_json(
    device_kel_json: String,
    device_attachments_json: String,
    delegator_kel_json: String,
    delegator_attachments_json: String,
) -> Result<VerifiedKeyState, MobileError> {
    // Authenticate the delegator first: only events proven against the
    // delegator's own in-force key-state may anchor a delegated device event.
    let delegator = authenticate_kel(&delegator_kel_json, &delegator_attachments_json)?;
    let delegator_events: Vec<auths_keri::Event> =
        delegator.iter().map(|s| s.event.clone()).collect();
    let seal_index = auths_keri::KelSealIndex::from_events(&delegator_events);

    let device = authenticate_kel(&device_kel_json, &device_attachments_json)?;
    let state = auths_keri::validate_signed_kel(&device, Some(&seal_index))
        .map_err(|e| MobileError::KelVerificationFailed(e.to_string()))?;

    verified_key_state(state)
}

/// Parse a KEL's events + CESR attachments and pair them into authenticatable
/// [`auths_keri::SignedEvent`]s, fail-closed on an absent/short attachment list
/// (the unauthenticated-KEL refusal lives once in `auths-keri`).
///
/// Each attachment is parsed as a delegated attachment — the `-A##`
/// indexed-signature group, optionally followed by a `-G##` `SealSourceCouple`.
/// On a `dip`/`drt` the couple's [`auths_keri::SourceSeal`] is rehydrated onto
/// the event's `source_seal` (the JSON body never carries it — it is
/// `#[serde(skip)]`), so the bilateral delegation binding the delegator's
/// [`auths_keri::KelSealIndex`] is checked against survives the JSON wire. A
/// non-delegated event that carries a stray `-G` couple is rejected.
fn authenticate_kel(
    kel_json: &str,
    attachments_json: &str,
) -> Result<Vec<auths_keri::SignedEvent>, MobileError> {
    if kel_json.len() > MAX_KEL_INPUT_BYTES || attachments_json.len() > MAX_KEL_INPUT_BYTES {
        return Err(MobileError::Serialization(format!(
            "KEL input too large: max {MAX_KEL_INPUT_BYTES} bytes per field"
        )));
    }

    let events = auths_keri::parse_kel_json(kel_json)
        .map_err(|e| MobileError::Serialization(format!("Invalid KEL JSON: {e}")))?;
    let attachments: Vec<String> = serde_json::from_str(attachments_json)
        .map_err(|e| MobileError::Serialization(format!("Invalid attachments JSON: {e}")))?;

    if attachments.len() != events.len() {
        // An unsigned event is unauthenticatable; refuse before any work rather
        // than degrade to a structural-only replay (the same rule
        // `pair_kel_attachments` enforces — restated here because this path
        // parses delegated attachments).
        return Err(MobileError::KelVerificationFailed(format!(
            "KEL/attachment count mismatch ({} events vs {} attachments): the KEL is unauthenticated, refusing",
            events.len(),
            attachments.len()
        )));
    }

    events
        .into_iter()
        .zip(attachments)
        .map(|(mut event, att)| {
            let (sigs, seals) = auths_keri::parse_delegated_attachment(att.as_bytes())
                .map_err(|e| MobileError::KelVerificationFailed(e.to_string()))?;
            rehydrate_source_seal(&mut event, seals)?;
            Ok(auths_keri::SignedEvent::new(event, sigs))
        })
        .collect()
}

/// Rehydrate a delegated event's `-G` source seal from its attachment, or reject
/// a couple attached to an event that has no delegate side.
fn rehydrate_source_seal(
    event: &mut auths_keri::Event,
    seals: Vec<auths_keri::SourceSeal>,
) -> Result<(), MobileError> {
    let source_seal = match seals.into_iter().next() {
        Some(seal) => seal,
        None => return Ok(()),
    };
    match event {
        auths_keri::Event::Dip(dip) => dip.source_seal = Some(source_seal),
        auths_keri::Event::Drt(drt) => drt.source_seal = Some(source_seal),
        _ => {
            return Err(MobileError::KelVerificationFailed(
                "source-seal couple attached to a non-delegated event".to_string(),
            ));
        }
    }
    Ok(())
}

/// Project an authenticated [`auths_keri::KeyState`] into the FFI record.
fn verified_key_state(
    state: auths_keri::KeyState,
) -> Result<VerifiedKeyState, MobileError> {
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
        CesrKey, DipEvent, DipEventInit, Event, IcpEvent, IndexedSignature, IxnEvent, KeriSequence,
        Prefix, Said, Seal, SourceSeal, Threshold, VersionString, finalize_dip_event,
        finalize_icp_event, finalize_ixn_event, serialize_attachment, serialize_for_signing,
        serialize_source_seal_couples,
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

    // -----------------------------------------------------------------------
    // Delegated device-link path: validate_delegated_kel_json
    // -----------------------------------------------------------------------

    /// A delegator (root) KEL that anchors a device dip, plus the signed device
    /// dip whose `-G` source-seal couple binds it back to that anchoring ixn.
    struct DelegatedFixture {
        device_kel_json: String,
        device_attachments_json: String,
        delegator_kel_json: String,
        delegator_attachments_json: String,
        device_prefix: String,
    }

    /// Append the `-G` `SealSourceCouple` to an indexed-sig attachment so the
    /// delegate side travels on the JSON wire (the dip body never carries it).
    fn delegated_attachment(event: &Event, sk: &SigningKey, source_seal: &SourceSeal) -> String {
        let mut att = cesr_attachment(event, sk);
        let couple = serialize_source_seal_couples(std::slice::from_ref(source_seal)).unwrap();
        att.push_str(std::str::from_utf8(&couple).unwrap());
        att
    }

    /// Build the delegator+device fixture. `anchor` controls whether the root
    /// actually anchors the dip — `false` reproduces a delegation with no
    /// authorizing seal, which must fail closed.
    fn delegated_fixture(anchor: bool) -> DelegatedFixture {
        // --- delegator (root) inception ---
        let (root_icp, root_sk) = signed_icp();
        let root_prefix = root_icp.i.clone();

        // --- device delegated inception (dip), delegated by the root ---
        let device_sk = SigningKey::random(&mut OsRng);
        let device_pk = device_sk.verifying_key().to_encoded_point(true);
        let device_key = format!("1AAJ{}", URL_SAFE_NO_PAD.encode(device_pk.as_bytes()));
        let mut dip = finalize_dip_event(DipEvent::new(DipEventInit {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked(device_key)],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("EDeviceNextCommitment".to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![],
            di: root_prefix.clone(),
        }))
        .unwrap();
        let device_prefix = dip.i.clone();
        let dip_said = dip.d.clone();

        // --- delegator anchors the dip in an ixn (the authorizing seal) ---
        let mut root_kel = vec![Event::Icp(root_icp.clone())];
        let mut root_atts = vec![cesr_attachment(&root_kel[0], &root_sk)];
        if anchor {
            let ixn = finalize_ixn_event(IxnEvent {
                v: VersionString::placeholder(),
                d: Said::default(),
                i: root_prefix.clone(),
                s: KeriSequence::new(1),
                p: root_icp.d.clone(),
                a: vec![Seal::KeyEvent {
                    i: device_prefix.clone(),
                    s: KeriSequence::new(0),
                    d: dip_said.clone(),
                }],
            })
            .unwrap();
            // Delegate-side -G back-reference to the anchoring ixn.
            dip.source_seal = Some(SourceSeal {
                s: KeriSequence::new(1),
                d: ixn.d.clone(),
            });
            let ixn_event = Event::Ixn(ixn);
            root_atts.push(cesr_attachment(&ixn_event, &root_sk));
            root_kel.push(ixn_event);
        }

        // Sign the dip (over its body) and attach its -G couple if present.
        let dip_event = Event::Dip(dip.clone());
        let device_att = match &dip.source_seal {
            Some(seal) => delegated_attachment(&dip_event, &device_sk, seal),
            None => cesr_attachment(&dip_event, &device_sk),
        };

        let (delegator_kel_json, delegator_attachments_json) = to_json(&root_kel, &root_atts);
        let (device_kel_json, device_attachments_json) =
            to_json(&[dip_event], &[device_att]);

        DelegatedFixture {
            device_kel_json,
            device_attachments_json,
            delegator_kel_json,
            delegator_attachments_json,
            device_prefix: device_prefix.as_str().to_string(),
        }
    }

    #[test]
    fn verifies_anchored_delegated_device_kel() {
        let f = delegated_fixture(true);
        let state = validate_delegated_kel_json(
            f.device_kel_json,
            f.device_attachments_json,
            f.delegator_kel_json,
            f.delegator_attachments_json,
        )
        .expect("an anchored delegated device KEL must verify against its delegator");
        assert_eq!(state.prefix, f.device_prefix);
        assert_eq!(state.did, format!("did:keri:{}", f.device_prefix));
        assert_eq!(state.sequence, 0);
    }

    #[test]
    fn single_kel_entrypoint_still_fails_closed_on_a_dip() {
        // The delegated KEL must NOT verify through the single-KEL entrypoint —
        // that path has no delegator seals and must refuse the dip.
        let f = delegated_fixture(true);
        let err = validate_kel_json(f.device_kel_json, f.device_attachments_json).unwrap_err();
        assert!(
            matches!(err, MobileError::KelVerificationFailed(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_delegated_device_with_no_anchoring_seal() {
        // The delegator never anchored the dip: no seal authorizes the
        // delegation, so it must fail closed even with the delegator KEL present.
        let f = delegated_fixture(false);
        let err = validate_delegated_kel_json(
            f.device_kel_json,
            f.device_attachments_json,
            f.delegator_kel_json,
            f.delegator_attachments_json,
        )
        .unwrap_err();
        assert!(
            matches!(err, MobileError::KelVerificationFailed(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_delegated_device_against_forged_delegator() {
        // A delegator KEL whose inception signature doesn't verify cannot seed a
        // trusted seal index — the whole device-link verification fails closed.
        let f = delegated_fixture(true);
        let forged_delegator_atts = serde_json::to_string(&[
            // Replace the root's real signatures with an unrelated signer's.
            {
                let (decoy, sk) = signed_icp();
                cesr_attachment(&Event::Icp(decoy), &sk)
            },
            "-AAB".to_string(),
        ])
        .unwrap();
        let err = validate_delegated_kel_json(
            f.device_kel_json,
            f.device_attachments_json,
            f.delegator_kel_json,
            forged_delegator_atts,
        )
        .unwrap_err();
        assert!(
            matches!(err, MobileError::KelVerificationFailed(_)),
            "got {err:?}"
        );
    }
}
