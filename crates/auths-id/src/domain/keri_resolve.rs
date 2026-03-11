use auths_crypto::KeriPublicKey;
use auths_verifier::types::IdentityDID;

use super::kel_port::KelPort;
use crate::keri::{DidKeriResolution, Event, Prefix, ResolveError, parse_did_keri, validate_kel};

/// Resolves a did:keri to its current key material using loaded events.
///
/// This is a pure function — it performs no I/O. It validates the event
/// chain and decodes the current public key from the resulting key state.
///
/// Args:
/// * `events`: The ordered list of KERI events for this prefix.
/// * `did`: The full did:keri string.
/// * `prefix`: The KERI prefix (extracted from the DID).
///
/// Usage:
/// ```ignore
/// use auths_id::domain::keri_resolve::resolve_from_events;
///
/// let events = kel.get_events(&prefix)?;
/// let resolution = resolve_from_events(&events, "did:keri:EAbcdef...", &prefix)?;
/// ```
pub fn resolve_from_events(
    events: &[Event],
    did: &str,
    prefix: &Prefix,
) -> Result<DidKeriResolution, ResolveError> {
    let state = validate_kel(events)?;

    let key_encoded = state.current_key().ok_or(ResolveError::NoCurrentKey)?;
    let public_key = KeriPublicKey::parse(key_encoded)
        .map(|k| k.as_bytes().to_vec())
        .map_err(|e| ResolveError::InvalidKeyEncoding(e.to_string()))?;

    Ok(DidKeriResolution {
        did: IdentityDID::new_unchecked(did),
        prefix: prefix.clone(),
        public_key,
        sequence: state.sequence,
        can_rotate: state.can_rotate(),
        is_abandoned: state.is_abandoned,
    })
}

/// Resolves a did:keri at a specific sequence number from loaded events.
///
/// This is a pure function — it filters events to the target sequence
/// and validates only that subset.
///
/// Args:
/// * `events`: The full ordered list of KERI events.
/// * `did`: The full did:keri string.
/// * `prefix`: The KERI prefix.
/// * `target_sequence`: The sequence number to resolve at.
///
/// Usage:
/// ```ignore
/// let resolution = resolve_from_events_at_sequence(&events, did, &prefix, 0)?;
/// ```
pub fn resolve_from_events_at_sequence(
    events: &[Event],
    did: &str,
    prefix: &Prefix,
    target_sequence: u64,
) -> Result<DidKeriResolution, ResolveError> {
    let events_subset: Vec<_> = events
        .iter()
        .take_while(|e| e.sequence().value() <= target_sequence)
        .cloned()
        .collect();

    if events_subset.is_empty() {
        return Err(ResolveError::NotFound(format!(
            "No events at sequence {}",
            target_sequence
        )));
    }

    resolve_from_events(&events_subset, did, prefix)
}

/// Orchestration: resolves a did:keri using a KelPort for I/O.
///
/// Decomposes into: parse DID (pure), load events (I/O), resolve from events (pure).
///
/// Args:
/// * `kel`: The KEL port providing event storage access.
/// * `did`: The did:keri string to resolve.
///
/// Usage:
/// ```ignore
/// use auths_id::domain::keri_resolve::resolve_did_keri_via_port;
///
/// let resolution = resolve_did_keri_via_port(&kel_port, "did:keri:EAbcdef...")?;
/// ```
pub fn resolve_did_keri_via_port(
    kel: &dyn KelPort,
    did: &str,
) -> Result<DidKeriResolution, ResolveError> {
    let prefix = parse_did_keri(did)?;

    if !kel.exists(&prefix) {
        return Err(ResolveError::NotFound(prefix.as_str().to_string()));
    }

    let events = kel.get_events(&prefix)?;
    resolve_from_events(&events, did, &prefix)
}

/// Orchestration: resolves at a historical sequence via a KelPort.
///
/// Args:
/// * `kel`: The KEL port providing event storage access.
/// * `did`: The did:keri string to resolve.
/// * `target_sequence`: The sequence number to resolve at.
///
/// Usage:
/// ```ignore
/// let resolution = resolve_did_keri_at_sequence_via_port(&kel_port, did, 0)?;
/// ```
pub fn resolve_did_keri_at_sequence_via_port(
    kel: &dyn KelPort,
    did: &str,
    target_sequence: u64,
) -> Result<DidKeriResolution, ResolveError> {
    let prefix = parse_did_keri(did)?;

    if !kel.exists(&prefix) {
        return Err(ResolveError::NotFound(prefix.as_str().to_string()));
    }

    let events = kel.get_events(&prefix)?;
    resolve_from_events_at_sequence(&events, did, &prefix, target_sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::{
        Event, IcpEvent, KERI_VERSION, KeriSequence, Said, finalize_icp_event,
        serialize_for_signing,
    };
    use auths_core::crypto::said::compute_next_commitment;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn make_test_inception() -> (IcpEvent, Vec<u8>) {
        let rng = SystemRandom::new();
        let current_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let current_kp = Ed25519KeyPair::from_pkcs8(current_pkcs8.as_ref()).unwrap();
        let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let next_kp = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();

        let current_pub_encoded = format!(
            "D{}",
            URL_SAFE_NO_PAD.encode(current_kp.public_key().as_ref())
        );
        let next_commitment = compute_next_commitment(next_kp.public_key().as_ref());

        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::default(),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec![current_pub_encoded],
            nt: "1".to_string(),
            n: vec![next_commitment],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let mut finalized = finalize_icp_event(icp).unwrap();
        let canonical = serialize_for_signing(&Event::Icp(finalized.clone())).unwrap();
        let sig = current_kp.sign(&canonical);
        finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let pub_key = current_kp.public_key().as_ref().to_vec();
        (finalized, pub_key)
    }

    #[test]
    fn resolve_from_events_succeeds() {
        let (icp, expected_key) = make_test_inception();
        let prefix = icp.i.clone();
        let did = format!("did:keri:{}", prefix.as_str());
        let events = vec![Event::Icp(icp)];

        let resolution = resolve_from_events(&events, &did, &prefix).unwrap();

        assert_eq!(resolution.public_key, expected_key);
        assert_eq!(resolution.sequence, 0);
        assert!(resolution.can_rotate);
    }

    #[test]
    fn resolve_from_events_empty_fails() {
        let prefix = Prefix::new_unchecked("ETest".to_string());
        let result = resolve_from_events_at_sequence(&[], "did:keri:ETest", &prefix, 0);
        assert!(matches!(result, Err(ResolveError::NotFound(_))));
    }

    #[test]
    fn resolve_via_port_not_found() {
        let kel = InMemoryKelForTest::new();
        let result = resolve_did_keri_via_port(&kel, "did:keri:ENonexistent");
        assert!(matches!(result, Err(ResolveError::NotFound(_))));
    }

    #[test]
    fn resolve_via_port_succeeds() {
        let (icp, expected_key) = make_test_inception();
        let prefix = icp.i.clone();
        let did = format!("did:keri:{}", prefix);

        let kel = InMemoryKelForTest::new();
        kel.insert(&prefix, vec![Event::Icp(icp)]);

        let resolution = resolve_did_keri_via_port(&kel, &did).unwrap();
        assert_eq!(resolution.public_key, expected_key);
        assert_eq!(resolution.sequence, 0);
    }

    #[test]
    fn resolve_at_sequence_via_port() {
        let (icp, expected_key) = make_test_inception();
        let prefix = icp.i.clone();
        let did = format!("did:keri:{}", prefix);

        let kel = InMemoryKelForTest::new();
        kel.insert(&prefix, vec![Event::Icp(icp)]);

        let resolution = resolve_did_keri_at_sequence_via_port(&kel, &did, 0).unwrap();
        assert_eq!(resolution.public_key, expected_key);
    }

    struct InMemoryKelForTest {
        events: std::sync::Mutex<std::collections::HashMap<String, Vec<Event>>>,
    }

    impl InMemoryKelForTest {
        fn new() -> Self {
            Self {
                events: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn insert(&self, prefix: &Prefix, events: Vec<Event>) {
            self.events
                .lock()
                .unwrap()
                .insert(prefix.as_str().to_string(), events);
        }
    }

    impl KelPort for InMemoryKelForTest {
        fn exists(&self, prefix: &Prefix) -> bool {
            self.events.lock().unwrap().contains_key(prefix.as_str())
        }

        fn get_events(&self, prefix: &Prefix) -> Result<Vec<Event>, crate::keri::KelError> {
            self.events
                .lock()
                .unwrap()
                .get(prefix.as_str())
                .cloned()
                .ok_or_else(|| {
                    crate::keri::KelError::NotFound(format!(
                        "KEL not found for {}",
                        prefix.as_str()
                    ))
                })
        }

        fn create(&self, prefix: &Prefix, event: &IcpEvent) -> Result<(), crate::keri::KelError> {
            let mut store = self.events.lock().unwrap();
            store.insert(prefix.as_str().to_string(), vec![Event::Icp(event.clone())]);
            Ok(())
        }

        fn append(&self, prefix: &Prefix, event: &Event) -> Result<(), crate::keri::KelError> {
            let mut store = self.events.lock().unwrap();
            store
                .entry(prefix.as_str().to_string())
                .or_default()
                .push(event.clone());
            Ok(())
        }
    }
}
