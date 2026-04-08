use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::Mutex;

use auths_core::storage::keychain::IdentityDID;
use auths_keri::Prefix;
use auths_verifier::core::Attestation;
use auths_verifier::types::{CanonicalDid, DeviceDID};
use chrono::{DateTime, Utc};

use crate::keri::event::Event;
use crate::keri::state::KeyState;
use crate::storage::registry::backend::{RegistryBackend, RegistryError};
use crate::storage::registry::org_member::{MemberInvalidReason, OrgMemberEntry};
use crate::storage::registry::schemas::{RegistryMetadata, TipInfo};

struct FakeState {
    events: HashMap<String, Vec<Event>>,
    key_states: HashMap<String, KeyState>,
    attestations: HashMap<CanonicalDid, Attestation>,
    attestation_history: HashMap<CanonicalDid, Vec<Attestation>>,
    org_members: HashMap<(String, String), Attestation>,
}

/// In-memory `RegistryBackend` for use in tests.
///
/// All state is held under a single `Mutex` to satisfy the atomicity requirement
/// of `store_attestation` (latest + history must update together).
pub struct FakeRegistryBackend {
    state: Mutex<FakeState>,
}

impl FakeRegistryBackend {
    /// Create an empty `FakeRegistryBackend`.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(FakeState {
                events: HashMap::new(),
                key_states: HashMap::new(),
                attestations: HashMap::new(),
                attestation_history: HashMap::new(),
                org_members: HashMap::new(),
            }),
        }
    }
}

impl Default for FakeRegistryBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn derive_key_state(prefix: &Prefix, events: &[Event]) -> Option<KeyState> {
    let mut state: Option<KeyState> = None;
    for event in events {
        let seq = event.sequence().value();
        let said = event.said().clone();
        match event {
            Event::Icp(e) => {
                state = Some(KeyState::from_inception(
                    prefix.clone(),
                    e.k.clone(),
                    e.n.clone(),
                    e.kt.clone(),
                    e.nt.clone(),
                    said,
                    e.b.clone(),
                    e.bt.clone(),
                    e.c.clone(),
                ));
            }
            Event::Rot(e) => {
                if let Some(ref mut s) = state {
                    s.apply_rotation(
                        e.k.clone(),
                        e.n.clone(),
                        e.kt.clone(),
                        e.nt.clone(),
                        seq,
                        said,
                        &e.br,
                        &e.ba,
                        e.bt.clone(),
                        e.c.clone(),
                    );
                }
            }
            Event::Ixn(_) => {
                if let Some(ref mut s) = state {
                    s.apply_interaction(seq, said);
                }
            }
            Event::Dip(e) => {
                state = Some(KeyState::from_inception(
                    prefix.clone(),
                    e.k.clone(),
                    e.n.clone(),
                    e.kt.clone(),
                    e.nt.clone(),
                    said,
                    e.b.clone(),
                    e.bt.clone(),
                    e.c.clone(),
                ));
            }
            Event::Drt(_) => {}
        }
    }
    state
}

impl RegistryBackend for FakeRegistryBackend {
    fn append_event(&self, prefix: &Prefix, event: &Event) -> Result<(), RegistryError> {
        let seq = event.sequence().value();

        let mut state = self.state.lock().unwrap();
        let key = prefix.as_str().to_string();
        let events = state.events.entry(key.clone()).or_default();

        if events.iter().any(|e| e.sequence().value() == seq) {
            return Err(RegistryError::EventExists { prefix: key, seq });
        }

        let expected = events.len() as u64;
        if seq != expected {
            return Err(RegistryError::SequenceGap {
                prefix: key,
                expected,
                got: seq,
            });
        }

        events.push(event.clone());

        if let Some(ks) = derive_key_state(prefix, events) {
            state.key_states.insert(key, ks);
        }

        Ok(())
    }

    fn get_event(&self, prefix: &Prefix, seq: u64) -> Result<Event, RegistryError> {
        let state = self.state.lock().unwrap();
        let key = prefix.as_str();
        let events = state
            .events
            .get(key)
            .ok_or_else(|| RegistryError::identity_not_found(prefix))?;
        events
            .iter()
            .find(|e| e.sequence().value() == seq)
            .cloned()
            .ok_or_else(|| RegistryError::event_not_found(prefix, seq))
    }

    fn visit_events(
        &self,
        prefix: &Prefix,
        from_seq: u64,
        visitor: &mut dyn FnMut(&Event) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let state = self.state.lock().unwrap();
        let key = prefix.as_str();
        let events = state
            .events
            .get(key)
            .ok_or_else(|| RegistryError::identity_not_found(prefix))?;
        for event in events.iter().filter(|e| e.sequence().value() >= from_seq) {
            if visitor(event).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn get_tip(&self, prefix: &Prefix) -> Result<TipInfo, RegistryError> {
        let state = self.state.lock().unwrap();
        let key = prefix.as_str();
        let events = state
            .events
            .get(key)
            .ok_or_else(|| RegistryError::identity_not_found(prefix))?;
        let last = events
            .last()
            .ok_or_else(|| RegistryError::identity_not_found(prefix))?;
        let seq = last.sequence().value();
        Ok(TipInfo::new(seq, last.said().clone()))
    }

    fn get_key_state(&self, prefix: &Prefix) -> Result<KeyState, RegistryError> {
        let state = self.state.lock().unwrap();
        let key = prefix.as_str();
        state
            .key_states
            .get(key)
            .cloned()
            .ok_or_else(|| RegistryError::identity_not_found(prefix))
    }

    fn write_key_state(&self, prefix: &Prefix, key_state: &KeyState) -> Result<(), RegistryError> {
        let mut state = self.state.lock().unwrap();
        state
            .key_states
            .insert(prefix.as_str().to_string(), key_state.clone());
        Ok(())
    }

    fn visit_identities(
        &self,
        visitor: &mut dyn FnMut(&str) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let state = self.state.lock().unwrap();
        for prefix in state.events.keys() {
            if visitor(prefix.as_str()).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn store_attestation(&self, attestation: &Attestation) -> Result<(), RegistryError> {
        let mut state = self.state.lock().unwrap();
        let did = attestation.subject.clone();
        state.attestations.insert(did.clone(), attestation.clone());
        state
            .attestation_history
            .entry(did)
            .or_default()
            .push(attestation.clone());
        Ok(())
    }

    fn load_attestation(&self, did: &DeviceDID) -> Result<Option<Attestation>, RegistryError> {
        let state = self.state.lock().unwrap();
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: did.as_str() is a valid DID string from DeviceDID
        let canonical = CanonicalDid::new_unchecked(did.as_str());
        Ok(state.attestations.get(&canonical).cloned())
    }

    fn visit_attestation_history(
        &self,
        did: &DeviceDID,
        visitor: &mut dyn FnMut(&Attestation) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let state = self.state.lock().unwrap();
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: did.as_str() is a valid DID string from DeviceDID
        let canonical = CanonicalDid::new_unchecked(did.as_str());
        if let Some(history) = state.attestation_history.get(&canonical) {
            for att in history {
                if visitor(att).is_break() {
                    break;
                }
            }
        }
        Ok(())
    }

    fn visit_devices(
        &self,
        visitor: &mut dyn FnMut(&DeviceDID) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let state = self.state.lock().unwrap();
        for canonical_did in state.attestations.keys() {
            if let Ok(device_did) = DeviceDID::parse(canonical_did.as_str())
                && visitor(&device_did).is_break()
            {
                break;
            }
        }
        Ok(())
    }

    fn store_org_member(&self, org: &str, member: &Attestation) -> Result<(), RegistryError> {
        let mut state = self.state.lock().unwrap();
        let key = (org.to_string(), member.subject.to_string());
        state.org_members.insert(key, member.clone());
        Ok(())
    }

    fn visit_org_member_attestations(
        &self,
        org: &str,
        visitor: &mut dyn FnMut(&OrgMemberEntry) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        let state = self.state.lock().unwrap();
        for ((org_key, member_did_str), att) in &state.org_members {
            if org_key != org {
                continue;
            }
            let entry = OrgMemberEntry {
                #[allow(clippy::disallowed_methods)] // INVARIANT: org is a KERI prefix from the org_members map key, format! produces a valid did:keri string
                org: IdentityDID::new_unchecked(format!("did:keri:{}", org)),
                #[allow(clippy::disallowed_methods)] // INVARIANT: member_did_str is a DID string stored in the org_members map key
                did: CanonicalDid::new_unchecked(member_did_str.clone()),
                filename: format!("{}.json", member_did_str.replace(':', "_")),
                attestation: validate_org_member(org, member_did_str, att),
            };
            if visitor(&entry).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn init_if_needed(&self) -> Result<bool, RegistryError> {
        Ok(false)
    }

    fn metadata(&self) -> Result<RegistryMetadata, RegistryError> {
        let state = self.state.lock().unwrap();
        let identities = state.events.len() as u64;
        let devices = state.attestations.len() as u64;
        let members = state.org_members.len() as u64;
        Ok(RegistryMetadata::new(
            DateTime::<Utc>::UNIX_EPOCH,
            identities,
            devices,
            members,
        ))
    }
}

fn validate_org_member(
    org: &str,
    member_did_str: &str,
    att: &Attestation,
) -> Result<Attestation, MemberInvalidReason> {
    let expected_issuer = format!("did:keri:{}", org);
    if att.issuer.as_str() != expected_issuer {
        return Err(MemberInvalidReason::IssuerMismatch {
            #[allow(clippy::disallowed_methods)] // INVARIANT: format! with "did:keri:" prefix and org KERI prefix produces a valid did:keri string
            expected_issuer: IdentityDID::new_unchecked(expected_issuer),
            #[allow(clippy::disallowed_methods)] // INVARIANT: att.issuer is a CanonicalDid from a deserialized Attestation
            actual_issuer: IdentityDID::new_unchecked(att.issuer.as_str()),
        });
    }
    if att.subject.as_str() != member_did_str {
        return Err(MemberInvalidReason::SubjectMismatch {
            #[allow(clippy::disallowed_methods)] // INVARIANT: member_did_str is a DID string from the org_members map key
            filename_did: CanonicalDid::new_unchecked(member_did_str),
            #[allow(clippy::disallowed_methods)] // INVARIANT: att.subject is a validated DID from deserialized attestation
            attestation_subject: CanonicalDid::new_unchecked(att.subject.as_str()),
        });
    }
    Ok(att.clone())
}
