//! Delegated devices under one root identity — multi-device on real hardware
//! (PRD §4, §6.2, §6.6, the multi-device claim).
//!
//! Your iPhone holds your **root identity**. To bring the Mac in you *pair* it —
//! you do not re-sign-up. The Mac mints its **own** signing key and builds a
//! **delegated inception** naming your root as the delegator; the root then
//! **anchors** that delegation with a signed event from the root key (PRD §6.2).
//! From then on a message sent from the Mac authenticates as the **same root
//! identity** — `device = Mac, identity = root` — because the contact can replay
//! the binding: the device signed the message, and the *root* signed a delegation
//! that names the device's key. The root key never leaves the iPhone; only the
//! delegation anchor (a root signature over the device binding) crosses to the
//! contact.
//!
//! ## Revocation is a chain event, not a re-key (PRD §6.5)
//!
//! When you lose the Mac you **revoke it from the iPhone**: the root signs a
//! revocation naming the device's key. Revocation and device-delegation are the
//! **same event class** — a signed root event that changes who may sign as this
//! identity. A contact who re-resolves the root's **witness-corroborated**
//! key-state then sees the device in the revoked set and **rejects** its next
//! message — *clawback from the chain*. The whole identity is **not** re-keyed and
//! every contact keeps verifying the root and the still-valid devices.
//!
//! The honest bound the PRD names (§6.5): clawback is only as fast as each contact
//! **re-resolves** the root's key-state, and only safe if they get
//! witness-corroborated state rather than a relay's stale cache — an offline
//! contact, or one served a stale delegation set, still has a window. This module
//! resolves against a [`DelegationState`] that stands in for that
//! witness-corroborated replay; the stale-served window itself is the subject of
//! its own claim (the freshness/corroboration surface), not this one.
//!
//! ## What this models vs. the full KERI delegation
//!
//! The full engine drives this over auths-id's delegated-inception / delegated-
//! rotation events (`incept_delegated_device`, `anchor_received_dip`,
//! `rotate_delegated_device`) replayed from a witnessed KEL. Here the same
//! **authorization property** is modelled directly: a delegation anchor is a root
//! signature over `(root AID ‖ device AID ‖ device key)`, a revocation is a root
//! signature over `(root AID ‖ device AID ‖ "revoked")`, and the contact's
//! resolved [`DelegationState`] carries the root key plus the live (admitted,
//! not-revoked) device set. So the seam is a real signature check the contact runs,
//! never a stub that trusts a flag.

use serde::{Deserialize, Serialize};

use crate::address::Aid;
use crate::identity::Identity;
use crate::{CoreError, CoreResult};

/// Domain-separating context a delegation anchor signs under — a root signature
/// over this binding is what authorizes a device to send as the root identity.
const DELEGATION_ANCHOR_CONTEXT: &[u8] = b"murmur/delegation/anchor/v1\n";

/// Domain-separating context a revocation signs under — a root signature over this
/// binding is what claws a device back out of the identity.
const DELEGATION_REVOKE_CONTEXT: &[u8] = b"murmur/delegation/revoke/v1\n";

/// The canonical bytes a delegation anchor is signed over: the root AID, the
/// device's AID, and the device's signing key, bound together so neither the
/// device key nor the identity it is delegated under can be swapped after signing.
fn anchor_signing_bytes(root: &Aid, device: &Aid, device_key: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DELEGATION_ANCHOR_CONTEXT);
    bytes.extend_from_slice(root.as_str().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(device.as_str().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(device_key);
    bytes
}

/// The canonical bytes a revocation is signed over: the root AID and the device's
/// AID. A revocation names *which* device the root is clawing back.
fn revoke_signing_bytes(root: &Aid, device: &Aid) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DELEGATION_REVOKE_CONTEXT);
    bytes.extend_from_slice(root.as_str().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(device.as_str().as_bytes());
    bytes
}

/// A delegated device: its **own** signing identity plus the AID of the **root**
/// it sends as. The device signs messages with its own key; a contact authenticates
/// those messages as the *root* AID by replaying the delegation binding (the root's
/// anchor over this device's key). The device's own key never *is* the identity —
/// it is a sub-identity the root authorized.
#[derive(Clone)]
pub struct DelegatedDevice {
    /// The device's own signing key (the Mac's Secure-Enclave key in the apps).
    identity: Identity,
    /// The root AID this device sends as. Authenticated, not asserted: a contact
    /// only treats a message as coming from this root once the delegation anchor
    /// and revocation set check out.
    root_aid: Aid,
}

impl DelegatedDevice {
    /// Build a delegated device from its own `identity` and the `root_aid` it is
    /// delegated under. The root's anchor over this device's key is what a contact
    /// later replays — see [`DelegationAnchor::issue`].
    pub fn new(identity: Identity, root_aid: Aid) -> Self {
        DelegatedDevice {
            identity,
            root_aid,
        }
    }

    /// This device's own AID (the sub-identity), distinct from the root it sends as.
    pub fn device_aid(&self) -> &Aid {
        self.identity.aid()
    }

    /// The root AID this device authenticates as.
    pub fn root_aid(&self) -> &Aid {
        &self.root_aid
    }

    /// The device's own signing public key — the key the root's anchor binds.
    pub fn device_key(&self) -> &[u8] {
        self.identity.public_key()
    }

    /// Sign `message` with the device's own key. A contact verifies this against the
    /// device key the root's anchor authorized.
    pub fn sign(&self, message: &[u8]) -> CoreResult<Vec<u8>> {
        self.identity.sign(message)
    }

    /// Borrow the device's underlying identity (so the envelope can be sealed and
    /// signed exactly as a non-delegated endpoint's would be).
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}

/// A delegation anchor: the root's signature over `(root AID ‖ device AID ‖ device
/// key)`. Issuing one is the root's act of bringing a device into the identity (the
/// iPhone anchoring the Mac's delegated inception, PRD §6.2). A contact verifies it
/// against the **root's** key, so a device whose key the root never anchored cannot
/// pass — there is no path to "authenticated as the root" without a root signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationAnchor {
    /// The root AID the device is delegated under.
    pub root_aid: Aid,
    /// The delegated device's AID.
    pub device_aid: Aid,
    /// The delegated device's signing key, bound into the signed bytes.
    pub device_key: Vec<u8>,
    /// The root's signature over `(root AID ‖ device AID ‖ device key)`.
    pub signature: Vec<u8>,
}

impl DelegationAnchor {
    /// The root issues an anchor for `device`: it signs the device's binding with
    /// the **root** key. Only the root key holder can produce this, which is exactly
    /// what makes the device "delegated by the root" rather than self-asserted.
    pub fn issue(root: &Identity, device: &DelegatedDevice) -> CoreResult<Self> {
        if device.root_aid() != root.aid() {
            return Err(CoreError::Malformed(
                "the device names a different root than the one issuing the anchor".into(),
            ));
        }
        let signing = anchor_signing_bytes(root.aid(), device.device_aid(), device.device_key());
        let signature = root.sign(&signing)?;
        Ok(DelegationAnchor {
            root_aid: root.aid().clone(),
            device_aid: device.device_aid().clone(),
            device_key: device.device_key().to_vec(),
            signature,
        })
    }

    /// Verify this anchor against the root's resolved key. The signature must check
    /// out under the **root** AID's key (resolved by the contact from the root's
    /// key-state), binding the device key to the root identity. A wrong-key or
    /// forged anchor is rejected here — no device is admitted without it.
    pub fn verify(&self, root_key: &[u8]) -> CoreResult<()> {
        // The resolved key must be the one the root AID is derived from — a contact
        // cannot be handed a key for a different AID and have the anchor pass.
        crate::identity::verify_sender(
            &self.root_aid,
            root_key,
            &anchor_signing_bytes(&self.root_aid, &self.device_aid, &self.device_key),
            &self.signature,
        )
    }
}

/// A revocation: the root's signature over `(root AID ‖ device AID)`. Producing one
/// is the root clawing a lost device back out of the identity (PRD §6.5). Like an
/// anchor it is verifiable against the root key, so a relay cannot fabricate or
/// suppress a revocation without forging the root's signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRevocation {
    /// The root AID doing the revoking.
    pub root_aid: Aid,
    /// The device AID being clawed back.
    pub device_aid: Aid,
    /// The root's signature over `(root AID ‖ device AID)`.
    pub signature: Vec<u8>,
}

impl DeviceRevocation {
    /// The root revokes `device_aid`: it signs the revocation binding with the root
    /// key. Only the root key holder can revoke a device, so a lost device cannot
    /// un-revoke itself.
    pub fn issue(root: &Identity, device_aid: &Aid) -> CoreResult<Self> {
        let signing = revoke_signing_bytes(root.aid(), device_aid);
        let signature = root.sign(&signing)?;
        Ok(DeviceRevocation {
            root_aid: root.aid().clone(),
            device_aid: device_aid.clone(),
            signature,
        })
    }

    /// Verify this revocation against the root's resolved key.
    pub fn verify(&self, root_key: &[u8]) -> CoreResult<()> {
        crate::identity::verify_sender(
            &self.root_aid,
            root_key,
            &revoke_signing_bytes(&self.root_aid, &self.device_aid),
            &self.signature,
        )
    }
}

/// The root's delegation key-state as a contact resolves it — the witness-
/// corroborated replay stand-in (PRD §6.5). It carries the root's current signing
/// key, the anchors that admitted each delegated device, and the revocations that
/// clawed devices back. Resolving a message from a delegated device against this
/// state yields the **root** AID iff the device is anchored *and not* revoked.
///
/// In the full engine this is the output of replaying the root's witnessed KEL
/// (delegated-inception + delegated-rotation events). The freshness of *this*
/// resolved state — that a contact got the witness-corroborated set rather than a
/// relay's stale cache — is the subject of the corroboration claim, not this one;
/// here the state is taken as already corroborated.
#[derive(Debug, Clone)]
pub struct DelegationState {
    root_aid: Aid,
    root_key: Vec<u8>,
    anchors: Vec<DelegationAnchor>,
    revocations: Vec<DeviceRevocation>,
}

impl DelegationState {
    /// Build a resolved delegation state for `root`, with no devices yet.
    pub fn for_root(root: &Identity) -> Self {
        DelegationState {
            root_aid: root.aid().clone(),
            root_key: root.public_key().to_vec(),
            anchors: Vec::new(),
            revocations: Vec::new(),
        }
    }

    /// The root AID this state is for.
    pub fn root_aid(&self) -> &Aid {
        &self.root_aid
    }

    /// Admit a device by recording the root's verified anchor for it. The anchor is
    /// verified against the root key *here*, so a forged anchor never enters the
    /// state — a contact admits a device only on the root's own signature.
    pub fn admit_device(&mut self, anchor: DelegationAnchor) -> CoreResult<()> {
        if anchor.root_aid != self.root_aid {
            return Err(CoreError::Malformed(
                "the anchor is for a different root than this delegation state".into(),
            ));
        }
        anchor.verify(&self.root_key)?;
        self.anchors.push(anchor);
        Ok(())
    }

    /// Record a verified revocation, clawing the named device out of the identity.
    /// The revocation is verified against the root key here, so a relay cannot
    /// inject a spurious revocation to deny a still-valid device.
    pub fn revoke_device(&mut self, revocation: DeviceRevocation) -> CoreResult<()> {
        if revocation.root_aid != self.root_aid {
            return Err(CoreError::Malformed(
                "the revocation is for a different root than this delegation state".into(),
            ));
        }
        revocation.verify(&self.root_key)?;
        self.revocations.push(revocation);
        Ok(())
    }

    /// True iff `device_aid` has been revoked in this state.
    fn is_revoked(&self, device_aid: &Aid) -> bool {
        self.revocations.iter().any(|r| &r.device_aid == device_aid)
    }

    /// Resolve a `(device AID, device key)` pair to the **root** AID it sends as, or
    /// reject it. This is the authentication gate for a delegated device:
    ///
    ///  * there must be a root anchor binding *this* device AID to *this* device key
    ///    (a device whose key the root never anchored, or whose key does not match
    ///    the anchored one, is rejected);
    ///  * the device must **not** be revoked (a revoked device is clawed back — its
    ///    next message is rejected, the clawback from the chain).
    ///
    /// Returns the root AID the device authenticates as iff both hold. A contact uses
    /// this to render `device = Mac, identity = root`, and to drop a revoked device's
    /// message rather than surface it.
    pub fn resolve_device_to_root(
        &self,
        device_aid: &Aid,
        device_key: &[u8],
    ) -> CoreResult<Aid> {
        let anchor = self
            .anchors
            .iter()
            .find(|a| &a.device_aid == device_aid)
            .ok_or(CoreError::Rejected(
                "the sending device is not a delegated device of this identity",
            ))?;
        if anchor.device_key != device_key {
            return Err(CoreError::Rejected(
                "the sending device's key does not match the root-anchored key",
            ));
        }
        if self.is_revoked(device_aid) {
            return Err(CoreError::Rejected(
                "the sending device has been revoked by the root — clawed back from the chain",
            ));
        }
        Ok(self.root_aid.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> Identity {
        Identity::from_seed([0x01u8; 32]).unwrap()
    }

    fn device(seed: u8, root_aid: &Aid) -> DelegatedDevice {
        DelegatedDevice::new(Identity::from_seed([seed; 32]).unwrap(), root_aid.clone())
    }

    #[test]
    fn an_anchored_device_resolves_to_the_root() {
        let root = root();
        let mac = device(0x02, root.aid());
        let anchor = DelegationAnchor::issue(&root, &mac).unwrap();
        let mut state = DelegationState::for_root(&root);
        state.admit_device(anchor).unwrap();

        let resolved = state
            .resolve_device_to_root(mac.device_aid(), mac.device_key())
            .unwrap();
        assert_eq!(&resolved, root.aid());
        // device != root: the Mac's own AID is its own, but it sends as the root.
        assert_ne!(mac.device_aid(), root.aid());
    }

    #[test]
    fn an_unanchored_device_is_rejected() {
        let root = root();
        let mac = device(0x02, root.aid());
        let state = DelegationState::for_root(&root); // never admitted
        assert!(matches!(
            state.resolve_device_to_root(mac.device_aid(), mac.device_key()),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_revoked_device_is_clawed_back() {
        let root = root();
        let mac = device(0x02, root.aid());
        let anchor = DelegationAnchor::issue(&root, &mac).unwrap();
        let mut state = DelegationState::for_root(&root);
        state.admit_device(anchor).unwrap();
        // Before revocation: resolves.
        assert!(
            state
                .resolve_device_to_root(mac.device_aid(), mac.device_key())
                .is_ok()
        );
        // The root revokes the Mac.
        let revocation = DeviceRevocation::issue(&root, mac.device_aid()).unwrap();
        state.revoke_device(revocation).unwrap();
        // After revocation: rejected — clawback from the chain.
        assert!(matches!(
            state.resolve_device_to_root(mac.device_aid(), mac.device_key()),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_forged_anchor_is_rejected_at_admission() {
        let root = root();
        let attacker = Identity::from_seed([0x09u8; 32]).unwrap();
        let mac = device(0x02, root.aid());
        // An anchor that claims the root AID but is signed by the attacker.
        let forged = DelegationAnchor {
            root_aid: root.aid().clone(),
            device_aid: mac.device_aid().clone(),
            device_key: mac.device_key().to_vec(),
            signature: attacker
                .sign(&anchor_signing_bytes(
                    root.aid(),
                    mac.device_aid(),
                    mac.device_key(),
                ))
                .unwrap(),
        };
        let mut state = DelegationState::for_root(&root);
        assert!(matches!(
            state.admit_device(forged),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_swapped_device_key_does_not_match_the_anchor() {
        let root = root();
        let mac = device(0x02, root.aid());
        let other = device(0x07, root.aid());
        let anchor = DelegationAnchor::issue(&root, &mac).unwrap();
        let mut state = DelegationState::for_root(&root);
        state.admit_device(anchor).unwrap();
        // The Mac's AID with someone else's key — the anchored key does not match.
        assert!(matches!(
            state.resolve_device_to_root(mac.device_aid(), other.device_key()),
            Err(CoreError::Rejected(_))
        ));
    }

    #[test]
    fn a_forged_revocation_is_rejected() {
        let root = root();
        let attacker = Identity::from_seed([0x09u8; 32]).unwrap();
        let mac = device(0x02, root.aid());
        let anchor = DelegationAnchor::issue(&root, &mac).unwrap();
        let mut state = DelegationState::for_root(&root);
        state.admit_device(anchor).unwrap();
        // A revocation claiming the root AID but signed by the attacker — a relay
        // trying to deny a still-valid device cannot forge the root's signature.
        let forged = DeviceRevocation {
            root_aid: root.aid().clone(),
            device_aid: mac.device_aid().clone(),
            signature: attacker
                .sign(&revoke_signing_bytes(root.aid(), mac.device_aid()))
                .unwrap(),
        };
        assert!(matches!(
            state.revoke_device(forged),
            Err(CoreError::Rejected(_))
        ));
        // And the device still resolves — the spurious revocation never took.
        assert!(
            state
                .resolve_device_to_root(mac.device_aid(), mac.device_key())
                .is_ok()
        );
    }
}
