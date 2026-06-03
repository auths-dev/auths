//! Delegated device identifiers — a device as a KERI delegated AID.
//!
//! A device is a **delegated identifier** of the root identity: its KEL is
//! incepted with a `dip` naming the root as delegator (`di`), and the root
//! **anchors** the dip via an `ixn` whose `a[]` carries a `Seal::KeyEvent` for
//! the dip. The device holds its own key; the root never holds it. Verifiers
//! confirm authorization via [`auths_keri::validate_delegation`] (the delegator
//! anchored the delegated event).
//!
//! This is the keripy-native, single-author, device-bound replacement for
//! shared-`k[]` controllers — and the same `dip`/`drt` mechanism agents use.

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::crypto::said::compute_next_commitment;
use auths_core::crypto::signer::{decrypt_keypair, encrypt_keypair};
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use auths_crypto::{CurveType, Pkcs8Der};

use crate::error::InitError;
use crate::keri::inception::{generate_keypair_for_init, sign_with_pkcs8_for_init};
use crate::keri::{
    CesrKey, Event, KeriSequence, Prefix, Said, Seal, Threshold, VersionString, finalize_dip_event,
    serialize_for_signing,
};
use crate::storage::registry::RegistryBackend;
use auths_keri::{
    DipEvent, DipEventInit, IndexedSignature, IxnEvent, finalize_ixn_event, serialize_attachment,
};

/// A device incepted as a delegated identifier of a root identity.
pub struct DelegatedDevice {
    /// The device's `did:keri:` (self-addressing — derived from the dip SAID).
    pub device_did: IdentityDID,
    /// The device's KEL prefix.
    pub device_prefix: Prefix,
    /// The keychain alias the device's current key is stored under.
    pub device_alias: KeyAlias,
}

/// Incept a device as a delegated identifier of the root identity.
///
/// Builds the device's `dip` (delegated inception) naming `root_prefix` as
/// delegator, signs it with a freshly-generated **device** key, appends it to the
/// device KEL, then authors the root's anchoring `ixn` (a `Seal::KeyEvent` for the
/// dip) signed by the root's current key. The device's private key is stored only
/// under `device_alias` — never under the root's alias.
///
/// Args:
/// * `backend`: Registry backend holding the root KEL and the new device KEL.
/// * `root_prefix`: The root identity's KEL prefix (the delegator).
/// * `root_alias`: Keychain alias of the root's current signing key.
/// * `root_curve`: Curve of the root's current key (for the anchoring signature).
/// * `device_alias`: Keychain alias to store the new device key under.
/// * `device_curve`: Curve for the new device key.
/// * `passphrase_provider`: Passphrase source for key decrypt/encrypt.
/// * `keychain`: Key storage.
///
/// Usage:
/// ```ignore
/// let dev = incept_delegated_device(backend, &root_prefix, &root_alias,
///     CurveType::Ed25519, &device_alias, CurveType::Ed25519, &provider, &keychain)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn incept_delegated_device(
    backend: Arc<dyn RegistryBackend + Send + Sync>,
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    device_alias: &KeyAlias,
    device_curve: CurveType,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<DelegatedDevice, InitError> {
    // 1. Generate the device's own current + next keypair.
    let device_cur =
        generate_keypair_for_init(device_curve).map_err(|e| InitError::Crypto(e.to_string()))?;
    let device_next =
        generate_keypair_for_init(device_curve).map_err(|e| InitError::Crypto(e.to_string()))?;
    let device_next_commitment = compute_next_commitment(&device_next.verkey());

    // 2. Build + finalize the dip (self-addressing prefix), delegated by the root.
    let dip = finalize_dip_event(DipEvent::new(DipEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(device_cur.cesr_encoded.clone())],
        nt: Threshold::Simple(1),
        n: vec![device_next_commitment],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
        di: root_prefix.clone(),
    }))
    .map_err(|e| InitError::Keri(e.to_string()))?;

    let device_prefix = dip.i.clone();
    let dip_said = dip.d.clone();

    // 3. Sign the dip with the device key; append it to the device KEL.
    let dip_canonical =
        serialize_for_signing(&Event::Dip(dip.clone())).map_err(|e| InitError::Keri(e.to_string()))?;
    let dip_sig = sign_with_pkcs8_for_init(device_curve, &device_cur.pkcs8, &dip_canonical)
        .map_err(|e| InitError::Crypto(e.to_string()))?;
    let dip_attachment = serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig: dip_sig,
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;
    backend
        .append_signed_event(&device_prefix, &Event::Dip(dip), &dip_attachment)
        .map_err(|e| InitError::Registry(e.to_string()))?;

    // 4. Author the root's anchoring ixn (a KeyEvent seal for the dip).
    author_root_anchor_ixn(
        backend.as_ref(),
        root_prefix,
        root_alias,
        root_curve,
        vec![Seal::KeyEvent {
            i: device_prefix.clone(),
            s: KeriSequence::new(0),
            d: dip_said,
        }],
        passphrase_provider,
        keychain,
    )?;

    // 5. Persist the device's keys under its own alias (current + pre-committed next).
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: device_prefix is from finalize_dip_event, a valid did:keri prefix.
    let device_did = IdentityDID::new_unchecked(format!("did:keri:{}", device_prefix));
    let pass = passphrase_provider
        .get_passphrase(&format!("Create passphrase for device key '{}':", device_alias))?;
    let enc_cur = encrypt_keypair(device_cur.pkcs8.as_ref(), &pass)?;
    keychain.store_key(device_alias, &device_did, KeyRole::Primary, &enc_cur)?;
    let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", device_alias));
    let enc_next = encrypt_keypair(device_next.pkcs8.as_ref(), &pass)?;
    keychain.store_key(&next_alias, &device_did, KeyRole::NextRotation, &enc_next)?;

    Ok(DelegatedDevice {
        device_did,
        device_prefix,
        device_alias: device_alias.clone(),
    })
}

/// Author an `ixn` on the root KEL anchoring the given seals, signed by the root's
/// current key. Single-author — no other identity's key is required.
fn author_root_anchor_ixn(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    anchors: Vec<Seal>,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(), InitError> {
    let root_state = backend
        .get_key_state(root_prefix)
        .map_err(|e| InitError::Registry(e.to_string()))?;
    if !root_state.can_emit_ixn() {
        return Err(InitError::InvalidData(
            "root identity cannot anchor (interaction events forbidden)".to_string(),
        ));
    }
    let ixn = finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: root_prefix.clone(),
        s: KeriSequence::new(root_state.sequence + 1),
        p: root_state.last_event_said.clone(),
        a: anchors,
    })
    .map_err(|e| InitError::Keri(e.to_string()))?;

    let canonical =
        serialize_for_signing(&Event::Ixn(ixn.clone())).map_err(|e| InitError::Keri(e.to_string()))?;
    let (_did, _role, encrypted) = keychain.load_key(root_alias)?;
    let pass = passphrase_provider
        .get_passphrase(&format!("Enter passphrase for root key '{}':", root_alias))?;
    let pkcs8 = Pkcs8Der::new(decrypt_keypair(&encrypted, &pass)?.to_vec());
    let sig = sign_with_pkcs8_for_init(root_curve, &pkcs8, &canonical)
        .map_err(|e| InitError::Crypto(e.to_string()))?;
    let attachment = serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig,
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;
    backend
        .append_signed_event(root_prefix, &Event::Ixn(ixn), &attachment)
        .map_err(|e| InitError::Registry(e.to_string()))?;
    Ok(())
}

/// One device the root has delegated, with its current revocation status.
pub struct DelegatedDeviceInfo {
    /// The delegated device's KEL prefix.
    pub device_prefix: Prefix,
    /// Whether the root has anchored a revocation for it.
    pub revoked: bool,
}

/// List every device the root has delegated, each tagged with whether the root
/// has revoked it (walks the root KEL collecting delegation `KeyEvent` seals and
/// revocation digest seals). Order follows first delegation.
///
/// Args:
/// * `backend`: Registry backend holding the root KEL.
/// * `root_prefix`: The root identity's KEL prefix.
///
/// Usage:
/// ```ignore
/// let devices = list_delegated_devices(&*backend, &root_prefix)?;
/// let live = devices.iter().filter(|d| !d.revoked).count();
/// ```
pub fn list_delegated_devices(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
) -> Result<Vec<DelegatedDeviceInfo>, InitError> {
    let mut delegated: Vec<String> = Vec::new();
    let mut revoked: std::collections::HashSet<String> = std::collections::HashSet::new();
    backend
        .visit_events(root_prefix, 0, &mut |event| {
            for seal in event.anchors() {
                match seal {
                    Seal::KeyEvent { i, .. } => {
                        let p = i.as_str().to_string();
                        if !delegated.contains(&p) {
                            delegated.push(p);
                        }
                    }
                    Seal::Digest { d } => {
                        revoked.insert(d.as_str().to_string());
                    }
                    _ => {}
                }
            }
            ControlFlow::Continue(())
        })
        .map_err(|e| InitError::Registry(e.to_string()))?;
    Ok(delegated
        .into_iter()
        .map(|p| DelegatedDeviceInfo {
            revoked: revoked.contains(&p),
            device_prefix: Prefix::new_unchecked(p),
        })
        .collect())
}

/// Resolve `(delegated, revoked)` for `device_prefix` against the root KEL: the
/// root anchored its `dip` (KeyEvent seal) and/or revoked it (digest seal of the
/// device prefix).
fn delegation_status(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    device_prefix: &Prefix,
) -> Result<(bool, bool), InitError> {
    let mut delegated = false;
    let mut revoked = false;
    backend
        .visit_events(root_prefix, 0, &mut |event| {
            for seal in event.anchors() {
                match seal {
                    Seal::KeyEvent { i, .. } if i.as_str() == device_prefix.as_str() => {
                        delegated = true;
                    }
                    Seal::Digest { d } if d.as_str() == device_prefix.as_str() => {
                        revoked = true;
                    }
                    _ => {}
                }
            }
            ControlFlow::Continue(())
        })
        .map_err(|e| InitError::Registry(e.to_string()))?;
    Ok((delegated, revoked))
}

/// Revoke a delegated device: the root anchors a revocation marker (a digest seal
/// of the device's prefix) so verifiers stop treating it as authorized. Single-
/// author — the root's current key signs the `ixn`; the device's key is not needed.
/// Idempotent if the device is already revoked.
///
/// Args:
/// * `backend`: Registry backend holding the root KEL.
/// * `root_prefix`: The root identity's KEL prefix (the delegator).
/// * `root_alias`: Keychain alias of the root's current signing key.
/// * `root_curve`: Curve of the root's current key.
/// * `device_prefix`: The delegated device's KEL prefix to revoke.
/// * `passphrase_provider`: Passphrase source.
/// * `keychain`: Key storage.
///
/// Usage:
/// ```ignore
/// revoke_delegated_device(&*backend, &root_prefix, &root_alias, curve, &device_prefix, &provider, &keychain)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn revoke_delegated_device(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    device_prefix: &Prefix,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(), InitError> {
    if device_prefix.as_str() == root_prefix.as_str() {
        return Err(InitError::InvalidData(
            "cannot revoke the root identity's own controller".to_string(),
        ));
    }
    let (delegated, revoked) = delegation_status(backend, root_prefix, device_prefix)?;
    if !delegated {
        return Err(InitError::InvalidData(format!(
            "device {device_prefix} is not a delegated controller of the identity"
        )));
    }
    if revoked {
        return Ok(());
    }
    let revocation = Seal::Digest {
        d: Said::new_unchecked(device_prefix.as_str().to_string()),
    };
    author_root_anchor_ixn(
        backend,
        root_prefix,
        root_alias,
        root_curve,
        vec![revocation],
        passphrase_provider,
        keychain,
    )
}
