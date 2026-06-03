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

    // 4. Author the root's anchoring ixn (a KeyEvent seal for the dip), signed by
    //    the root's current key — single-author, no device key needed.
    let root_state = backend
        .get_key_state(root_prefix)
        .map_err(|e| InitError::Registry(e.to_string()))?;
    if !root_state.can_emit_ixn() {
        return Err(InitError::InvalidData(
            "root identity cannot anchor a delegation (interaction events forbidden)".to_string(),
        ));
    }
    let ixn = finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: root_prefix.clone(),
        s: KeriSequence::new(root_state.sequence + 1),
        p: root_state.last_event_said.clone(),
        a: vec![Seal::KeyEvent {
            i: device_prefix.clone(),
            s: KeriSequence::new(0),
            d: dip_said,
        }],
    })
    .map_err(|e| InitError::Keri(e.to_string()))?;

    let ixn_canonical =
        serialize_for_signing(&Event::Ixn(ixn.clone())).map_err(|e| InitError::Keri(e.to_string()))?;
    let (_root_did, _role, root_encrypted) = keychain.load_key(root_alias)?;
    let root_pass = passphrase_provider
        .get_passphrase(&format!("Enter passphrase for root key '{}':", root_alias))?;
    let root_pkcs8 = Pkcs8Der::new(decrypt_keypair(&root_encrypted, &root_pass)?.to_vec());
    let ixn_sig = sign_with_pkcs8_for_init(root_curve, &root_pkcs8, &ixn_canonical)
        .map_err(|e| InitError::Crypto(e.to_string()))?;
    let ixn_attachment = serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig: ixn_sig,
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;
    backend
        .append_signed_event(root_prefix, &Event::Ixn(ixn), &ixn_attachment)
        .map_err(|e| InitError::Registry(e.to_string()))?;

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
