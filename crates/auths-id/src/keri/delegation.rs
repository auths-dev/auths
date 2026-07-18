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

use auths_core::crypto::said::{compute_next_commitment, verify_commitment};
use auths_core::crypto::signer::{decrypt_keypair, encrypt_keypair};
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use auths_crypto::{CurveType, Pkcs8Der};
use ring::signature::KeyPair;

use crate::error::InitError;
use crate::identity::helpers::load_keypair_from_der_or_seed;
use crate::keri::inception::{generate_keypair_for_init, sign_with_pkcs8_for_init};
use crate::keri::{
    CesrKey, Event, KeriSequence, Prefix, Said, Seal, Threshold, VersionString, finalize_dip_event,
    finalize_drt_event, serialize_for_signing,
};
use crate::storage::registry::RegistryBackend;
use auths_keri::{
    AgentScope, DipEvent, DipEventInit, DrtEvent, DrtEventInit, IndexedSignature, IxnEvent,
    KeriPublicKey, SourceSeal, decode_agent_scope, encode_agent_scope, finalize_ixn_event,
    serialize_attachment, serialize_source_seal_couples,
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
    // Local add = build the device dip here (we generate the key) + anchor it +
    // store the keys. The remote path (pairing) calls the two halves separately.
    let bundle = build_device_dip(root_prefix, device_curve)?;
    let device_did = bundle.device_did.clone();
    let device_prefix = bundle.device_prefix.clone();

    anchor_received_dip(
        backend.as_ref(),
        root_prefix,
        root_alias,
        root_curve,
        &bundle.dip,
        &bundle.attachment,
        passphrase_provider,
        keychain,
    )?;

    let pass = passphrase_provider.get_passphrase(&format!(
        "Create passphrase for device key '{}':",
        device_alias
    ))?;
    let enc_cur = encrypt_keypair(bundle.current_pkcs8.as_ref(), &pass)?;
    keychain.store_key(device_alias, &device_did, KeyRole::Primary, &enc_cur)?;
    let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", device_alias));
    let enc_next = encrypt_keypair(bundle.next_pkcs8.as_ref(), &pass)?;
    keychain.store_key(&next_alias, &device_did, KeyRole::NextRotation, &enc_next)?;

    Ok(DelegatedDevice {
        device_did,
        device_prefix,
        device_alias: device_alias.clone(),
    })
}

/// The joiner-side product of [`build_device_dip`]: a signed device `dip` plus the
/// device's own keys, ready to be anchored by the root — locally (same host) or
/// after transport (remote pairing). The dip names the root as delegator but is
/// not yet on any KEL and not yet anchored.
pub struct DeviceDipBundle {
    /// The finalized, device-signed delegated-inception event.
    pub dip: DipEvent,
    /// CESR attachment carrying the device's signature over the dip.
    pub attachment: Vec<u8>,
    /// The device's KEL prefix (self-addressing — equals the dip SAID).
    pub device_prefix: Prefix,
    /// The device's `did:keri:`.
    pub device_did: IdentityDID,
    /// The device's current private key (PKCS#8 DER) — the joiner stores this.
    pub current_pkcs8: Pkcs8Der,
    /// The device's pre-committed next private key (PKCS#8 DER).
    pub next_pkcs8: Pkcs8Der,
    /// Curve of the device's keys.
    pub device_curve: CurveType,
}

/// Build + sign a device's delegated-inception (`dip`) without touching any KEL.
///
/// This is the **joiner** half of delegation: the joining device generates its own
/// key, builds a `dip` naming `root_prefix` as delegator, and self-signs it. The
/// result is pure — no backend, no keychain — so it can be produced on a device
/// that has no registry and transmitted to the root for anchoring (see
/// [`anchor_received_dip`]). For same-host adds, [`incept_delegated_device`]
/// composes this with `anchor_received_dip` directly.
///
/// Args:
/// * `root_prefix`: The root identity's KEL prefix (becomes the dip's `di`).
/// * `device_curve`: Curve for the new device key.
///
/// Usage:
/// ```ignore
/// let bundle = build_device_dip(&root_prefix, CurveType::Ed25519)?;
/// // transmit bundle.dip + bundle.attachment to the root; store the keys locally
/// ```
pub fn build_device_dip(
    root_prefix: &Prefix,
    device_curve: CurveType,
) -> Result<DeviceDipBundle, InitError> {
    let device_cur =
        generate_keypair_for_init(device_curve).map_err(|e| InitError::Crypto(e.to_string()))?;
    let device_next =
        generate_keypair_for_init(device_curve).map_err(|e| InitError::Crypto(e.to_string()))?;
    let device_next_commitment = compute_next_commitment(&device_next.verkey());

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
    let dip_canonical = serialize_for_signing(&Event::Dip(dip.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let dip_sig = sign_with_pkcs8_for_init(device_curve, &device_cur.pkcs8, &dip_canonical)
        .map_err(|e| InitError::Crypto(e.to_string()))?;
    let attachment = serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig: dip_sig,
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;

    let device_did =
        IdentityDID::try_from(&device_prefix).map_err(|e| InitError::Keri(e.to_string()))?;

    Ok(DeviceDipBundle {
        dip,
        attachment,
        device_prefix,
        device_did,
        current_pkcs8: device_cur.pkcs8,
        next_pkcs8: device_next.pkcs8,
        device_curve,
    })
}

/// Anchor a received device `dip` on the root's registry: append the (already
/// device-signed) dip to the device KEL, then author the root's anchoring `ixn`.
///
/// This is the **initiator** half of delegation. The dip is taken as-is — its
/// signature is the device's, validated by the backend on append — so this never
/// needs the device's private key. Returns the now-delegated device's DID and the
/// root's anchoring `ixn` (remote pairing relays the `ixn` back to the joiner so it
/// can confirm the anchor via `validate_delegation`).
///
/// Args:
/// * `backend`: Registry holding the root KEL; the dip is appended to the device KEL here.
/// * `root_prefix`: The root identity's KEL prefix (the delegator).
/// * `root_alias`: Keychain alias of the root's current signing key.
/// * `root_curve`: Curve of the root's current key (for the anchoring signature).
/// * `dip`: The device-signed delegated-inception event (from [`build_device_dip`]).
/// * `dip_attachment`: The device's CESR signature attachment over the dip.
/// * `passphrase_provider`: Passphrase source for the root key.
/// * `keychain`: Key storage (the root's signing key).
///
/// Usage:
/// ```ignore
/// let device_did = anchor_received_dip(backend.as_ref(), &root_prefix, &root_alias,
///     CurveType::Ed25519, &bundle.dip, &bundle.attachment, &provider, &keychain)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn anchor_received_dip(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    dip: &DipEvent,
    dip_attachment: &[u8],
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(IdentityDID, IxnEvent), InitError> {
    let device_prefix = dip.i.clone();
    let dip_said = dip.d.clone();

    // Cooperative double-anchor: author the root's anchoring `ixn` FIRST so we
    // know its (sequence, SAID). Only then can the delegate's `-G` source seal
    // point back at the exact anchoring event (the dip's own SAID doesn't depend
    // on the anchor, so authoring the anchor before appending the dip is sound).
    let anchor_ixn = author_root_anchor_ixn(
        backend,
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

    // Attach the delegate-side source seal (`-G`) and append the dip carrying it:
    // combined attachment = device signature group (`-A`) ++ source-seal group (`-G`).
    let source_seal = SourceSeal {
        s: anchor_ixn.s,
        d: anchor_ixn.d.clone(),
    };
    let mut anchored_dip = dip.clone();
    anchored_dip.source_seal = Some(source_seal.clone());
    let mut attachment = dip_attachment.to_vec();
    attachment.extend_from_slice(
        &serialize_source_seal_couples(&[source_seal])
            .map_err(|e| InitError::Keri(format!("source seal serialization: {e}")))?,
    );
    backend
        .append_signed_event(&device_prefix, &Event::Dip(anchored_dip), &attachment)
        .map_err(|e| InitError::Registry(e.to_string()))?;

    let device_did =
        IdentityDID::try_from(&device_prefix).map_err(|e| InitError::Keri(e.to_string()))?;
    Ok((device_did, anchor_ixn))
}

/// Build + sign an `ixn` on the root KEL anchoring the given seals, **staging** it
/// into `batch` rather than committing. Single-author — signed by the root's
/// current key. The caller commits the batch (alone or alongside other staged
/// writes that must land atomically with the anchor, e.g. a TEL event + ACDC blob).
///
/// Returns the finalized, signed `ixn` and its CESR signature attachment so callers
/// that relay the anchor (or need its `(sequence, SAID)`) can.
///
/// Args:
/// * `backend`: Registry holding the root KEL (read for the current key state).
/// * `root_prefix`: The root identity's KEL prefix (the anchoring controller).
/// * `root_alias`: Keychain alias of the root's current signing key.
/// * `root_curve`: Curve of the root's current key.
/// * `anchors`: The seals to carry in the `ixn`'s `a[]`.
/// * `passphrase_provider`: Passphrase source for the root key.
/// * `keychain`: Key storage (the root's signing key).
/// * `batch`: The atomic write batch the `ixn` is staged into.
///
/// Usage:
/// ```ignore
/// let mut batch = AtomicWriteBatch::new();
/// let ixn = stage_root_anchor_ixn(backend, &root, &alias, curve, seals, &provider, &keychain, &mut batch)?;
/// backend.commit_batch(&batch)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn stage_root_anchor_ixn(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    anchors: Vec<Seal>,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
    batch: &mut crate::storage::registry::backend::AtomicWriteBatch,
) -> Result<IxnEvent, InitError> {
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

    let canonical = serialize_for_signing(&Event::Ixn(ixn.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    // The root key may live in a HARDWARE backend (Secure Enclave), whose blob is
    // an opaque handle no software decrypt can open. Route the signature through
    // the keychain's hardware-aware signer — the same dispatch the commit-signing
    // path trusts — instead of decrypting a seed that may not exist in software.
    let (sig, _pubkey, signed_curve) = auths_core::storage::keychain::sign_with_key(
        keychain,
        root_alias,
        passphrase_provider,
        &canonical,
    )
    .map_err(|e| InitError::Crypto(e.to_string()))?;
    if signed_curve != root_curve {
        return Err(InitError::Crypto(format!(
            "root key curve mismatch: expected {root_curve:?}, key signed as {signed_curve:?}"
        )));
    }
    let attachment = serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig,
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;
    batch.stage_event(root_prefix.clone(), Event::Ixn(ixn.clone()), attachment);
    Ok(ixn)
}

/// Author an `ixn` on the root KEL anchoring the given seals, signed by the root's
/// current key, and commit it immediately. Single-author — no other identity's key
/// is required. Returns the finalized, signed `ixn` (callers that relay the anchor —
/// e.g. remote pairing — need its bytes; same-host callers may ignore it).
///
/// Thin wrapper over [`stage_root_anchor_ixn`] + `commit_batch` — use the staging
/// form directly when the anchor must commit atomically with other writes.
pub fn author_root_anchor_ixn(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    anchors: Vec<Seal>,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<IxnEvent, InitError> {
    let mut batch = crate::storage::registry::backend::AtomicWriteBatch::new();
    let ixn = stage_root_anchor_ixn(
        backend,
        root_prefix,
        root_alias,
        root_curve,
        anchors,
        passphrase_provider,
        keychain,
        &mut batch,
    )?;
    backend
        .commit_batch(&batch)
        .map_err(|e| InitError::Registry(e.to_string()))?;
    Ok(ixn)
}

/// One agent to incept in a bulk delegation batch (issue #255 bulk onboarding).
pub struct BulkAgentSpec {
    /// Keychain alias to store the new agent key under.
    pub device_alias: KeyAlias,
    /// Curve for the new agent key.
    pub device_curve: CurveType,
}

/// Result of [`incept_delegated_agents_bulk`]: the devices plus the one anchoring `ixn`.
pub struct BulkDelegation {
    /// The delegated identifiers, in spec order.
    pub devices: Vec<DelegatedDevice>,
    /// The single root `ixn` anchoring every dip in the batch.
    pub anchor_ixn: IxnEvent,
}

/// Incept a batch of agents as delegated identifiers with ONE root anchoring `ixn`
/// and ONE atomic commit — the bulk-onboarding write path (issue #255 / PRD KL-9).
///
/// The per-agent path spreads three anchors over three root events (the dip
/// `Seal::KeyEvent`, the `agent:{prefix}` role marker, the attestation digest) and
/// three commits; here the same three seals per agent ride in one shared `ixn`, and
/// every dip's `-G` source seal points at that one anchoring event — the same
/// whole-set-at-one-KEL-position semantics [`revoke_delegated_devices_batch`]
/// already uses on the way out.
///
/// `extras` runs once per agent AFTER its keys are stored in the keychain: it may
/// stage additional writes into the shared batch (e.g. the delegation-attestation
/// blob) and returns extra seals to carry in the anchoring `ixn` (e.g. the
/// attestation digest). Witness receipting is the caller's concern — one receipt
/// round per batch instead of per agent; this function does not contact witnesses.
#[allow(clippy::too_many_arguments)]
pub fn incept_delegated_agents_bulk(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    specs: &[BulkAgentSpec],
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
    mut extras: impl FnMut(
        &DeviceDipBundle,
        &mut crate::storage::registry::backend::AtomicWriteBatch,
    ) -> Result<Vec<Seal>, InitError>,
) -> Result<BulkDelegation, InitError> {
    let mut batch = crate::storage::registry::backend::AtomicWriteBatch::new();
    let mut bundles = Vec::with_capacity(specs.len());
    let mut seals = Vec::with_capacity(specs.len() * 3);

    for spec in specs {
        let bundle = build_device_dip(root_prefix, spec.device_curve)?;

        // Store the agent's keys first so `extras` (attestation building) can read
        // the public key back through the keychain exactly like the per-agent path.
        let pass = passphrase_provider.get_passphrase(&format!(
            "Create passphrase for device key '{}':",
            spec.device_alias
        ))?;
        let enc_cur = encrypt_keypair(bundle.current_pkcs8.as_ref(), &pass)?;
        keychain.store_key(
            &spec.device_alias,
            &bundle.device_did,
            KeyRole::Primary,
            &enc_cur,
        )?;
        let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", spec.device_alias));
        let enc_next = encrypt_keypair(bundle.next_pkcs8.as_ref(), &pass)?;
        keychain.store_key(
            &next_alias,
            &bundle.device_did,
            KeyRole::NextRotation,
            &enc_next,
        )?;

        seals.push(Seal::KeyEvent {
            i: bundle.device_prefix.clone(),
            s: KeriSequence::new(0),
            d: bundle.dip.d.clone(),
        });
        seals.push(Seal::Digest {
            d: Said::new_unchecked(agent_role_marker(&bundle.device_prefix)),
        });
        seals.extend(extras(&bundle, &mut batch)?);

        bundles.push(bundle);
    }

    // One anchoring ixn for the whole batch, staged BEFORE the dips so the dips
    // staged after it see the anchor through the batch's state/tip overlays.
    let anchor_ixn = stage_root_anchor_ixn(
        backend,
        root_prefix,
        root_alias,
        root_curve,
        seals,
        passphrase_provider,
        keychain,
        &mut batch,
    )?;

    let source_seal = SourceSeal {
        s: anchor_ixn.s,
        d: anchor_ixn.d.clone(),
    };
    let mut devices = Vec::with_capacity(bundles.len());
    for (spec, bundle) in specs.iter().zip(bundles) {
        let mut anchored_dip = bundle.dip;
        anchored_dip.source_seal = Some(source_seal.clone());
        let mut attachment = bundle.attachment;
        attachment.extend_from_slice(
            &serialize_source_seal_couples(std::slice::from_ref(&source_seal))
                .map_err(|e| InitError::Keri(format!("source seal serialization: {e}")))?,
        );
        batch.stage_event(
            bundle.device_prefix.clone(),
            Event::Dip(anchored_dip),
            attachment,
        );
        devices.push(DelegatedDevice {
            device_did: bundle.device_did,
            device_prefix: bundle.device_prefix,
            device_alias: spec.device_alias.clone(),
        });
    }

    backend
        .commit_batch(&batch)
        .map_err(|e| InitError::Registry(e.to_string()))?;

    Ok(BulkDelegation {
        devices,
        anchor_ixn,
    })
}

/// The role a delegated identifier plays.
///
/// Agents and devices share the exact same `dip`/`drt` delegation mechanism; the
/// role is a presentation distinction so `agent list` and `device list` don't
/// intermix. It is carried by an `agent:{prefix}` `Seal::Digest` marker in the root
/// KEL (no new seal type) — devices are the unmarked default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegatedRole {
    /// A device — the default delegated identifier (carries no role marker).
    Device,
    /// An AI agent — carries an `agent:{prefix}` role marker in the root KEL.
    Agent,
}

/// One identifier the root has delegated, with its role and revocation status.
pub struct DelegatedDeviceInfo {
    /// The delegated identifier's KEL prefix.
    pub device_prefix: Prefix,
    /// Whether the root has anchored a revocation for it.
    pub revoked: bool,
    /// Whether this delegation is an agent or a device.
    pub role: DelegatedRole,
}

/// The role-marker digest value for an agent prefix (`agent:{prefix}`).
fn agent_role_marker(agent_prefix: &Prefix) -> String {
    format!("agent:{}", agent_prefix.as_str())
}

/// Anchor an agent role marker for `agent_prefix` on the root KEL (single-author).
///
/// Anchors a `Seal::Digest{d: "agent:{prefix}"}` so [`list_delegated_devices`] can
/// classify this delegated identifier as an agent — distinguishing it from devices
/// without a new seal type. Distinct from the exact-prefix revocation digest, so it
/// never reads as a revocation.
///
/// Args:
/// * `backend`: Registry backend holding the root KEL.
/// * `root_prefix` / `root_alias` / `root_curve`: the delegator authoring the marker.
/// * `agent_prefix`: The agent's KEL prefix to mark.
/// * `passphrase_provider` / `keychain`: root key custody.
///
/// Usage:
/// ```ignore
/// mark_delegated_agent(&*backend, &root_prefix, &root_alias, curve, &agent_prefix, &provider, &keychain)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn mark_delegated_agent(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    agent_prefix: &Prefix,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(), InitError> {
    author_root_anchor_ixn(
        backend,
        root_prefix,
        root_alias,
        root_curve,
        vec![Seal::Digest {
            d: Said::new_unchecked(agent_role_marker(agent_prefix)),
        }],
        passphrase_provider,
        keychain,
    )
    .map(|_| ())
}

/// Anchor a delegator-anchored scope/expiry seal for an agent on the root KEL.
///
/// Authority comes from the party that controls the delegator key — the scope rides
/// in the delegator's own `ixn`, never in the agent's KEL (a compromised agent must
/// not widen its own scope). Advisory authorization (ACDC is the Epic-F upgrade).
///
/// Args:
/// * `backend`: Registry backend holding the root KEL.
/// * `root_prefix` / `root_alias` / `root_curve`: the delegator authoring the seal.
/// * `agent_prefix`: The agent's KEL prefix the scope applies to.
/// * `scope`: The granted capabilities + optional expiry.
/// * `passphrase_provider` / `keychain`: root key custody.
///
/// Usage:
/// ```ignore
/// mark_agent_scope(&*backend, &root_prefix, &root_alias, curve, &agent_prefix, &scope, &provider, &keychain)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn mark_agent_scope(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    agent_prefix: &Prefix,
    scope: &AgentScope,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(), InitError> {
    author_root_anchor_ixn(
        backend,
        root_prefix,
        root_alias,
        root_curve,
        vec![Seal::Digest {
            d: Said::new_unchecked(encode_agent_scope(agent_prefix.as_str(), scope)),
        }],
        passphrase_provider,
        keychain,
    )
    .map(|_| ())
}

/// Read the latest delegator-anchored scope for `agent_prefix` from a KEL slice,
/// or `None` if the delegator never anchored one. Pure — used by the verifier.
///
/// Args:
/// * `events`: The delegator's KEL events.
/// * `agent_prefix`: The agent prefix to resolve scope for.
pub fn read_agent_scope(events: &[Event], agent_prefix: &Prefix) -> Option<AgentScope> {
    let mut found: Option<AgentScope> = None;
    for event in events {
        for seal in event.anchors() {
            if let Seal::Digest { d } = seal
                && let Some((prefix, scope)) = decode_agent_scope(d.as_str())
                && prefix == agent_prefix.as_str()
            {
                found = Some(scope);
            }
        }
    }
    found
}

/// Marker prefix for an org-policy `Seal::Digest` value (`policy:{source_hash_hex}`).
///
/// Distinct from the `agent:` role marker, the `agentscope:` scope seal, and the
/// bare-prefix revocation digest, so an org-policy seal is never misread as any of
/// them by [`list_delegated_devices`], [`read_agent_scope`], or the revocation scan.
const ORG_POLICY_MARKER: &str = "policy:";

/// Anchor an org-policy seal on the org KEL: a `Seal::Digest{d: "policy:{hash}"}`
/// binding the KEL to the BLAKE3 source-hash of the org's compiled policy.
///
/// Only the hash rides the KEL — the policy bytes live in a content-addressed blob
/// (the registry credential store) — so the append-only log stays lean and the
/// binding is tamper-evident (loaders recompute the blob's hash and compare).
/// Single-author: the org's current key signs the `ixn`. Latest-anchored wins.
///
/// Args:
/// * `backend`: Registry backend holding the org KEL.
/// * `org_prefix` / `org_alias` / `org_curve`: the org authoring the seal.
/// * `source_hash_hex`: Lowercase-hex BLAKE3 hash of the compiled policy's source.
/// * `passphrase_provider` / `keychain`: org key custody.
///
/// Usage:
/// ```ignore
/// mark_org_policy(&*backend, &org_prefix, &org_alias, curve, &hash_hex, &provider, &keychain)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn mark_org_policy(
    backend: &(dyn RegistryBackend + Send + Sync),
    org_prefix: &Prefix,
    org_alias: &KeyAlias,
    org_curve: CurveType,
    source_hash_hex: &str,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(), InitError> {
    author_root_anchor_ixn(
        backend,
        org_prefix,
        org_alias,
        org_curve,
        vec![Seal::Digest {
            d: Said::new_unchecked(format!("{ORG_POLICY_MARKER}{source_hash_hex}")),
        }],
        passphrase_provider,
        keychain,
    )
    .map(|_| ())
}

/// Read the latest org-policy source-hash anchored on a KEL slice, or `None` if the
/// org never anchored one. Pure — the inverse of [`mark_org_policy`]'s marker.
///
/// Args:
/// * `events`: The org's KEL events (oldest first; the latest anchored policy wins).
pub fn read_org_policy_hash(events: &[Event]) -> Option<String> {
    read_latest_marked_digest(events, ORG_POLICY_MARKER)
}

/// Marker prefix for an org OIDC-subject-policy `Seal::Digest` value
/// (`oidcpolicy:{source_digest_hex}`).
///
/// A different document from the `policy:` authorization policy: this one states
/// WHICH OIDC workload identity may sign keylessly. The marker is distinct from
/// `policy:`, the `agent:` role marker, the `agentscope:` scope seal, and the
/// bare-prefix revocation digest, so no scanner misreads it.
const ORG_OIDC_POLICY_MARKER: &str = "oidcpolicy:";

/// Anchor an OIDC-subject-policy seal on the org KEL: a
/// `Seal::Digest{d: "oidcpolicy:{digest}"}` binding the KEL to the digest of the
/// org's OIDC-subject policy source.
///
/// Only the digest rides the KEL — the policy bytes live in a content-addressed
/// blob (the registry credential store) — so the append-only log stays lean and
/// the binding is tamper-evident (loaders recompute the blob's digest and
/// compare). Single-author: the org's current key signs the `ixn`.
/// Latest-anchored wins.
///
/// Args:
/// * `backend`: Registry backend holding the org KEL.
/// * `org_prefix` / `org_alias` / `org_curve`: the org authoring the seal.
/// * `source_digest_hex`: Lowercase-hex digest of the policy's source bytes.
/// * `passphrase_provider` / `keychain`: org key custody.
///
/// Usage:
/// ```ignore
/// mark_org_oidc_policy(&*backend, &org_prefix, &org_alias, curve, &digest_hex, &provider, &keychain)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn mark_org_oidc_policy(
    backend: &(dyn RegistryBackend + Send + Sync),
    org_prefix: &Prefix,
    org_alias: &KeyAlias,
    org_curve: CurveType,
    source_digest_hex: &str,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(), InitError> {
    author_root_anchor_ixn(
        backend,
        org_prefix,
        org_alias,
        org_curve,
        vec![Seal::Digest {
            d: Said::new_unchecked(format!("{ORG_OIDC_POLICY_MARKER}{source_digest_hex}")),
        }],
        passphrase_provider,
        keychain,
    )
    .map(|_| ())
}

/// Read the latest OIDC-subject-policy digest anchored on a KEL slice, or `None`
/// if the org never anchored one. Pure — the inverse of
/// [`mark_org_oidc_policy`]'s marker.
///
/// Args:
/// * `events`: The org's KEL events (oldest first; the latest anchored policy wins).
pub fn read_org_oidc_policy_digest(events: &[Event]) -> Option<String> {
    read_latest_marked_digest(events, ORG_OIDC_POLICY_MARKER)
}

/// The latest `Seal::Digest` value carrying `marker` on a KEL slice — the one
/// scan both policy markers share (latest anchored wins).
fn read_latest_marked_digest(events: &[Event], marker: &str) -> Option<String> {
    let mut found: Option<String> = None;
    for event in events {
        for seal in event.anchors() {
            if let Seal::Digest { d } = seal
                && let Some(hash) = d.as_str().strip_prefix(marker)
            {
                found = Some(hash.to_string());
            }
        }
    }
    found
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
    let mut agents: std::collections::HashSet<String> = std::collections::HashSet::new();
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
                    // An `agent:{prefix}` digest is a role marker; a bare-prefix
                    // digest is a revocation.
                    Seal::Digest { d } => match d.as_str().strip_prefix("agent:") {
                        Some(prefix) => {
                            agents.insert(prefix.to_string());
                        }
                        None => {
                            revoked.insert(d.as_str().to_string());
                        }
                    },
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
            role: if agents.contains(&p) {
                DelegatedRole::Agent
            } else {
                DelegatedRole::Device
            },
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
    .map(|_| ())
}

/// Revoke an enumerated set of delegated devices in a **single** `ixn` — the org-wide
/// kill switch. Anchors one revocation `Seal::Digest` per still-live device in one
/// atomic event (an `ixn`'s `a[]` is a seal vector), so the whole set's authority ends
/// at the same KEL position. Idempotent: devices already revoked are skipped; if none
/// remain to revoke, no event is written (`Ok(None)`).
///
/// This is an atomic batch of N revocations, **not** a class abstraction — the caller
/// supplies the explicit membership. (Class-by-predicate revocation needs the policy
/// path; it is tracked as a follow-on.)
///
/// Args:
/// * `backend`: Registry backend holding the root KEL.
/// * `root_prefix` / `root_alias` / `root_curve`: the delegator authoring the batch.
/// * `device_prefixes`: The delegated devices to revoke.
/// * `passphrase_provider` / `keychain`: root key custody.
///
/// Returns the newly-revoked prefixes and the anchoring `ixn` (or `None` if every
/// listed device was already revoked).
///
/// Usage:
/// ```ignore
/// let (revoked, ixn) = revoke_delegated_devices_batch(&*backend, &root, &alias, curve, &prefixes, &p, &kc)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn revoke_delegated_devices_batch(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    device_prefixes: &[Prefix],
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(Vec<Prefix>, Option<IxnEvent>), InitError> {
    let mut seals = Vec::new();
    let mut newly_revoked = Vec::new();
    for device_prefix in device_prefixes {
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
            continue; // already revoked — idempotent skip.
        }
        seals.push(Seal::Digest {
            d: Said::new_unchecked(device_prefix.as_str().to_string()),
        });
        newly_revoked.push(device_prefix.clone());
    }

    if seals.is_empty() {
        return Ok((newly_revoked, None));
    }
    let ixn = author_root_anchor_ixn(
        backend,
        root_prefix,
        root_alias,
        root_curve,
        seals,
        passphrase_provider,
        keychain,
    )?;
    Ok((newly_revoked, Some(ixn)))
}

/// Reveal and validate a delegated device's pre-committed next key (its new current
/// key) for a `drt`: loads `{device_alias}--next-{establishment_seq}`, decrypts it,
/// and checks it against the prior next-key commitment. Returns the next-key alias (so
/// the caller can retire it), the revealed PKCS#8, and its verkey.
fn reveal_pre_committed_next_key(
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
    device_alias: &KeyAlias,
    device_state: &auths_keri::KeyState,
) -> Result<(KeyAlias, Pkcs8Der, KeriPublicKey), InitError> {
    let next_alias = KeyAlias::new_unchecked(format!(
        "{}--next-{}",
        device_alias, device_state.last_establishment_sequence
    ));
    let (_did, _role, encrypted) = keychain.load_key(&next_alias)?;
    let pass = passphrase_provider.get_passphrase(&format!(
        "Enter passphrase for device next key '{}':",
        next_alias
    ))?;
    let revealed_pkcs8 = Pkcs8Der::new(decrypt_keypair(&encrypted, &pass)?.to_vec());
    let revealed_keypair = load_keypair_from_der_or_seed(revealed_pkcs8.as_ref())?;
    #[allow(clippy::expect_used)] // INVARIANT: ring Ed25519 public key is always 32 bytes
    let revealed_verkey = KeriPublicKey::ed25519(revealed_keypair.public_key().as_ref())
        .expect("ring Ed25519 public key is 32 bytes");
    if device_state.next_commitment.is_empty()
        || !verify_commitment(&revealed_verkey, &device_state.next_commitment[0])
    {
        return Err(InitError::InvalidData(
            "device next key does not match its prior commitment".to_string(),
        ));
    }
    Ok((next_alias, revealed_pkcs8, revealed_verkey))
}

/// Rotate a delegated device's own key (`drt`), anchored by the root.
///
/// The device reveals its pre-committed next key (its new current key), signs a
/// `drt` on its own KEL advancing to it, commits a fresh next key, and the root
/// anchors the `drt`. Single signer = the device; the root only anchors. (Local
/// case: the device's keys live in this keychain under `device_alias`; the remote
/// case runs the device half on the device.)
///
/// Args:
/// * `backend`: Registry backend holding the device + root KELs.
/// * `root_prefix` / `root_alias` / `root_curve`: the delegator (anchors the drt).
/// * `device_prefix`: the delegated device's KEL prefix.
/// * `device_alias`: keychain alias of the device's current key (its next key is
///   under `{device_alias}--next-{seq}`).
/// * `device_curve`: the device key's curve.
/// * `passphrase_provider` / `keychain`: key custody.
///
/// Usage:
/// ```ignore
/// rotate_delegated_device(&*backend, &root_prefix, &root_alias, root_curve,
///     &device_prefix, &device_alias, CurveType::Ed25519, &provider, &keychain)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn rotate_delegated_device(
    backend: &(dyn RegistryBackend + Send + Sync),
    root_prefix: &Prefix,
    root_alias: &KeyAlias,
    root_curve: CurveType,
    device_prefix: &Prefix,
    device_alias: &KeyAlias,
    device_curve: CurveType,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(), InitError> {
    let device_state = backend
        .get_key_state(device_prefix)
        .map_err(|e| InitError::Registry(e.to_string()))?;

    // Reveal the device's pre-committed next key (its new current key).
    let (next_alias, revealed_pkcs8, revealed_verkey) =
        reveal_pre_committed_next_key(keychain, passphrase_provider, device_alias, &device_state)?;

    // Commit a fresh next key for the device's subsequent rotation.
    let fresh_next =
        generate_keypair_for_init(device_curve).map_err(|e| InitError::Crypto(e.to_string()))?;
    let new_next_commitment = compute_next_commitment(&fresh_next.verkey());

    let new_sequence = device_state.sequence + 1;
    let revealed_cesr = revealed_verkey
        .to_qb64()
        .map_err(|e| InitError::InvalidData(e.to_string()))?;
    let drt = finalize_drt_event(DrtEvent::new(DrtEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: device_prefix.clone(),
        s: KeriSequence::new(new_sequence),
        p: device_state.last_event_said.clone(),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(revealed_cesr)],
        nt: Threshold::Simple(1),
        n: vec![new_next_commitment],
        bt: Threshold::Simple(0),
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
        di: root_prefix.clone(),
    }))
    .map_err(|e| InitError::Keri(e.to_string()))?;
    let drt_said = drt.d.clone();

    // The device signs the drt with its revealed (new current) key. The signature
    // is over the event body only; the `-G` source seal is an attachment added
    // after anchoring and never affects the SAID or the signed bytes.
    let canonical = serialize_for_signing(&Event::Drt(drt.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let sig = sign_with_pkcs8_for_init(device_curve, &revealed_pkcs8, &canonical)
        .map_err(|e| InitError::Crypto(e.to_string()))?;
    let mut attachment = serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig,
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;

    // Cooperative double-anchor (as in `anchor_received_dip`): the root anchors
    // the drt first, then the delegate's `-G` source seal points back at it.
    let anchor_ixn = author_root_anchor_ixn(
        backend,
        root_prefix,
        root_alias,
        root_curve,
        vec![Seal::KeyEvent {
            i: device_prefix.clone(),
            s: KeriSequence::new(new_sequence),
            d: drt_said,
        }],
        passphrase_provider,
        keychain,
    )?;

    let source_seal = SourceSeal {
        s: anchor_ixn.s,
        d: anchor_ixn.d.clone(),
    };
    let mut anchored_drt = drt;
    anchored_drt.source_seal = Some(source_seal.clone());
    attachment.extend_from_slice(
        &serialize_source_seal_couples(&[source_seal])
            .map_err(|e| InitError::Keri(format!("source seal serialization: {e}")))?,
    );
    backend
        .append_signed_event(device_prefix, &Event::Drt(anchored_drt), &attachment)
        .map_err(|e| InitError::Registry(e.to_string()))?;

    // Persist the device's new current (the revealed key) + fresh next.
    let device_did =
        IdentityDID::try_from(device_prefix).map_err(|e| InitError::Keri(e.to_string()))?;
    let store_pass = passphrase_provider.get_passphrase(&format!(
        "Create passphrase for rotated device key '{}':",
        device_alias
    ))?;
    let enc_cur = encrypt_keypair(revealed_pkcs8.as_ref(), &store_pass)?;
    keychain.store_key(device_alias, &device_did, KeyRole::Primary, &enc_cur)?;
    let new_next_alias =
        KeyAlias::new_unchecked(format!("{}--next-{}", device_alias, new_sequence));
    let enc_next = encrypt_keypair(fresh_next.pkcs8.as_ref(), &store_pass)?;
    keychain.store_key(
        &new_next_alias,
        &device_did,
        KeyRole::NextRotation,
        &enc_next,
    )?;
    let _ = keychain.delete_key(&next_alias);

    Ok(())
}
