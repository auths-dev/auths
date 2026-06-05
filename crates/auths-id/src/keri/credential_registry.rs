//! Credential registry — backerless TEL persistence anchored to the issuer KEL.
//!
//! A credential registry is a KERI-native, backerless (`NB`) Transaction Event Log
//! (TEL). It derives all of its trust from the issuer's KEL: every TEL event
//! (`vcp` registry inception, `iss` issuance, `rev` revocation) is anchored by an
//! `ixn` in the issuer KEL carrying a [`TelAnchorSeal`]-shaped `{i, s, d}` key-event
//! seal. The issuer is single-author, so anchoring reuses the same single-signature
//! `ixn` machinery devices and org members use ([`stage_root_anchor_ixn`]).
//!
//! ## Atomicity
//!
//! A TEL event and its KEL anchor (and, for an `iss`, the ACDC blob) MUST land in
//! one commit — see the `RegistryBackend` TEL doc-block. [`anchor_tel_event`] stages
//! all of them into one [`AtomicWriteBatch`] and commits once, so a crash never
//! leaves an anchored-but-absent TEL event or a TEL event the KEL never anchored.
//!
//! ## Single-signature only
//!
//! [`stage_root_anchor_ixn`] signs with one key, so the issuer must be `kt=1`. A
//! `kt≥2` issuer is rejected with [`CredentialRegistryError::ThresholdUnsupported`];
//! multi-sig registry anchoring is a tracked follow-up (mirrors the org delegator).

use auths_core::error::AuthsErrorInfo;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_crypto::CurveType;
use auths_keri::{Iss, Rev, TelAnchorSeal, TelEvent, Vcp, encode_tel_nonce, tel_to_wire_bytes};
use rand::Rng;

use crate::error::InitError;
use crate::keri::delegation::stage_root_anchor_ixn;
use crate::keri::{KeriSequence, Prefix, Said, Seal};
use crate::storage::registry::backend::{AtomicWriteBatch, RegistryBackend, RegistryError};

/// Errors raised while inceptioning, anchoring, or reading a credential registry.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialRegistryError {
    /// The issuer's KEL is `kt≥2` — single-signature anchoring only.
    #[error(
        "issuer '{issuer}' is multi-signature (kt≥2); credential registry anchoring is single-author only"
    )]
    ThresholdUnsupported {
        /// The offending issuer's KEL prefix.
        issuer: String,
    },

    /// A TEL or ACDC type failed to build, SAID, or serialize.
    #[error("TEL event error: {0}")]
    Tel(String),

    /// Authoring or committing the anchoring `ixn` failed.
    #[error("KEL anchoring failed: {0}")]
    Anchor(#[from] InitError),

    /// A registry-backend storage operation failed.
    #[error("registry storage error: {0}")]
    Storage(#[from] RegistryError),
}

impl AuthsErrorInfo for CredentialRegistryError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::ThresholdUnsupported { .. } => "AUTHS-E4981",
            Self::Tel(_) => "AUTHS-E4982",
            Self::Anchor(_) => "AUTHS-E4983",
            Self::Storage(_) => "AUTHS-E4984",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::ThresholdUnsupported { .. } => {
                Some("Credential issuance currently requires a single-signature (kt=1) issuer")
            }
            _ => None,
        }
    }
}

/// Reject a `kt≥2` (multi-signature) issuer — the anchoring `ixn` is single-author.
///
/// `kt=1` issuers (the documented pre-launch baseline) pass; mirrors the org
/// delegator's `ensure_single_sig` guard.
fn ensure_single_sig(
    backend: &(dyn RegistryBackend + Send + Sync),
    issuer: &Prefix,
) -> Result<(), CredentialRegistryError> {
    let state = backend.get_key_state(issuer)?;
    if state.threshold.simple_value() == Some(1) {
        Ok(())
    } else {
        Err(CredentialRegistryError::ThresholdUnsupported {
            issuer: issuer.as_str().to_string(),
        })
    }
}

/// The `(registry_said, credential_said, seal_aid, sn, event_said)` coordinate of a TEL event.
///
/// - `registry_said`/`credential_said` are the storage keys (for a `vcp` the
///   credential segment is the registry SAID itself, self-addressing).
/// - `seal_aid` is the AID the KEL anchor seal's `i` carries — the TEL event's own
///   `i` field: the registry SAID for a `vcp`, the credential SAID for an `iss`/`rev`
///   (matching keripy's `SealEvent(i=tev.pre, …)`).
fn tel_coordinate(event: &TelEvent) -> (Said, Said, Said, u128, Said) {
    match event {
        TelEvent::Vcp(vcp) => (
            vcp.d.clone(),
            vcp.d.clone(),
            vcp.i.clone(),
            vcp.s.value(),
            vcp.d.clone(),
        ),
        TelEvent::Iss(iss) => (
            iss.ri.clone(),
            iss.i.clone(),
            iss.i.clone(),
            iss.s.value(),
            iss.d.clone(),
        ),
        TelEvent::Rev(rev) => (
            rev.ri.clone(),
            rev.i.clone(),
            rev.i.clone(),
            rev.s.value(),
            rev.d.clone(),
        ),
    }
}

/// Canonical insertion-order JSON bytes of a TEL event.
fn tel_event_bytes(event: &TelEvent) -> Result<Vec<u8>, CredentialRegistryError> {
    let bytes = match event {
        TelEvent::Vcp(vcp) => tel_to_wire_bytes(vcp),
        TelEvent::Iss(iss) => tel_to_wire_bytes(iss),
        TelEvent::Rev(rev) => tel_to_wire_bytes(rev),
    };
    bytes.map_err(|e| CredentialRegistryError::Tel(e.to_string()))
}

/// Anchor a single TEL event in the issuer KEL and persist it atomically.
///
/// Authors a single-author `ixn` on the issuer's KEL carrying the TEL anchor
/// [`Seal::KeyEvent`] (`{i, s, d}` — the registry/credential AID, the TEL event
/// sequence, and the TEL event SAID), and commits it **in one batch** with the TEL
/// event blob (and the optional ACDC credential blob). Reuses
/// [`stage_root_anchor_ixn`] for the ixn authoring — the ixn is staged, not
/// committed, so it lands atomically with the TEL writes.
///
/// Rejects a `kt≥2` issuer ([`CredentialRegistryError::ThresholdUnsupported`]).
///
/// Args:
/// * `backend`: Registry holding the issuer KEL and the TEL.
/// * `issuer_prefix`: The issuer's KEL prefix (the anchoring controller).
/// * `issuer_alias`: Keychain alias of the issuer's current signing key.
/// * `issuer_curve`: Curve of the issuer's current key.
/// * `tel_event`: The TEL event (`vcp`/`iss`/`rev`) to anchor and persist.
/// * `credential_blob`: Optional ACDC blob (`(credential_said, bytes)`) committed
///   atomically alongside the TEL event — supplied for an `iss`.
/// * `passphrase_provider`: Passphrase source for the issuer key.
/// * `keychain`: Key storage (the issuer's signing key).
///
/// Usage:
/// ```ignore
/// anchor_tel_event(backend, &issuer, &alias, curve, &TelEvent::Iss(iss),
///     Some((acdc.d.clone(), acdc.to_wire_bytes()?)), &provider, &keychain)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn anchor_tel_event(
    backend: &(dyn RegistryBackend + Send + Sync),
    issuer_prefix: &Prefix,
    issuer_alias: &KeyAlias,
    issuer_curve: CurveType,
    tel_event: &TelEvent,
    credential_blob: Option<(Said, Vec<u8>)>,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<(), CredentialRegistryError> {
    ensure_single_sig(backend, issuer_prefix)?;

    let (registry_said, credential_said, seal_aid, sn, event_said) = tel_coordinate(tel_event);
    let event_bytes = tel_event_bytes(tel_event)?;

    // The TEL anchor seal's `i` is the TEL event's own AID (the registry SAID for a
    // `vcp`, the credential SAID for an `iss`/`rev`) — keripy's `SealEvent(i=tev.pre)`.
    let seal = Seal::KeyEvent {
        i: Prefix::new_unchecked(seal_aid.as_str().to_string()),
        s: KeriSequence::new(sn),
        d: event_said,
    };

    let mut batch = AtomicWriteBatch::new();
    stage_root_anchor_ixn(
        backend,
        issuer_prefix,
        issuer_alias,
        issuer_curve,
        vec![seal],
        passphrase_provider,
        keychain,
        &mut batch,
    )?;
    batch.stage_tel_event(
        issuer_prefix.clone(),
        registry_said.clone(),
        credential_said.clone(),
        sn,
        event_bytes,
    );
    if let Some((cred_said, cred_bytes)) = credential_blob {
        batch.stage_credential(issuer_prefix.clone(), cred_said, cred_bytes);
    }

    backend.commit_batch(&batch)?;
    Ok(())
}

/// The registry SAID a TEL anchor seal carries, validated against its KERI shape.
///
/// Reads the issuer KEL `ixn` anchors and confirms one carries the TEL event's
/// `{i, s, d}` key-event seal. The verifier (Epic F.5) does the full cross-check;
/// this is the persistence-side equivalent used by tests.
///
/// Args:
/// * `seal`: A `TelAnchorSeal` to convert into the matching KEL seal shape.
///
/// Usage:
/// ```ignore
/// let kel_seal = anchor_seal_for(&TelAnchorSeal::for_event(reg, iss.s, iss.d));
/// ```
pub fn anchor_seal_for(seal: &TelAnchorSeal) -> Seal {
    Seal::KeyEvent {
        i: seal.i.clone(),
        s: seal.s,
        d: seal.d.clone(),
    }
}

/// Lazily incept and anchor a backerless registry (`vcp`) for an issuer if absent.
///
/// Idempotent and one-registry-per-issuer: if the issuer already has an anchored
/// registry (a `vcp` anchor in its KEL), the existing registry SAID is returned
/// untouched. Otherwise a fresh backerless `vcp` is incepted (with a random
/// 128-bit nonce so its registry SAID is unique) and anchored via [`anchor_tel_event`].
///
/// Rejects a `kt≥2` issuer ([`CredentialRegistryError::ThresholdUnsupported`]).
///
/// Args:
/// * `backend`: Registry holding the issuer KEL and the TEL.
/// * `issuer_prefix`: The issuer's KEL prefix.
/// * `issuer_alias`: Keychain alias of the issuer's current signing key.
/// * `issuer_curve`: Curve of the issuer's current key.
/// * `passphrase_provider`: Passphrase source for the issuer key.
/// * `keychain`: Key storage (the issuer's signing key).
///
/// Usage:
/// ```ignore
/// let registry = ensure_registry(backend, &issuer, &alias, curve, &provider, &keychain)?;
/// ```
pub fn ensure_registry(
    backend: &(dyn RegistryBackend + Send + Sync),
    issuer_prefix: &Prefix,
    issuer_alias: &KeyAlias,
    issuer_curve: CurveType,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<Said, CredentialRegistryError> {
    ensure_single_sig(backend, issuer_prefix)?;

    if let Some(existing) = find_registry(backend, issuer_prefix)? {
        return Ok(existing);
    }

    let mut nonce_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce =
        encode_tel_nonce(&nonce_bytes).map_err(|e| CredentialRegistryError::Tel(e.to_string()))?;

    let vcp = Vcp::new(issuer_prefix.clone(), nonce)
        .saidify()
        .map_err(|e| CredentialRegistryError::Tel(e.to_string()))?;
    let registry_said = vcp.registry().clone();

    anchor_tel_event(
        backend,
        issuer_prefix,
        issuer_alias,
        issuer_curve,
        &TelEvent::Vcp(vcp),
        None,
        passphrase_provider,
        keychain,
    )?;

    Ok(registry_said)
}

/// Find the issuer's anchored registry SAID, if any (the lazy-incept idempotency check).
///
/// Walks the issuer KEL for an `ixn` carrying a `vcp` anchor — a `Seal::KeyEvent`
/// at TEL sequence `0` whose registry SAID has a persisted `vcp` TEL event. Returns
/// the first such registry SAID, or `None` if the issuer has no registry yet.
///
/// Args:
/// * `backend`: Registry holding the issuer KEL and TEL.
/// * `issuer_prefix`: The issuer's KEL prefix.
///
/// Usage:
/// ```ignore
/// let existing = find_registry(backend, &issuer)?;
/// ```
pub fn find_registry(
    backend: &(dyn RegistryBackend + Send + Sync),
    issuer_prefix: &Prefix,
) -> Result<Option<Said>, CredentialRegistryError> {
    use std::ops::ControlFlow;

    let mut candidates: Vec<Said> = Vec::new();
    backend.visit_events(issuer_prefix, 0, &mut |event| {
        for seal in event.anchors() {
            if let Seal::KeyEvent { i, s, .. } = seal
                && s.value() == 0
            {
                candidates.push(Said::new_unchecked(i.as_str().to_string()));
            }
        }
        ControlFlow::Continue(())
    })?;

    for candidate in candidates {
        if registry_exists(backend, issuer_prefix, &candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// True if a `vcp` TEL event is persisted for `registry_said` under `issuer`.
fn registry_exists(
    backend: &(dyn RegistryBackend + Send + Sync),
    issuer_prefix: &Prefix,
    registry_said: &Said,
) -> Result<bool, CredentialRegistryError> {
    use std::ops::ControlFlow;

    let mut found = false;
    backend.visit_tel_events(issuer_prefix, registry_said, registry_said, &mut |_bytes| {
        found = true;
        ControlFlow::Break(())
    })?;
    Ok(found)
}

/// Read back a credential's TEL events in order (`vcp`-anchored chain replay input).
///
/// Returns the parsed `vcp` (always first, read from its own self-addressed slot)
/// followed by the credential's `iss`/`rev` chain in ascending sequence order. The
/// result is the exact ordered slice [`auths_keri::validate_tel`] consumes.
///
/// Args:
/// * `backend`: Registry holding the TEL.
/// * `issuer_prefix`: The issuer's KEL prefix.
/// * `registry_said`: The registry SAID (`vcp.d`).
/// * `credential_said`: The credential SAID to read the `iss`/`rev` chain for.
///
/// Usage:
/// ```ignore
/// let events = read_credential_tel(backend, &issuer, &registry, &credential)?;
/// let state = auths_keri::validate_tel(&events)?;
/// ```
pub fn read_credential_tel(
    backend: &(dyn RegistryBackend + Send + Sync),
    issuer_prefix: &Prefix,
    registry_said: &Said,
    credential_said: &Said,
) -> Result<Vec<TelEvent>, CredentialRegistryError> {
    use std::ops::ControlFlow;

    let mut events = Vec::new();
    let mut parse_err: Option<String> = None;

    let mut collect = |bytes: &[u8]| match TelEvent::from_wire_bytes(bytes) {
        Ok(event) => {
            events.push(event);
            ControlFlow::Continue(())
        }
        Err(e) => {
            parse_err = Some(e.to_string());
            ControlFlow::Break(())
        }
    };

    backend.visit_tel_events(issuer_prefix, registry_said, registry_said, &mut collect)?;
    if credential_said != registry_said {
        backend.visit_tel_events(issuer_prefix, registry_said, credential_said, &mut collect)?;
    }

    if let Some(detail) = parse_err {
        return Err(CredentialRegistryError::Tel(detail));
    }
    Ok(events)
}

/// Build a SAID'd backerless `iss` issuance event for a credential.
///
/// A thin, errors-mapped wrapper over [`Iss::new`]+`saidify` so callers in this
/// crate don't depend on `auths_keri` directly.
///
/// Args:
/// * `credential_said`: The credential SAID being issued.
/// * `registry_said`: The registry SAID the issuance belongs to.
/// * `dt`: ISO-8601 issuance datetime (informational; injected by the caller).
///
/// Usage:
/// ```ignore
/// let iss = build_iss(&acdc.d, &registry, dt.to_rfc3339())?;
/// ```
pub fn build_iss(
    credential_said: &Said,
    registry_said: &Said,
    dt: String,
) -> Result<Iss, CredentialRegistryError> {
    Iss::new(credential_said.clone(), registry_said.clone(), dt)
        .saidify()
        .map_err(|e| CredentialRegistryError::Tel(e.to_string()))
}

/// Build a SAID'd backerless `rev` revocation event for a credential.
///
/// Args:
/// * `credential_said`: The credential SAID being revoked.
/// * `registry_said`: The registry SAID the revocation belongs to.
/// * `prior_iss_said`: The prior `iss` event SAID (the chain back-link `p`).
/// * `dt`: ISO-8601 revocation datetime (informational; injected by the caller).
///
/// Usage:
/// ```ignore
/// let rev = build_rev(&acdc.d, &registry, &iss.d, dt.to_rfc3339())?;
/// ```
pub fn build_rev(
    credential_said: &Said,
    registry_said: &Said,
    prior_iss_said: &Said,
    dt: String,
) -> Result<Rev, CredentialRegistryError> {
    Rev::new(
        credential_said.clone(),
        registry_said.clone(),
        prior_iss_said.clone(),
        dt,
    )
    .saidify()
    .map_err(|e| CredentialRegistryError::Tel(e.to_string()))
}
