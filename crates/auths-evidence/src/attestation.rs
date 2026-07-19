//! The `activity/v1` aggregate attestation — the privacy-preserving publishing
//! model (auths-site `spend-attestation-privacy.md`).
//!
//! A listed tool never publishes its per-call spend log (that exposes the
//! counterparty graph). It publishes ONE signed aggregate — `{head, count,
//! cumulative_cents, as_of}` — and the market earns `proven-live` from growth it
//! WITNESSES across probes. The per-call log stays private and is disclosed only
//! point-to-point inside an `EvidenceBundle`.
//!
//! Structurally excluded (no field exists for them): per-call rows, per-call
//! timestamps or amounts, counterparty DIDs, settlement tx hashes, tool names,
//! `args_hash`es.

use auths_keri::{KeriPublicKey, Prefix};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::EvidenceError;
use crate::types::Subject;

/// The activity wire version.
pub const ACTIVITY_VERSION: &str = "activity/v1";

/// The as-of block: when the aggregate was stamped, and (optionally) the anchor
/// tier that countersigned it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivityAsOf {
    /// When the aggregate was computed.
    pub ts: DateTime<Utc>,
    /// The optional third-party anchor (a treasury/witness checkpoint by value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<serde_json::Value>,
}

/// The signed aggregate a listed tool publishes at its `attestationUrl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityV1 {
    /// Always `"activity/v1"`.
    pub version: String,
    /// In-band curve-tagged signature suite (matches the agent key's curve).
    pub suite: String,
    /// The seller's own DIDs — the ONLY identities in the document.
    pub subject: Subject,
    /// The spend-log chain head — commits to the whole private log without
    /// revealing any of it.
    pub head: String,
    /// Total settled calls (monotonic).
    pub count: u64,
    /// Total settled cents (monotonic).
    pub cumulative_cents: u64,
    /// When, and under which anchor.
    pub as_of: ActivityAsOf,
    /// Agent signature over `canon(doc minus signature)`, chaining to the root
    /// through the public registry KEL.
    pub signature: String,
}

/// The canonical signing bytes: RFC-8785 over the document minus `signature`.
pub fn activity_signing_bytes(doc: &ActivityV1) -> Result<Vec<u8>, EvidenceError> {
    let mut value =
        serde_json::to_value(doc).map_err(|e| EvidenceError::Canonical(e.to_string()))?;
    if let Some(map) = value.as_object_mut() {
        map.remove("signature");
    }
    json_canon::to_string(&value)
        .map(String::into_bytes)
        .map_err(|e| EvidenceError::Canonical(e.to_string()))
}

/// Verify an attestation's signature against the agent's CURRENT signing keys
/// (resolved by the caller from the public KEL). Passes if ANY current key
/// verifies — the default posture is `kt=1`.
///
/// Args:
/// * `doc`: the attestation.
/// * `current_keys`: the agent's current CESR-parsed verkeys.
///
/// Usage:
/// ```ignore
/// verify_activity(&doc, &keys)?;
/// ```
pub fn verify_activity(
    doc: &ActivityV1,
    current_keys: &[KeriPublicKey],
) -> Result<(), EvidenceError> {
    if doc.version != ACTIVITY_VERSION {
        return Err(EvidenceError::Input(format!(
            "unknown version {}",
            doc.version
        )));
    }
    let message = activity_signing_bytes(doc)?;
    let signature = BASE64
        .decode(&doc.signature)
        .map_err(|e| EvidenceError::Input(format!("signature b64: {e}")))?;
    for key in current_keys {
        if auths_crypto::typed_verify(key.curve(), key.raw_bytes(), &message, &signature).is_ok() {
            return Ok(());
        }
    }
    Err(EvidenceError::Input(
        "attestation signature verifies under no current agent key".to_string(),
    ))
}

/// Verify an attestation against a public registry copy: resolve the agent's
/// current key state from the KEL (identity resolution ONLY — no spend data is
/// ever fetched), require its delegator to be the claimed root, and verify the
/// signature. This is the market's whole verification; it never sees a per-call
/// row.
///
/// Args:
/// * `doc`: the attestation.
/// * `registry`: a fetched copy of the public registry.
///
/// Usage:
/// ```ignore
/// verify_activity_against_registry(&doc, &registry_dir)?;
/// ```
pub fn verify_activity_against_registry(
    doc: &ActivityV1,
    registry: &std::path::Path,
) -> Result<(), EvidenceError> {
    use auths_sdk::ports::RegistryBackend;
    use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};

    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(registry));
    let agent_tail = doc
        .subject
        .agent
        .strip_prefix("did:keri:")
        .unwrap_or(&doc.subject.agent);
    let prefix = Prefix::new(agent_tail.to_string())
        .map_err(|e| EvidenceError::Input(format!("agent prefix: {e}")))?;
    let state = backend
        .get_key_state(&prefix)
        .map_err(|e| EvidenceError::Registry(format!("agent key state: {e}")))?;

    let root_tail = doc
        .subject
        .root
        .strip_prefix("did:keri:")
        .unwrap_or(&doc.subject.root);
    match &state.delegator {
        Some(delegator) if delegator.as_str() == root_tail => {}
        Some(delegator) => {
            return Err(EvidenceError::Input(format!(
                "agent delegator {} is not the claimed root {root_tail}",
                delegator.as_str()
            )));
        }
        None => {
            return Err(EvidenceError::Input(
                "agent is not a delegated identity — no chain to a root".to_string(),
            ));
        }
    }

    let keys: Vec<KeriPublicKey> = state
        .current_keys
        .iter()
        .map(|k| {
            k.parse()
                .map_err(|e| EvidenceError::Input(format!("current key: {e}")))
        })
        .collect::<Result<_, _>>()?;
    verify_activity(doc, &keys)
}

/// The monotonicity rules a verifier applies between a stored checkpoint and a
/// freshly fetched attestation (the market's own witnessing state machine).
/// Returns the named violation, or `None` when the transition is acceptable.
pub fn monotonicity_violation(
    prev: Option<(&str, u64, u64, DateTime<Utc>)>,
    next: &ActivityV1,
) -> Option<&'static str> {
    let (prev_head, prev_count, prev_cents, prev_ts) = prev?;
    if next.cumulative_cents < prev_cents {
        return Some("cumulative-regressed");
    }
    if next.count < prev_count {
        return Some("count-regressed");
    }
    if next.as_of.ts < prev_ts {
        return Some("as-of-regressed");
    }
    if next.cumulative_cents > prev_cents && next.head == prev_head {
        return Some("head-unmoved-under-growth");
    }
    None
}
