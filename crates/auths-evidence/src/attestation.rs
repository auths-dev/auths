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
    /// Agent signature over `canon(doc minus signature minus anchor)`, chaining
    /// to the root through the public registry KEL.
    pub signature: String,
    /// A quorum-finalized anchor over this same aggregate, when the seller
    /// anchored it. Collected AFTER the document is signed (the cosignatures
    /// cover the anchor tuple, which restates the aggregate), so it rides
    /// outside the document signature and is verified on its own: the tuple
    /// must equal the document's aggregate and the finalization must re-check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<auths_anchor::FinalizedAnchor>,
}

/// The canonical signing bytes: RFC-8785 over the document minus `signature`
/// and minus `anchor` (the anchor is collected after signing and carries its
/// own signatures).
pub fn activity_signing_bytes(doc: &ActivityV1) -> Result<Vec<u8>, EvidenceError> {
    let mut value =
        serde_json::to_value(doc).map_err(|e| EvidenceError::Canonical(e.to_string()))?;
    if let Some(map) = value.as_object_mut() {
        map.remove("signature");
        map.remove("anchor");
    }
    json_canon::to_string(&value)
        .map(String::into_bytes)
        .map_err(|e| EvidenceError::Canonical(e.to_string()))
}

/// The seed identifier of this attestation's spend chain: derived from the
/// public delegation triple `(root, agent, agent prefix)` — one spend chain
/// per delegated agent. Producers and verifiers must derive it identically;
/// this function is the single place the derivation inputs are named.
///
/// Args:
/// * `doc`: the attestation naming the subject.
///
/// Usage:
/// ```ignore
/// let seed = activity_seed_id(&doc);
/// ```
pub fn activity_seed_id(doc: &ActivityV1) -> auths_anchor::SeedId {
    let agent_tail = doc
        .subject
        .agent
        .strip_prefix("did:keri:")
        .unwrap_or(&doc.subject.agent);
    auths_anchor::SeedId::derive(&doc.subject.root, &doc.subject.agent, agent_tail)
}

/// Build the unsigned anchor tuple this attestation submits to its witnesses:
/// the same aggregate under protocol names, with the party signature left for
/// the caller to fill (it holds the agent key; this crate never signs).
///
/// Args:
/// * `doc`: the signed attestation being anchored.
/// * `witness_set`: the committed declared-set reference (content-SAID + threshold).
/// * `party_curve` / `party_public_key`: the agent signing key the caller will
///   sign the party message with.
///
/// Usage:
/// ```ignore
/// let mut anchor = unsigned_activity_anchor(&doc, set_ref, curve, pubkey)?;
/// anchor.sig_party.signature = sign(&anchor.party_signing_bytes()?);
/// ```
pub fn unsigned_activity_anchor(
    doc: &ActivityV1,
    witness_set: auths_anchor::WitnessSetRef,
    party_curve: auths_crypto::CurveType,
    party_public_key: Vec<u8>,
) -> Result<auths_anchor::Anchor, EvidenceError> {
    let head = auths_anchor::Head::from_hex(&doc.head)
        .map_err(|e| EvidenceError::Input(format!("attestation head: {e}")))?;
    let ts_secs = doc.as_of.ts.timestamp();
    let timestamp = chrono::DateTime::<Utc>::from_timestamp(ts_secs, 0)
        .ok_or_else(|| EvidenceError::Input("attestation timestamp out of range".to_string()))?;
    Ok(auths_anchor::Anchor {
        seed_id: activity_seed_id(doc),
        index: doc.count,
        head,
        cumulative: u128::from(doc.cumulative_cents),
        timestamp,
        witness_set,
        sig_party: auths_anchor::PartySignature {
            curve: party_curve,
            public_key: party_public_key,
            signature: Vec::new(),
        },
    })
}

/// Verify an attestation's embedded finalized anchor against the document it
/// rides in: the finalization re-checks offline, the tuple restates exactly
/// this document's aggregate, and the party key that signed the anchor is one
/// of the agent's current keys. A document without an anchor passes — the
/// anchor is an additive assurance tier, never a gate.
fn verify_embedded_anchor(
    doc: &ActivityV1,
    current_keys: &[KeriPublicKey],
) -> Result<(), EvidenceError> {
    let Some(finalized) = &doc.anchor else {
        return Ok(());
    };
    auths_anchor::verify_finalized(finalized, None)
        .map_err(|e| EvidenceError::Input(format!("embedded anchor: {e}")))?;

    let anchor = &finalized.anchor;
    if anchor.seed_id != activity_seed_id(doc) {
        return Err(EvidenceError::Input(
            "embedded anchor is for a different spend chain".to_string(),
        ));
    }
    if anchor.head.to_hex() != doc.head
        || anchor.index != doc.count
        || anchor.cumulative != u128::from(doc.cumulative_cents)
    {
        return Err(EvidenceError::Input(
            "embedded anchor does not restate this document's aggregate".to_string(),
        ));
    }
    let party_is_current = current_keys.iter().any(|key| {
        key.curve() == anchor.sig_party.curve && key.raw_bytes() == anchor.sig_party.public_key
    });
    if !party_is_current {
        return Err(EvidenceError::Input(
            "embedded anchor's party key is not a current agent key".to_string(),
        ));
    }
    Ok(())
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
            return verify_embedded_anchor(doc, current_keys);
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
