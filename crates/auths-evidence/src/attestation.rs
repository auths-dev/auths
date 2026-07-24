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
use auths_verifier::freshness::{Freshness, FreshnessEvidence, FreshnessPolicy};
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
    let agent_did = auths_verifier::IdentityDID::parse(&doc.subject.agent).ok();
    let agent_tail = agent_did
        .as_ref()
        .map(|d| d.prefix())
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

/// The verified summary of an embedded quorum anchor — the report an RP branches
/// on, never the raw finalized anchor. Present on a verdict only when a witness
/// anchor verified whole (finalization re-checked, tuple restates the document's
/// aggregate, party key current).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorSummary {
    /// The assurance tier this anchor confers. Always `"witness"` today.
    pub tier: &'static str,
    /// The finalization threshold `t` of the co-signing witness set.
    pub threshold: u32,
    /// Declared members `N` of the witness set.
    pub witnesses: usize,
    /// Distinct cosignatures that met the threshold.
    pub cosigners: usize,
    /// The spend chain this anchor extends (hex seed id).
    pub seed_id: String,
    /// The self-addressing identifier of the co-signing witness set.
    pub witness_set_said: String,
    /// True when a supplied witness tip index proves a fresher anchor exists —
    /// the document is genuinely anchored, but the witness has moved past it.
    pub stale: bool,
}

impl AnchorSummary {
    /// Build the summary from a verified finalized anchor. `stale` defaults to
    /// `false`; [`verify_activity_with_keys`] sets it from a supplied witness tip.
    fn witness(finalized: &auths_anchor::FinalizedAnchor) -> Self {
        Self {
            tier: "witness",
            threshold: finalized.witness_set.threshold,
            witnesses: finalized.witness_set.members.len(),
            cosigners: finalized.cosignatures.len(),
            seed_id: finalized.anchor.seed_id.to_hex(),
            witness_set_said: finalized.witness_set.said.clone(),
            stale: false,
        }
    }
}

/// The first-class verdict the `activity/v1` verifiers return: the freshness
/// bound, the verified anchor summary (or `None` when unanchored), and whether
/// the head is bound by a witness anchor. The report is the only API — a relying
/// party reads these fields and never re-derives them from evidence.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityVerdict {
    /// How fresh this positive verdict is, relative to the policy window.
    pub freshness: Freshness,
    /// The verified witness-anchor summary, or `None` for an unanchored document.
    pub anchor: Option<AnchorSummary>,
    /// True iff a verified witness anchor cosigns `head == doc.head`. A
    /// self-asserted head is never bound (the verifier never sees the private
    /// spend chain the head commits to).
    pub head_bound: bool,
}

/// Options for `activity/v1` verification. The defaults keep the anchor an
/// additive assurance tier; `require_witness` promotes it to a required gate.
#[derive(Debug, Clone, Default)]
pub struct VerifyActivityOpts {
    /// Fail the whole document when there is no verified witness anchor — turns
    /// the anchor from an additive assurance into a gate (a document that simply
    /// omits its anchor no longer passes).
    pub require_witness: bool,
    /// An independently-known witness tip index for this seed, if the relying
    /// party has one. A tip greater than the document's count proves the witness
    /// has moved past this anchor (the document is stale).
    pub witness_tip_index: Option<u64>,
}

/// Map a finalization failure to a typed anchor-invalid error with a stable,
/// machine-readable code the relying party can gate on.
fn anchor_invalid(e: auths_anchor::AnchorError) -> EvidenceError {
    use auths_anchor::AnchorError as A;
    let code = match &e {
        A::CosignatureInvalid { .. } => "cosignature-invalid",
        A::CosignerOutsideSet { .. } => "cosigner-outside-set",
        A::ThresholdNotMet { .. } => "threshold-not-met",
        A::WitnessSetMismatch { .. } | A::SetSaidMismatch { .. } => "set-said-mismatch",
        A::SetInvalid(_) => "witness-set-invalid",
        A::PartyKeyNotCurrent | A::PartySignatureInvalid => "party-key-not-current",
        A::CheckpointUnverifiable { .. } | A::InclusionMissing { .. } | A::InclusionInvalid(_) => {
            "inclusion-invalid"
        }
        _ => "anchor-invalid",
    };
    EvidenceError::AnchorInvalid {
        code,
        detail: e.to_string(),
    }
}

/// Verify an attestation's embedded finalized anchor against the document it
/// rides in and report its tier: the finalization re-checks offline, the tuple
/// restates exactly this document's aggregate, and the party key that signed the
/// anchor is one of the agent's current keys.
///
/// `require_witness` turns the anchor from an additive assurance into a gate: an
/// unanchored document fails whole when a caller demands the witness tier,
/// instead of passing with `anchor == None`.
///
/// `kel_digest_seals` is the root KEL's `ixn`-anchored digest-seal SAIDs when
/// the caller holds the seller's KEL (the registry path): the anchor's witness
/// set must be declared there, or verification fails with
/// `witness-set-not-anchored`. `None` means the caller has NO KEL at all (the
/// pure keys-injected surface) — the check then stops at self-addressing,
/// which cannot detect a party declaring different sets to different verifiers.
///
/// Args:
/// * `doc`: the attestation carrying the optional anchor.
/// * `current_keys`: the agent's current CESR-parsed verkeys.
/// * `require_witness`: fail whole when no verified witness anchor is present.
/// * `kel_digest_seals`: the root KEL's `ixn` digest seals, when resolvable.
///
/// Usage:
/// ```ignore
/// let anchor = verify_embedded_anchor(&doc, &keys, false, Some(&seals))?;
/// ```
fn verify_embedded_anchor(
    doc: &ActivityV1,
    current_keys: &[KeriPublicKey],
    require_witness: bool,
    kel_digest_seals: Option<&[String]>,
) -> Result<Option<AnchorSummary>, EvidenceError> {
    let Some(finalized) = &doc.anchor else {
        return if require_witness {
            Err(EvidenceError::AnchorInvalid {
                code: "anchor-required",
                detail: "witness tier required but this document carries no anchor".to_string(),
            })
        } else {
            Ok(None)
        };
    };
    let declared_said = match kel_digest_seals {
        Some(seals) => Some(
            auths_anchor::find_witness_set_seal(seals, &finalized.anchor.witness_set.said)
                .ok_or_else(|| EvidenceError::AnchorInvalid {
                    code: "witness-set-not-anchored",
                    detail: format!(
                        "witness set {} is not declared in the seller's KEL — \
                         the seller must anchor it with `auths witness-set declare`",
                        finalized.anchor.witness_set.said
                    ),
                })?,
        ),
        None => None,
    };
    auths_anchor::verify_finalized(finalized, declared_said).map_err(anchor_invalid)?;

    let anchor = &finalized.anchor;
    if anchor.seed_id != activity_seed_id(doc) {
        return Err(EvidenceError::AnchorInvalid {
            code: "chain-mismatch",
            detail: "embedded anchor is for a different spend chain".to_string(),
        });
    }
    if anchor.head.to_hex() != doc.head
        || anchor.index != doc.count
        || anchor.cumulative != u128::from(doc.cumulative_cents)
    {
        return Err(EvidenceError::AnchorInvalid {
            code: "aggregate-mismatch",
            detail: "embedded anchor does not restate this document's aggregate".to_string(),
        });
    }
    let party_is_current = current_keys.iter().any(|key| {
        key.curve() == anchor.sig_party.curve && key.raw_bytes() == anchor.sig_party.public_key
    });
    if !party_is_current {
        return Err(EvidenceError::AnchorInvalid {
            code: "party-key-not-current",
            detail: "embedded anchor's party key is not a current agent key".to_string(),
        });
    }
    Ok(Some(AnchorSummary::witness(finalized)))
}

/// Verify an attestation's body signature against the agent's CURRENT signing
/// keys (resolved by the caller from the public KEL) and, when present, its
/// embedded quorum anchor. Passes if ANY current key verifies the body signature
/// — the default posture is `kt=1`. Returns the verified anchor summary, or
/// `None` for an unanchored document (or an error when `require_witness` demands
/// a witness tier the document lacks).
///
/// This is the pure keys-injected surface: the caller holds no KEL here, so the
/// embedded witness set is proven self-addressing only — it is NOT checked
/// against a KEL declaration (there is no KEL to check). Callers that hold the
/// registry get that enforcement through [`verify_activity_against_registry`].
///
/// Args:
/// * `doc`: the attestation.
/// * `current_keys`: the agent's current CESR-parsed verkeys.
/// * `require_witness`: fail whole when no verified witness anchor is present.
///
/// Usage:
/// ```ignore
/// let anchor = verify_activity(&doc, &keys, false)?;
/// ```
pub fn verify_activity(
    doc: &ActivityV1,
    current_keys: &[KeriPublicKey],
    require_witness: bool,
) -> Result<Option<AnchorSummary>, EvidenceError> {
    verify_activity_declared(doc, current_keys, require_witness, None)
}

/// [`verify_activity`] with the root KEL's `ixn` digest seals threaded through
/// to the embedded-anchor check, for callers that resolved the seller's KEL.
fn verify_activity_declared(
    doc: &ActivityV1,
    current_keys: &[KeriPublicKey],
    require_witness: bool,
    kel_digest_seals: Option<&[String]>,
) -> Result<Option<AnchorSummary>, EvidenceError> {
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
            return verify_embedded_anchor(doc, current_keys, require_witness, kel_digest_seals);
        }
    }
    Err(EvidenceError::Input(
        "attestation signature does not verify under any current agent key \
         (the body was edited after signing, or the signing key was rotated out)"
            .to_string(),
    ))
}

/// Verify an `activity/v1` attestation against already-resolved agent keys and
/// return a first-class verdict: the body signature, the embedded quorum anchor
/// (when present, as a gate under `require_witness`), and a freshness bound. The
/// clock is INJECTED — this function reads no wall clock and no network.
///
/// A future `as_of` is rejected outright (a stale timestamp can only be *more*
/// stale, never falsely fresh). Freshness is classified against the policy the
/// options imply: strict (offline-`Unknown` denied) when a witness tier is
/// required, offline-friendly otherwise. A witness anchor cosigns the `as_of`,
/// so a recent anchored document reads `Fresh`; a recent, self-asserted
/// timestamp is unconfirmable and reads `Unknown`; a supplied fresher witness
/// tip marks the anchor `stale`.
///
/// This is the pure keys-injected surface: with no KEL in hand, the embedded
/// witness set is proven self-addressing only, never against a KEL declaration
/// — use [`verify_activity_against_registry`] for that enforcement.
///
/// Args:
/// * `doc`: the attestation.
/// * `current_keys`: the agent's current CESR-parsed verkeys.
/// * `now`: the verification instant (injected at the binding boundary).
/// * `opts`: gating options (`require_witness`, `witness_tip_index`).
///
/// Usage:
/// ```ignore
/// let verdict = verify_activity_with_keys(&doc, &keys, now, &opts)?;
/// ```
pub fn verify_activity_with_keys(
    doc: &ActivityV1,
    current_keys: &[KeriPublicKey],
    now: DateTime<Utc>,
    opts: &VerifyActivityOpts,
) -> Result<ActivityVerdict, EvidenceError> {
    verify_activity_with_keys_declared(doc, current_keys, now, opts, None)
}

/// [`verify_activity_with_keys`] with the root KEL's `ixn` digest seals
/// threaded through, so an embedded anchor's witness set must be one the
/// seller declared on its KEL.
fn verify_activity_with_keys_declared(
    doc: &ActivityV1,
    current_keys: &[KeriPublicKey],
    now: DateTime<Utc>,
    opts: &VerifyActivityOpts,
    kel_digest_seals: Option<&[String]>,
) -> Result<ActivityVerdict, EvidenceError> {
    if doc.as_of.ts > now + chrono::Duration::seconds(60) {
        return Err(EvidenceError::Input(
            "attestation as_of is in the future".to_string(),
        ));
    }
    let mut anchor =
        verify_activity_declared(doc, current_keys, opts.require_witness, kel_digest_seals)?;

    let policy = if opts.require_witness {
        FreshnessPolicy::strict(std::time::Duration::from_secs(24 * 60 * 60))
    } else {
        FreshnessPolicy::default()
    };
    let evidence = match opts.witness_tip_index {
        Some(tip) => FreshnessEvidence::FresherTip {
            latest_seq: u128::from(tip),
            slice_as_of: u128::from(doc.count),
        },
        None => {
            let age = (now - doc.as_of.ts).to_std().unwrap_or_default();
            if age > policy.max_age || anchor.is_some() {
                // A witness anchor cosigns the `as_of`, and an old self-timestamp
                // can only be MORE stale — both are legible as a witnessed source
                // age (recent → Fresh, past the window → Stale).
                FreshnessEvidence::SourceAge(age)
            } else {
                // A recent, self-asserted timestamp is unconfirmable → named Unknown.
                FreshnessEvidence::Offline
            }
        }
    };
    let freshness = policy.classify(evidence);

    if let Some(summary) = anchor.as_mut()
        && let Some(tip) = opts.witness_tip_index
    {
        summary.stale = tip > doc.count;
    }

    if opts.require_witness && !policy.trusts(freshness) {
        return Err(EvidenceError::Input(format!(
            "freshness not trusted for a witness-tier claim: {freshness:?}"
        )));
    }

    let head_bound = anchor.is_some();
    Ok(ActivityVerdict {
        freshness,
        anchor,
        head_bound,
    })
}

/// Verify an attestation against a public registry copy: resolve the agent's
/// current key state from the KEL (identity resolution ONLY — no spend data is
/// ever fetched), require its delegator to be the claimed root, verify the body
/// signature and (when present, or when `opts.require_witness` demands it) the
/// embedded quorum anchor, and classify freshness against the injected clock.
/// This is the market's whole verification; it never sees a per-call row.
///
/// When the document embeds a witness anchor, the anchor's witness set must be
/// declared on the root's KEL in this registry (an `ixn` digest seal over the
/// set's content SAID — `auths witness-set declare`): a set the seller never
/// anchored is refused with `witness-set-not-anchored`.
///
/// Args:
/// * `doc`: the attestation.
/// * `registry`: a fetched copy of the public registry.
/// * `now`: the verification instant (injected at the binding boundary).
/// * `opts`: gating options (`require_witness`, `witness_tip_index`).
///
/// Usage:
/// ```ignore
/// let verdict = verify_activity_against_registry(&doc, &registry_dir, now, opts)?;
/// ```
pub fn verify_activity_against_registry(
    doc: &ActivityV1,
    registry: &std::path::Path,
    now: DateTime<Utc>,
    opts: VerifyActivityOpts,
) -> Result<ActivityVerdict, EvidenceError> {
    use auths_sdk::ports::RegistryBackend;
    use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};

    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(registry));
    let parsed_agent = auths_verifier::IdentityDID::parse(&doc.subject.agent)
        .map_err(|e| EvidenceError::Input(format!("agent DID: {e}")))?;
    let prefix = Prefix::new(parsed_agent.prefix().to_string())
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

    // Resolve the root KEL's declaration seals only when an anchor is embedded:
    // an unanchored document needs no witness-set enforcement, and a registry
    // that lacks the root KEL entirely must fail an ANCHORED claim, not every
    // unanchored one.
    let kel_seals = match doc.anchor {
        Some(_) => Some(root_ixn_digest_seals(&backend, root_tail)?),
        None => None,
    };
    verify_activity_with_keys_declared(doc, &keys, now, &opts, kel_seals.as_deref())
}

/// Replay the root's KEL from the registry and collect its `ixn`-anchored
/// digest-seal SAIDs — the surface a witness-set declaration lives on.
fn root_ixn_digest_seals(
    backend: &auths_sdk::storage::GitRegistryBackend,
    root_tail: &str,
) -> Result<Vec<String>, EvidenceError> {
    use auths_sdk::ports::RegistryBackend;
    use std::ops::ControlFlow;

    let root_prefix = Prefix::new(root_tail.to_string())
        .map_err(|e| EvidenceError::Input(format!("root prefix: {e}")))?;
    let mut events: Vec<auths_keri::Event> = Vec::new();
    backend
        .visit_events(&root_prefix, 0, &mut |event| {
            events.push(event.clone());
            ControlFlow::Continue(())
        })
        .map_err(|e| EvidenceError::Registry(format!("root KEL: {e}")))?;
    Ok(auths_anchor::ixn_digest_seals(&events))
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
    // A self-asserted head can be freshly minted each publish, so this rule is
    // cosmetic at first-seen; it is load-bearing only once BOTH checkpoints carry
    // a verified witness anchor (the anchor cosigns `head == doc.head`, which is
    // what makes the head un-forgeable — see `ActivityVerdict::head_bound`).
    if next.cumulative_cents > prev_cents && next.head == prev_head {
        return Some("head-unmoved-under-growth");
    }
    None
}
