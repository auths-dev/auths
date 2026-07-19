//! `EvidenceBundle` build + canonical signing + fully-offline verification.
//!
//! The bundle is self-contained: a recipient with only this document reaches the
//! same as-of verdict with no network, no wall clock, and no trust in the tool
//! that built it. Signing is RFC-8785 canonical JSON over the bundle minus its
//! own `signature`, under an in-band curve-tagged suite (P-256 default).

use auths_crypto::{CurveType, DecodedDidKey, TypedSeed, did_key_decode};
use auths_mcp_core::{AnnotatedAudit, AuditResume, AuditVerdict, Settlement, SpendLogRecord};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::anchor::{
    AnchorCheck, composite_head, first_seen_anchor, kel_digest, spend_binding_head, verify_anchor,
};
use crate::error::EvidenceError;
use crate::judge::{ChainView, judge_call, judge_log};
use crate::resolve_chain::ResolvedChain;
use crate::types::{
    AnchorRef, AnchorTier, BundleCall, BundleProof, BundleSettlement, EvidenceBundle,
    OnlineFreshness, RECEIPTS_VERSION, Subject, Verdicts,
};

// The curve-tagged suite tag lives in auths-crypto (the sanctioned home for
// curve-specific wire naming); re-exported so consumers keep one path.
pub use auths_crypto::SignatureSuite;

/// Parse an in-band suite string, failing closed on an unknown suite.
fn parse_suite(raw: &str) -> Result<SignatureSuite, EvidenceError> {
    SignatureSuite::parse(raw).ok_or_else(|| EvidenceError::Input(format!("unknown suite `{raw}`")))
}

// The multicodec-tagged encoder lives in auths-crypto's did_key module (the one
// sanctioned home for curve-specific wire tags); re-exported so the bindings and
// the escrow domain keep one path.
pub use auths_crypto::did_key_encode;

/// The tool server's own signing identity: a curve-tagged seed plus the
/// `did:key:` it signs as.
pub struct BundleSigner {
    seed: TypedSeed,
    /// The signer's `did:key:` — the bundle's `issued_by`.
    pub did: String,
    /// The signing suite.
    pub suite: SignatureSuite,
}

impl BundleSigner {
    /// Build a signer from a 32-byte hex seed on the given suite's curve.
    ///
    /// Args:
    /// * `seed_hex`: 64 hex chars.
    /// * `suite`: the signing suite (P-256 default).
    ///
    /// Usage:
    /// ```ignore
    /// let signer = BundleSigner::from_seed_hex(&seed_hex, SignatureSuite::P256)?;
    /// ```
    pub fn from_seed_hex(seed_hex: &str, suite: SignatureSuite) -> Result<Self, EvidenceError> {
        let bytes = decode_hex(seed_hex)?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| EvidenceError::Input("signing seed must be 32 bytes".to_string()))?;
        let seed = TypedSeed::from_curve(suite.curve(), seed);
        let public_key = auths_crypto::typed_public_key(&seed)
            .map_err(|e| EvidenceError::Signing(e.to_string()))?;
        let did = did_key_encode(suite.curve(), &public_key);
        Ok(BundleSigner { seed, did, suite })
    }

    /// Generate a fresh signer (ephemeral identities, tests).
    pub fn generate(suite: SignatureSuite) -> Result<Self, EvidenceError> {
        let (seed, public_key) = auths_crypto::typed_generate(suite.curve())
            .map_err(|e| EvidenceError::Signing(e.to_string()))?;
        let did = did_key_encode(suite.curve(), &public_key);
        Ok(BundleSigner { seed, did, suite })
    }

    fn sign(&self, message: &[u8]) -> Result<String, EvidenceError> {
        let signature = auths_crypto::typed_sign(&self.seed, message)
            .map_err(|e| EvidenceError::Signing(e.to_string()))?;
        Ok(BASE64.encode(signature))
    }

    /// Sign arbitrary canonical bytes under this identity (base64) — for sibling
    /// signed artifacts (a reversal determination, an arbiter bundle).
    pub fn sign_message(&self, message: &[u8]) -> Result<String, EvidenceError> {
        self.sign(message)
    }
}

/// Optional sections + per-call inputs for one bundle build.
#[derive(Debug, Clone, Default)]
pub struct BuildOpts {
    /// CAIP-2 network id for the settlement leg (e.g. `eip155:84532`).
    pub network: String,
    /// The resolved counterparty the settlement paid (settlement address / root DID).
    pub counterparty: String,
    /// The build-time online freshness stamp (D4) — supplied by the caller that ran
    /// the re-check; absent means "offline-only, freshness unknown".
    pub online_freshness: Option<OnlineFreshness>,
    /// Verified escrow-record summary (dispute bundles).
    pub escrow: Option<serde_json::Value>,
    /// Minimized compliance cross-link (dispute bundles, S3).
    pub compliance: Option<serde_json::Value>,
    /// Human-readable render over hashed fields.
    pub rendered: Option<String>,
    /// When the treasury anchor lags the requested call, fall back to a
    /// first-seen anchor over the full log instead of failing.
    pub allow_first_seen_fallback: bool,
}

/// Build and sign an `EvidenceBundle` for one identified call of a resolved chain.
///
/// Under a treasury anchor the embedded log is CUT to the anchored prefix (the
/// longest prefix whose settled total equals the final checkpointed cumulative) so
/// the committed head covers exactly what travels; a call past the anchored prefix
/// either falls back to first-seen (when allowed) or fails `AnchorLagging`.
///
/// Args:
/// * `chain`: the resolved chain.
/// * `call_index`: the identified call's log index.
/// * `opts`: per-call inputs + optional sections.
/// * `signer`: the tool's own signing identity.
///
/// Usage:
/// ```ignore
/// let bundle = build_bundle(&chain, index, opts, &signer)?;
/// ```
pub fn build_bundle(
    chain: &ResolvedChain,
    call_index: usize,
    opts: BuildOpts,
    signer: &BundleSigner,
) -> Result<EvidenceBundle, EvidenceError> {
    let (records, facts, anchor) = anchored_prefix(chain, call_index, &opts)?;
    let Some(record) = records.get(call_index) else {
        return Err(EvidenceError::CallNotFound(format!("#{call_index}")));
    };
    let Some(fact) = facts.get(call_index) else {
        return Err(EvidenceError::CallNotFound(format!(
            "#{call_index} has no re-derived fact (the audit stopped before it)"
        )));
    };

    let view = ChainView {
        grant: &chain.grant,
        records,
        facts,
        audit_verdict: &chain.audit.verdict,
        anchor: &anchor,
        revocation: chain.revocation.as_ref(),
    };
    let call_verdict = judge_call(&view, call_index, &opts.counterparty);
    let log_verdict = judge_log(&chain.audit.verdict);

    let rail = match &record.settlement {
        Settlement::Metered { rail, .. } => rail.clone(),
        Settlement::Unmetered => "none".to_string(),
    };
    let amount_cents = fact.signed_cents.map(|c| c.get()).unwrap_or(0);

    let mut bundle = EvidenceBundle {
        version: RECEIPTS_VERSION.to_string(),
        suite: signer.suite.as_str().to_string(),
        subject: Subject {
            root: chain.root.clone(),
            agent: chain.agent.clone(),
        },
        grant: chain.grant.clone(),
        call: BundleCall {
            tool: record.receipt.tool.clone(),
            args_hash: record.receipt.action_hash.clone(),
            ts: record.receipt.at,
            signature: record.receipt.proof_ref.clone(),
            index: call_index as u64,
        },
        settlement: BundleSettlement {
            rail,
            tx: record.receipt.charge_ref.clone().unwrap_or_default(),
            amount: amount_cents.to_string(),
            network: opts.network,
            counterparty: opts.counterparty,
        },
        verdicts: Verdicts {
            call: call_verdict,
            log: log_verdict,
            as_of: anchor,
            online_freshness: opts.online_freshness,
        },
        proof: BundleProof {
            agent_kel: chain.agent_kel.clone(),
            delegator_kel: chain.delegator_kel.clone(),
            spend_log: records.to_vec(),
            revocation: chain.revocation.clone(),
        },
        escrow: opts.escrow,
        compliance: opts.compliance,
        rendered: opts.rendered,
        issued_by: signer.did.clone(),
        signature: String::new(),
    };
    bundle.signature = signer.sign(&signing_bytes(&bundle)?)?;
    Ok(bundle)
}

/// The prefix of the chain the anchor actually covers, plus the (possibly
/// recomputed) anchor. Only a `consistent` log is ever cut — a bundle documenting
/// a broken log embeds it whole under first-seen so both sides re-derive the same
/// damning verdicts.
fn anchored_prefix<'a>(
    chain: &'a ResolvedChain,
    call_index: usize,
    opts: &BuildOpts,
) -> Result<
    (
        &'a [SpendLogRecord],
        &'a [auths_mcp_core::RecordFact],
        AnchorRef,
    ),
    EvidenceError,
> {
    if chain.anchor.tier != AnchorTier::Treasury || !chain.audit.consistent {
        let anchor = if chain.anchor.tier == AnchorTier::Treasury {
            first_seen_anchor(
                chain.anchor.head.clone(),
                chain.anchor.kel_seq,
                chain.anchor.ts,
            )
        } else {
            chain.anchor.clone()
        };
        return Ok((&chain.records, &chain.facts, anchor));
    }

    let cumulative = chain
        .audit
        .treasury
        .as_ref()
        .map(|t| t.cumulative_cents)
        .unwrap_or(chain.audit.settled_cents);
    let mut cut: Option<usize> = None;
    for fact in &chain.facts {
        let running =
            fact.settled_cents_before.get() + fact.signed_cents.map(|c| c.get()).unwrap_or(0);
        if running == cumulative {
            cut = Some(fact.index);
        }
    }
    if cumulative == 0 && chain.facts.iter().all(|f| f.signed_cents.is_none()) {
        cut = chain.facts.last().map(|f| f.index);
    }
    let covered = cut.map(|c| c + 1).unwrap_or(0);
    if call_index < covered {
        let records = &chain.records[..covered];
        let facts = &chain.facts[..covered];
        let log_head = spend_binding_head(records);
        let head = composite_head(
            &log_head,
            &kel_digest(&chain.agent_kel)?,
            &kel_digest(&chain.delegator_kel)?,
            &chain.revocation,
        )?;
        let mut anchor = chain.anchor.clone();
        anchor.head = head;
        return Ok((records, facts, anchor));
    }
    if opts.allow_first_seen_fallback {
        return Ok((
            &chain.records,
            &chain.facts,
            first_seen_anchor(
                chain.anchor.head.clone(),
                chain.anchor.kel_seq,
                chain.anchor.ts,
            ),
        ));
    }
    Err(EvidenceError::AnchorLagging(format!(
        "the treasury checkpoint covers {covered} record(s); call #{call_index} is past it"
    )))
}

/// The canonical signing bytes: RFC-8785 over the bundle minus `signature`.
pub fn signing_bytes(bundle: &EvidenceBundle) -> Result<Vec<u8>, EvidenceError> {
    let mut value =
        serde_json::to_value(bundle).map_err(|e| EvidenceError::Canonical(e.to_string()))?;
    if let Some(map) = value.as_object_mut() {
        map.remove("signature");
    }
    json_canon::to_string(&value)
        .map(String::into_bytes)
        .map_err(|e| EvidenceError::Canonical(e.to_string()))
}

/// The offline re-check's result. `reason` uses the stable codes the threat gate
/// asserts: `invalid-signature`, `invalid-proof`, `head-mismatch`,
/// `anchor-unverifiable`, `tampered`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OfflineVerdict {
    /// Whether the bundle verified.
    pub ok: bool,
    /// The failure code, when it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable failure detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The (re-checked) verdicts — always restating the anchor, never bare.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdicts: Option<Verdicts>,
    /// The subject echoed for caller binding (security S4).
    pub subject: Subject,
    /// The settlement tx echoed for caller binding (S4).
    pub tx: String,
    /// The call index echoed for caller binding (S4).
    #[serde(rename = "callIndex")]
    pub call_index: u64,
    /// The proven root (the pinned root the chain re-derivation reached).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

impl OfflineVerdict {
    fn fail(bundle: &EvidenceBundle, reason: &str, detail: String) -> Self {
        OfflineVerdict {
            ok: false,
            reason: Some(reason.to_string()),
            detail: Some(detail),
            verdicts: None,
            subject: bundle.subject.clone(),
            tx: bundle.settlement.tx.clone(),
            call_index: bundle.call.index,
            root: None,
        }
    }
}

/// Fully-offline verification of a bundle: proof replay → head recompute →
/// anchor tier → verdict recompute → issuer signature → S4 echo. No network, no
/// wall clock — everything is judged as of the embedded anchor instant, so a
/// bundle verifies identically forever.
///
/// The issuer signature is checked LAST, as provenance: the security boundary is
/// the RE-DERIVATION of the embedded signed material ("you don't have to trust
/// the tool that made this"), so a hostile producer's tamper is diagnosed by
/// what it broke (head-mismatch, tampered) rather than masked behind a generic
/// signature failure.
///
/// Args:
/// * `bundle`: the bundle to verify.
///
/// Usage:
/// ```ignore
/// let verdict = verify_offline(&bundle).await;
/// assert!(verdict.ok && verdict.tx == my_disputed_tx); // the caller's S4 binding
/// ```
pub async fn verify_offline(bundle: &EvidenceBundle) -> OfflineVerdict {
    // 1. Replay the embedded proof through the one audit walk, as of the anchor.
    let agent_kel = match deserialize_kel(&bundle.proof.agent_kel) {
        Ok(kel) => kel,
        Err(e) => return OfflineVerdict::fail(bundle, "invalid-proof", e.to_string()),
    };
    let delegator_kel = match deserialize_kel(&bundle.proof.delegator_kel) {
        Ok(kel) => kel,
        Err(e) => return OfflineVerdict::fail(bundle, "invalid-proof", e.to_string()),
    };
    let pinned_roots = vec![bundle.subject.root.clone()];
    let AnnotatedAudit { verdict, facts } = auths_mcp_core::audit_spend_log_annotated(
        &bundle.proof.spend_log,
        &agent_kel,
        &delegator_kel,
        &pinned_roots,
        bundle.verdicts.as_of.ts.timestamp(),
        None,
        None,
        &AuditResume::genesis(),
    )
    .await;
    if matches!(
        verdict,
        AuditVerdict::TamperedProof { .. } | AuditVerdict::CostMismatch { .. }
    ) {
        return OfflineVerdict::fail(bundle, "tampered", format!("{verdict}"));
    }

    // 2. The composite head must re-derive to exactly the committed head —
    //    truncation or substitution of the embedded material is caught here.
    let log_head = spend_binding_head(&bundle.proof.spend_log);
    let recomputed_head = match (
        kel_digest(&bundle.proof.agent_kel),
        kel_digest(&bundle.proof.delegator_kel),
    ) {
        (Ok(agent_digest), Ok(delegator_digest)) => match composite_head(
            &log_head,
            &agent_digest,
            &delegator_digest,
            &bundle.proof.revocation,
        ) {
            Ok(head) => head,
            Err(e) => return OfflineVerdict::fail(bundle, "head-mismatch", e.to_string()),
        },
        (Err(e), _) | (_, Err(e)) => {
            return OfflineVerdict::fail(bundle, "head-mismatch", e.to_string());
        }
    };
    if recomputed_head != bundle.verdicts.as_of.head {
        return OfflineVerdict::fail(
            bundle,
            "head-mismatch",
            "the embedded material does not re-derive to the anchored head".to_string(),
        );
    }

    // 3. The anchor tier's own proof (the pinned committer's trail, when present).
    let rederived_settled = match &verdict {
        AuditVerdict::Consistent(proof) => proof.settled_cents().get(),
        _ => facts
            .last()
            .map(|f| f.settled_cents_before.get() + f.signed_cents.map(|c| c.get()).unwrap_or(0))
            .unwrap_or(0),
    };
    if let AnchorCheck::Invalid { code, detail } =
        verify_anchor(&bundle.verdicts.as_of, rederived_settled)
    {
        return OfflineVerdict::fail(bundle, code, detail);
    }

    // 4. Independently recompute both verdicts and compare to the bundle's.
    let view = ChainView {
        grant: &bundle.grant,
        records: &bundle.proof.spend_log,
        facts: &facts,
        audit_verdict: &verdict,
        anchor: &bundle.verdicts.as_of,
        revocation: bundle.proof.revocation.as_ref(),
    };
    let recomputed_call = judge_call(
        &view,
        bundle.call.index as usize,
        &bundle.settlement.counterparty,
    );
    let recomputed_log = judge_log(&verdict);
    if recomputed_call != bundle.verdicts.call || recomputed_log != bundle.verdicts.log {
        return OfflineVerdict::fail(
            bundle,
            "tampered",
            format!(
                "stated {}/{} but re-derived {}/{}",
                bundle.verdicts.call.code(),
                bundle.verdicts.log.code(),
                recomputed_call.code(),
                recomputed_log.code()
            ),
        );
    }

    // 5. The issuer's signature — provenance, checked once the content already
    //    re-derived (a broken signature on re-deriving content is a forgery of
    //    WHO issued it, not of what it proves).
    if let Err(reason) = check_issuer_signature(bundle) {
        return OfflineVerdict::fail(bundle, "invalid-signature", reason);
    }

    // 6. S4 — echo the binding fields; the CALLER must assert they match its own
    //    payment ref before acting on the verdict.
    OfflineVerdict {
        ok: true,
        reason: None,
        detail: None,
        verdicts: Some(bundle.verdicts.clone()),
        subject: bundle.subject.clone(),
        tx: bundle.settlement.tx.clone(),
        call_index: bundle.call.index,
        root: Some(bundle.subject.root.clone()),
    }
}

fn check_issuer_signature(bundle: &EvidenceBundle) -> Result<(), String> {
    let suite = parse_suite(&bundle.suite).map_err(|e| e.to_string())?;
    let decoded = did_key_decode(&bundle.issued_by).map_err(|e| format!("issued_by: {e}"))?;
    if decoded.curve() != suite.curve() {
        return Err("issued_by curve does not match the suite".to_string());
    }
    let message = signing_bytes(bundle).map_err(|e| e.to_string())?;
    let signature = BASE64
        .decode(&bundle.signature)
        .map_err(|e| e.to_string())?;
    let pubkey = match &decoded {
        DecodedDidKey::Ed25519(pk) => pk.as_slice(),
        DecodedDidKey::P256(pk) => pk.as_slice(),
    };
    auths_crypto::typed_verify(suite.curve(), pubkey, &message, &signature)
        .map_err(|_| "bundle signature did not verify under issued_by".to_string())
}

fn deserialize_kel(
    events: &[serde_json::Value],
) -> Result<Vec<auths_id::keri::Event>, EvidenceError> {
    crate::kel_wire::kel_from_wire(events)
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, EvidenceError> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(EvidenceError::Input("odd-length hex".to_string()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| EvidenceError::Input(format!("bad hex: {e}")))
        })
        .collect()
}
