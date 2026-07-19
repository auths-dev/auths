//! The `receipts/v1` and `audit/v1` wire types — the cross-binding contract.
//!
//! Field names on the wire follow `schemas/receipts-v1.json` exactly (a mix of
//! camelCase and snake_case is deliberate: the schema is the contract, serde
//! renames make the Rust names idiomatic). Every verdict is anchored — there is
//! no way to construct an unqualified "authorized" on this wire.

use auths_mcp_core::{AuditVerdict, SpendLogRecord};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The anchor ladder — who committed the head this bundle's verdicts are "as of".
/// A verdict is never stronger than its tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnchorTier {
    /// Fleet coordinator's signed checkpoint trail (pinned P-256 key) — offline-verifiable.
    Treasury,
    /// Witness commons / transparency-log checkpoint — offline-verifiable (not yet wired).
    Witness,
    /// On-chain calldata anchor (not yet wired).
    Onchain,
    /// Nobody committed the head — the documented bare default posture
    /// ("verifiers trust the first valid event seen locally").
    FirstSeen,
}

/// The head commitment a bundle's verdicts are relative to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnchorRef {
    /// Which anchor tier committed this head.
    pub tier: AnchorTier,
    /// Commitment over the COMPOSITE state as of H: the spend-log binding head,
    /// both KEL digests, and the revocation surface (see `anchor::composite_head`).
    pub head: String,
    /// Last KEL event sequence covered (the agent KEL's length at H).
    #[serde(rename = "kelSeq")]
    pub kel_seq: u64,
    /// Pinned committer key (hex) / witness id / tx ref — absent for first-seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committer: Option<String>,
    /// Tier-specific proof by value (a treasury checkpoint trail, an inclusion
    /// proof, a tx ref) so the bundle stays self-contained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<serde_json::Value>,
    /// When the head was committed — verdicts are "as of" this instant.
    pub ts: DateTime<Utc>,
}

/// The per-call verdict — first failure wins, each check presumes the ones above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallVerdict {
    /// Everything below passed — as of the anchor head.
    Authorized,
    /// The signing key's chain does not reach the claimed root, or a revocation
    /// is recorded at or before H.
    Unauthorized,
    /// The call falls outside the grant's validity window.
    Expired,
    /// The exercised capability is outside the granted scope.
    OutOfScope,
    /// The counterparty policy signed into the grant denies the resolved counterparty.
    OutOfCounterparty,
    /// Spend strictly before this call plus this call exceeds the cap.
    OverBudget,
    /// The chain does not re-derive to the anchored head, no usable anchor tier,
    /// or the gate's recorded verdict and the offline re-derivation disagree
    /// (a flagged reconciliation — never silently overridden).
    Unverifiable,
}

impl CallVerdict {
    /// The stable kebab-case wire code.
    pub fn code(&self) -> &'static str {
        match self {
            CallVerdict::Authorized => "authorized",
            CallVerdict::Unauthorized => "unauthorized",
            CallVerdict::Expired => "expired",
            CallVerdict::OutOfScope => "out-of-scope",
            CallVerdict::OutOfCounterparty => "out-of-counterparty",
            CallVerdict::OverBudget => "over-budget",
            CallVerdict::Unverifiable => "unverifiable",
        }
    }
}

/// The whole-log verdict — surfaced from the one audit walk, never recomputed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogVerdict {
    /// The audit re-derived `consistent`.
    Consistent,
    /// A named audit check failed (the audit verdict carries which).
    Inconsistent,
    /// The log could not be audited at all.
    Unverifiable,
}

impl LogVerdict {
    /// The stable kebab-case wire code.
    pub fn code(&self) -> &'static str {
        match self {
            LogVerdict::Consistent => "consistent",
            LogVerdict::Inconsistent => "inconsistent",
            LogVerdict::Unverifiable => "unverifiable",
        }
    }
}

/// How the grant's cap is denominated across rails (design D2): a cross-rail cap
/// re-derives via the settled cross-rail counter, never a raw sum of one rail's costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetBasis {
    /// One rail, one currency — plain summation is valid.
    SingleRail,
    /// One cap across rails — re-derivation must use the cross-rail settled counter.
    CrossRail,
}

/// The counterparty policy kinds the grant can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CounterpartyPolicyKind {
    /// Spend freely — the default; the counterparty check always passes.
    AllowAll,
    /// Only pre-approved settlement addresses / counterparty root DIDs.
    AllowList,
    /// Credential/reputation-gated (adapter-supplied) — fails closed here because
    /// the predicate adapter is an extension this crate does not embed.
    Predicate,
}

/// The counterparty policy signed into the delegation — part of the remit, never
/// gateway config, so loosening it needs the principal's signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CounterpartyPolicy {
    /// Which adapter is in force.
    pub kind: CounterpartyPolicyKind,
    /// The allow-list, for `kind = allow-list`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    /// A reference naming the predicate, for `kind = predicate`.
    #[serde(
        rename = "predicateRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub predicate_ref: Option<String>,
}

/// A policy decision — allow or deny, never a bool in disguise elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The counterparty is acceptable under the signed policy.
    Allow,
    /// The counterparty is refused under the signed policy.
    Deny,
}

impl CounterpartyPolicy {
    /// The default policy: allow-all (agents spend freely unless the principal
    /// signed a tighter remit).
    pub fn allow_all() -> Self {
        CounterpartyPolicy {
            kind: CounterpartyPolicyKind::AllowAll,
            allow: None,
            predicate_ref: None,
        }
    }

    /// Decide the resolved counterparty under this policy. The single adapter
    /// implementation — the live gate and the offline judge both call exactly this.
    ///
    /// Args:
    /// * `counterparty`: the resolved settlement address / counterparty root DID.
    ///
    /// Usage:
    /// ```ignore
    /// if policy.decide("0xattacker") == PolicyDecision::Deny { /* out-of-counterparty */ }
    /// ```
    pub fn decide(&self, counterparty: &str) -> PolicyDecision {
        match self.kind {
            CounterpartyPolicyKind::AllowAll => PolicyDecision::Allow,
            CounterpartyPolicyKind::AllowList => match &self.allow {
                Some(list) if list.iter().any(|entry| entry == counterparty) => {
                    PolicyDecision::Allow
                }
                // An allow-list with no list, or a counterparty not on it, fails closed.
                _ => PolicyDecision::Deny,
            },
            // The predicate adapter is an extension; without it the check fails closed.
            CounterpartyPolicyKind::Predicate => PolicyDecision::Deny,
        }
    }
}

/// The grant facts a bundle's verdicts judge against. Scope is the
/// delegator-anchored capability set; cap/ttl are the session remit the
/// principal configured; the counterparty policy is signed into the remit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleGrant {
    /// The granted capabilities (dotted gateway form, e.g. `paid.call`).
    pub scope: Vec<String>,
    /// The budget cap, in the gateway's budget grammar (e.g. `"$5"`).
    pub cap: String,
    /// The cap's currency (e.g. `"USD"`).
    pub currency: String,
    /// Grant validity window start.
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    /// Grant validity window end.
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    /// How the cap is denominated across rails (design D2).
    #[serde(rename = "budgetBasis")]
    pub budget_basis: BudgetBasis,
    /// The signed counterparty remit.
    #[serde(rename = "counterpartyPolicy")]
    pub counterparty_policy: CounterpartyPolicy,
}

/// The identified call the bundle is about. Arguments travel HASHED only
/// (security S3) — the plaintext never enters a bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleCall {
    /// The tool the call targeted.
    pub tool: String,
    /// Hex SHA-256 of the canonical `{tool, args}` bytes the agent signed.
    pub args_hash: String,
    /// When the call was judged.
    pub ts: DateTime<Utc>,
    /// The reference to the agent's signed-call proof (the commit SHA); the full
    /// signed bytes travel in `proof.spendLog`.
    pub signature: String,
    /// The call's index in the spend log.
    pub index: u64,
}

/// The settlement leg of the identified call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleSettlement {
    /// The settling rail.
    pub rail: String,
    /// The rail-native settlement reference (tx hash / charge id).
    pub tx: String,
    /// The settled amount (cents, decimal string).
    pub amount: String,
    /// CAIP-2 network id — an open string, never a closed union.
    pub network: String,
    /// The resolved counterparty (settlement address / root DID) the policy judged.
    pub counterparty: String,
}

/// The build-time online freshness stamp (design D4). Absence means
/// "offline-only, freshness unknown" — never "fresh".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnlineFreshness {
    /// When the online re-check ran.
    #[serde(rename = "checkedAt")]
    pub checked_at: DateTime<Utc>,
    /// Whether a later head contradicting this bundle's verdicts was found.
    pub contradicted: bool,
}

/// Both verdicts plus the anchor they are relative to — no unqualified verdicts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdicts {
    /// The per-call verdict for the identified call.
    pub call: CallVerdict,
    /// The whole-log verdict as of the same head.
    pub log: LogVerdict,
    /// The anchor the verdicts are "as of".
    #[serde(rename = "asOf")]
    pub as_of: AnchorRef,
    /// The optional build-time freshness stamp (design D4).
    #[serde(
        rename = "onlineFreshness",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub online_freshness: Option<OnlineFreshness>,
}

/// A revocation fact resolved from the registry — either an in-KEL event or a
/// TEL/attestation `revoked_at` that moves no KEL tip (§2.2(c)).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevocationFact {
    /// Where the revocation is recorded: `"kel"` or `"tel"`.
    pub source: String,
    /// The KEL sequence of the revocation event, when in-KEL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// When the revocation took effect, when the surface records it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<DateTime<Utc>>,
}

/// The self-contained proof material: both KELs and every spend-log record up to
/// the anchor head, so an air-gapped recipient re-derives the same as-of verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleProof {
    /// The agent's delegated KEL, in order.
    #[serde(rename = "agentKel")]
    pub agent_kel: Vec<serde_json::Value>,
    /// The delegator/root KEL, in order.
    #[serde(rename = "delegatorKel")]
    pub delegator_kel: Vec<serde_json::Value>,
    /// The spend log up to the anchor head — completeness checking needs them all.
    #[serde(rename = "spendLog")]
    pub spend_log: Vec<SpendLogRecord>,
    /// The revocation surface as resolved at build time (never cached).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationFact>,
}

/// The subject the bundle is about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subject {
    /// The principal's root DID.
    pub root: String,
    /// The delegated agent DID.
    pub agent: String,
}

/// The portable, signed, offline-re-derivable evidence bundle (`receipts/v1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Always `"receipts/v1"`.
    pub version: String,
    /// In-band curve-tagged signature suite for `signature` (e.g. `"json-canon/p256"`).
    pub suite: String,
    /// Who the bundle is about.
    pub subject: Subject,
    /// The grant the verdicts judge against.
    pub grant: BundleGrant,
    /// The identified call.
    pub call: BundleCall,
    /// The identified call's settlement.
    pub settlement: BundleSettlement,
    /// Both verdicts, anchored.
    pub verdicts: Verdicts,
    /// The self-contained proof material.
    pub proof: BundleProof,
    /// Optional verified escrow-record summary (dispute bundles).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow: Option<serde_json::Value>,
    /// Optional minimized compliance cross-link (dispute bundles, security S3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<serde_json::Value>,
    /// Optional human-readable render, built over hashed fields only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered: Option<String>,
    /// The issuing tool's own agent DID (a `did:key:` the signature verifies under).
    pub issued_by: String,
    /// Signature over `canon(bundle minus signature)` by `issued_by`, per `suite`.
    pub signature: String,
}

/// The `receipts/v1` version string.
pub const RECEIPTS_VERSION: &str = "receipts/v1";

/// The typed `audit/v1` report — the versioned output of one spend re-derivation,
/// shared by the gateway CLI, the tool servers, and every binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditV1 {
    /// Always `"audit/v1"`.
    pub version: String,
    /// The typed audit verdict (tagged, kebab-case — the walk's own serialization).
    pub verdict: AuditVerdict,
    /// The stable verdict code (`consistent`, `tampered-proof`, …).
    pub code: String,
    /// True only for a `consistent` re-derivation.
    pub consistent: bool,
    /// Records audited.
    pub records: usize,
    /// The re-derived cross-rail settled total (cents).
    pub settled_cents: u64,
    /// The resumable end state for a checkpointing caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<AuditCheckpoint>,
    /// The treasury cross-check result, when a trail was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub treasury: Option<TreasuryCheck>,
}

/// The `audit/v1` version string.
pub const AUDIT_VERSION: &str = "audit/v1";

/// The resumable end state of a verified log — what a checkpointing caller stores.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    /// Records verified.
    pub records: usize,
    /// The re-derived settled total (cents).
    pub settled_cents: u64,
    /// The final commit binding (the next record's `Auths-Prev`).
    pub binding: String,
}

/// A verified treasury checkpoint trail's final state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TreasuryCheck {
    /// The fleet the trail is for.
    pub fleet: String,
    /// The final checkpoint's reservation count.
    pub count: u64,
    /// The final checkpointed cumulative (cents).
    pub cumulative_cents: u64,
    /// When the final checkpoint was signed.
    pub at: DateTime<Utc>,
}
