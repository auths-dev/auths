//! The one per-`tools/call` gate: scope ⊆ parent · budget · expiry · revocation.
//!
//! Every brokered `tools/call` is canonicalized, signed as an auths artifact (a
//! git commit over the canonical call), and judged here against the agent's
//! delegator-anchored grant. The gate resolves the agent's delegated KEL **and**
//! its delegator's KEL from the registry and runs
//! [`auths_verifier::verify_commit_against_kel_scoped`] — the proven, delegation-
//! aware authorization. It returns a [`Decision`] carrying the machine-readable
//! [`Verdict`]; the gateway forwards to the downstream server **only** on
//! [`Verdict::Allowed`], and emits a receipt either way.

use auths_sdk::keri::KelResolverChain;
use auths_sdk::ports::RegistryBackend;
use auths_verifier::CommitVerdict;
use chrono::{DateTime, Utc};

use crate::Capability;
use crate::budget::{CrossRailBudget, Hold, ReserveOutcome};
use crate::money::{Actual, Ceiling, Cents, NonZeroCents};

/// A serialized MCP `tools/call` the gate judges. The canonical bytes (tool name
/// + sorted args) are what gets signed as the auths artifact.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolCall {
    /// The downstream tool name (e.g. `read_file`).
    pub tool: String,
    /// The canonical JSON of the call arguments.
    pub args: serde_json::Value,
    /// The metered cost this call would incur (cents), if the tool is metered.
    #[serde(default = "Cents::zero")]
    pub cost_cents: Cents,
}

impl ToolCall {
    /// The capability this call exercises (the tool→capability map).
    pub fn capability(&self) -> Capability {
        Capability::for_tool(&self.tool)
    }

    /// The canonical bytes signed as the auths artifact (stable across runs so the
    /// receipt is reproducible): RFC-8785 JSON canonicalization of `{tool, args}`.
    /// These are the exact bytes the agent's per-call signature covers; tampering
    /// with the call after signing breaks the signature at the verify boundary.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let body = serde_json::json!({ "tool": self.tool, "args": self.args });
        // json-canon is the same RFC-8785 canonicalizer auths uses for attestation
        // bodies; on the (unreachable) error path fall back to compact serde so the
        // call still has stable bytes rather than panicking.
        json_canon::to_string(&body)
            .unwrap_or_else(|_| body.to_string())
            .into_bytes()
    }
}

/// The machine-readable verdict for one brokered call — the distinct codes the
/// incumbents cannot express. Each maps to a fail-closed MCP error the
/// model can read and react to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// In scope, in budget, unexpired, unrevoked — forward to the downstream tool.
    Allowed,
    /// The requested capability lies outside the agent's delegator-anchored scope
    /// (maps AGT-1). Carries the offending capability.
    OutsideAgentScope { capability: Capability },
    /// The call would cross the session budget cap (maps AGT-4). For the cross-rail
    /// budget (D8) this is the reservation refusal: `settled + Σ(holds) + ceiling`
    /// would exceed the cap, refused BEFORE the rail is touched.
    UsageCapExceeded {
        cap_cents: Cents,
        would_be_cents: Cents,
    },
    /// A payment rail is set but the call declared no amount to meter, so the gate cannot reserve —
    /// and therefore cannot bound — the charge before the rail is touched. Refused fail-closed: a
    /// metered call must declare what it intends to spend, so an omitted amount can never let the
    /// rail charge while the durable cap stays unmoved.
    MeteredAmountRequired { rail: String },
    /// A settle presented a cumulative SETTLED total *below* the verifier-held
    /// monotonic high-water — a replayed/stale total (e.g. a crashed-and-restored
    /// gateway that reloaded a stale snapshot). Refused so the counter cannot roll
    /// back (the D8 monotonicity guard; maps AGT-4's `UsageCounterRolledBack`).
    UsageCounterRolledBack {
        presented_cents: Cents,
        high_water_cents: Cents,
    },
    /// The grant is past its anchored expiry at the injected `now`.
    AgentExpired,
    /// The grant was revoked — liveness re-derived from the chain (maps OPS-1).
    Revoked,
    /// The signed call did not authenticate against the agent's grant for a reason
    /// other than the above (bad signature, unanchored signer, broken chain). The
    /// gateway treats this as a hard fail-closed: the call is not forwarded. A
    /// forged or malformed proof lands here.
    ProofUnauthentic { reason: String },
}

impl Verdict {
    /// The stable kebab-case code for this verdict, for the gateway's verdict line.
    pub fn code(&self) -> &'static str {
        match self {
            Verdict::Allowed => "allowed",
            Verdict::OutsideAgentScope { .. } => "outside-agent-scope",
            Verdict::UsageCapExceeded { .. } => "usage-cap-exceeded",
            Verdict::MeteredAmountRequired { .. } => "metered-amount-required",
            Verdict::UsageCounterRolledBack { .. } => "usage-counter-rolled-back",
            Verdict::AgentExpired => "agent-expired",
            Verdict::Revoked => "revoked",
            Verdict::ProofUnauthentic { .. } => "proof-unauthentic",
        }
    }

    /// Map an `auths-verifier` [`CommitVerdict`] (the proven authorization verdict
    /// over the signed call) into the gateway's per-call [`Verdict`]. The scope,
    /// expiry, and revocation rejections come straight from the verifier; anything
    /// else non-`Valid` is an unauthentic proof and fails closed.
    pub(crate) fn from_commit_verdict(v: &CommitVerdict) -> Self {
        match v {
            CommitVerdict::Valid { .. } => Verdict::Allowed,
            CommitVerdict::OutsideAgentScope { capability, .. } => Verdict::OutsideAgentScope {
                capability: Capability(capability.clone()),
            },
            CommitVerdict::AgentExpired { .. } => Verdict::AgentExpired,
            CommitVerdict::DeviceRevoked | CommitVerdict::SignedAfterRevocation { .. } => {
                Verdict::Revoked
            }
            other => Verdict::ProofUnauthentic {
                reason: other.code().to_string(),
            },
        }
    }
}

/// The reservation a brokered `tools/call` carries into the gate: either it is non-metered (no
/// rail, nothing to reserve or settle) or it is metered on a named rail with a NON-ZERO ceiling
/// reserved before the rail is touched. The rail and the ceiling move together, so "a rail with no
/// amount" and "an amount with no rail" are both unrepresentable — the gate can no longer treat a
/// zero ceiling as a non-metered call, which is the gap that let an undeclared metered call skip the
/// cap. An operator rail with no declared amount is parsed to a fail-closed refusal at the wire
/// boundary (before the gate), so it never reaches the gate as a `Meter`.
#[derive(Debug, Clone)]
pub enum Meter {
    /// Non-metered (e.g. `fs.read`): no rail, no reservation, nothing to settle.
    Unmetered,
    /// Metered on `rail`, reserving `ceiling` cents before the rail is touched.
    Metered {
        /// The payment rail this call settles on (cross-rail attribution).
        rail: String,
        /// The non-zero ceiling reserved before the rail is touched.
        ceiling: NonZeroCents,
    },
}

impl Meter {
    /// The rail this call settles on, for receipt attribution — `None` when non-metered.
    pub fn rail(&self) -> Option<&str> {
        match self {
            Meter::Unmetered => None,
            Meter::Metered { rail, .. } => Some(rail.as_str()),
        }
    }
}

/// One gate decision for a paid call: the verdict, the running cross-rail total, and
/// — when the call was authorized — the pre-authorization [`Hold`] the caller must
/// SETTLE (with the actual cost) once the downstream returns, plus the rail it
/// settles on. A refused call carries no hold (the rail is never touched).
#[derive(Debug, Clone)]
pub struct Decision {
    /// The fail-closed verdict for this call.
    pub verdict: Verdict,
    /// The running cross-rail SETTLED total this call's receipt reports (the durable
    /// counter the moment the decision was made, before this call settles).
    pub cumulative_cents: Cents,
    /// The reserved ceiling the pre-authorization took (zero for a non-paid/refused call).
    pub reserved_cents: Cents,
    /// The pre-authorization hold to settle after the downstream returns — `Some` only
    /// when the call was authorized (reserved). `None` for a refused or non-paid call.
    pub hold: Option<Hold>,
    /// The payment rail this paid call settles on (cross-rail attribution).
    pub rail: Option<String>,
}

impl Decision {
    /// Whether the gateway should forward this call to the downstream server.
    pub fn forwards(&self) -> bool {
        matches!(self.verdict, Verdict::Allowed)
    }
}

/// Errors that abort a gate evaluation before a verdict (could-not-measure, not a
/// fail-closed verdict). The gateway surfaces these as protocol errors, not tool
/// refusals.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("could not resolve the agent's delegator-anchored grant: {0}")]
    GrantUnresolved(String),
    #[error("could not verify the signed call artifact: {0}")]
    ArtifactUnverified(String),
    #[error("registry/liveness lookup failed: {0}")]
    Registry(String),
}

/// The per-call gate. Holds the agent's and delegator's `did:keri:` and the
/// resolved KELs; judges each `tools/call`'s signed proof against the
/// delegator-anchored grant with an injected `now` and the running session ledger.
pub struct PerCallGate {
    /// The agent's delegated identity (did:keri) whose grant bounds every call.
    pub agent_did: String,
    /// The parent/delegator did:keri the scope/budget/expiry seal is anchored to.
    pub delegator_did: String,
    /// The agent's delegated KEL (a `dip`), resolved once at construction.
    agent_kel: Vec<auths_id::keri::Event>,
    /// The delegator's KEL (carries the scope/expiry/revocation seals).
    delegator_kel: Vec<auths_id::keri::Event>,
}

impl PerCallGate {
    /// Build a gate for an agent, resolving its delegated KEL and its delegator's
    /// KEL from the registry (offline, no issuer). The same local KEL resolution
    /// the commit-trust path uses.
    pub fn resolve(
        registry: &dyn RegistryBackend,
        agent_did: &str,
        delegator_did: &str,
    ) -> Result<Self, GateError> {
        let chain = KelResolverChain::local(registry);
        let agent_kel = chain
            .resolve_kel(agent_did)
            .map_err(|e| GateError::GrantUnresolved(format!("agent KEL {agent_did}: {e}")))?;
        let delegator_kel = chain.resolve_kel(delegator_did).map_err(|e| {
            GateError::GrantUnresolved(format!("delegator KEL {delegator_did}: {e}"))
        })?;
        Ok(Self {
            agent_did: agent_did.to_string(),
            delegator_did: delegator_did.to_string(),
            agent_kel,
            delegator_kel,
        })
    }

    /// Independently re-audit a persisted spend log with THIS gate's resolved KELs — the offline
    /// [`crate::audit::audit_spend_log`] driven by the same agent/delegator KELs + pinned root the
    /// gate judges against. Lets the hermetic gate re-audit its own log end-to-end: after a run,
    /// re-verify the log it wrote and confirm a tampered proof is caught.
    pub async fn audit_spend_log(
        &self,
        records: &[crate::audit::SpendLogRecord],
        now: i64,
        counter: &crate::budget::CounterRef,
        facilitator_pubkey: Option<&[u8]>,
    ) -> crate::audit::AuditVerdict {
        crate::audit::audit_spend_log(
            records,
            &self.agent_kel,
            &self.delegator_kel,
            std::slice::from_ref(&self.delegator_did),
            now,
            counter,
            facilitator_pubkey,
        )
        .await
    }

    /// Judge one `tools/call`, given the bytes of the agent's signed proof, the
    /// [`Meter`] it carries (non-metered, or metered on a rail with a non-zero ceiling),
    /// and the cross-rail budget it PRE-AUTHORIZES against.
    ///
    /// `signed_proof` is the raw git-commit object the agent produced over the
    /// canonical call (with the `Auths-Scope` trailer naming the exercised
    /// capability). The single entrypoint the gateway calls per call:
    ///
    /// 1. **authenticity + scope + expiry + revocation** — run the proven
    ///    [`auths_verifier::verify_commit_against_kel_scoped`] over the signed
    ///    proof against the agent's and delegator's KELs at `now`; a non-`Valid`
    ///    verdict is a fail-closed [`Verdict`] (scope/expiry/revocation) or, for
    ///    anything else, [`Verdict::ProofUnauthentic`];
    /// 2. **budget (pre-authorization, D8)** — only when the proof authenticated AND
    ///    the call is [`Meter::Metered`], RESERVE the ceiling against the cross-rail
    ///    budget's `available = cap − settled − Σ(holds)` BEFORE the rail is touched. A
    ///    reservation that would cross the cap is refused [`Verdict::UsageCapExceeded`]
    ///    and **no hold is taken** (the metered downstream is never invoked). On success
    ///    the verdict is [`Verdict::Allowed`] and the [`Decision`] carries the [`Hold`]
    ///    the caller SETTLES after the downstream returns (advancing the monotonic
    ///    SETTLED counter by the *actual* and releasing the slack).
    ///
    /// The metered ceiling is a [`NonZeroCents`] by construction, so a zero ceiling can no
    /// longer be mistaken for a non-metered call. The "metered rail with no declared amount"
    /// case is parsed to a fail-closed refusal at the wire boundary BEFORE this gate (see
    /// [`Verdict::MeteredAmountRequired`]) and never reaches `judge`.
    ///
    /// The cap-crossing refusal is computed against the ONE cross-rail counter, so a
    /// call that would exceed the cap across rails is refused even when a per-rail silo
    /// would still read in-budget. The settle (and its monotonic rollback guard) is the
    /// caller's post-downstream step ([`PerCallGate::settle`]).
    pub async fn judge(
        &self,
        meter: &Meter,
        signed_proof: &[u8],
        now: DateTime<Utc>,
        budget: &mut CrossRailBudget,
    ) -> Result<Decision, GateError> {
        let pinned_roots = vec![self.delegator_did.clone()];
        let provider = auths_crypto::default_provider();

        let commit_verdict = auths_verifier::verify_commit_against_kel_scoped(
            signed_proof,
            &self.agent_kel,
            &self.delegator_kel,
            &pinned_roots,
            provider,
            now.timestamp(),
        )
        .await;

        let auth_verdict = Verdict::from_commit_verdict(&commit_verdict);
        let settled = budget
            .settled_cents()
            .map_err(|e| GateError::Registry(format!("settled counter: {e}")))?;

        // The running cross-rail total the receipt reports is the durable SETTLED
        // counter (summed across all rails) at decision time. A refused or non-paid
        // call leaves it unchanged.
        if !matches!(auth_verdict, Verdict::Allowed) {
            return Ok(Decision {
                verdict: auth_verdict,
                cumulative_cents: settled,
                reserved_cents: Cents::ZERO,
                hold: None,
                rail: meter.rail().map(str::to_string),
            });
        }

        // Authenticated + in-scope + live. A non-metered call reserves nothing and settles nothing.
        let Meter::Metered { rail, ceiling } = meter else {
            return Ok(Decision {
                verdict: Verdict::Allowed,
                cumulative_cents: settled,
                reserved_cents: Cents::ZERO,
                hold: None,
                rail: None,
            });
        };

        // Pre-authorize the spend BEFORE the rail is touched. The ceiling is NON-ZERO by type — a
        // metered rail with no declared amount was refused at the parse boundary, before this gate —
        // so there is no zero-ceiling case here to mistake for a non-metered call.
        let outcome = budget
            .reserve(Ceiling::new(ceiling.get()))
            .map_err(|e| GateError::Registry(format!("reserve: {e}")))?;
        match outcome {
            ReserveOutcome::Reserved { hold, .. } => Ok(Decision {
                verdict: Verdict::Allowed,
                cumulative_cents: settled,
                reserved_cents: ceiling.get(),
                hold: Some(hold),
                rail: Some(rail.clone()),
            }),
            ReserveOutcome::Refused {
                cap_cents,
                would_be_cents,
            } => Ok(Decision {
                verdict: Verdict::UsageCapExceeded {
                    cap_cents,
                    would_be_cents,
                },
                cumulative_cents: settled,
                reserved_cents: Cents::ZERO,
                hold: None,
                rail: Some(rail.clone()),
            }),
        }
    }

    /// SETTLE a forwarded paid call's ACTUAL cost into the cross-rail budget after the
    /// downstream returns: release the pre-authorization hold (returning the slack) and
    /// advance the monotonic SETTLED counter. Returns the verdict to record for the
    /// call — [`Verdict::Allowed`] on a clean advance, or
    /// [`Verdict::UsageCounterRolledBack`] if the new cumulative would fall below the
    /// verifier-held high-water (a replayed/stale total), plus the new cross-rail total.
    pub fn settle(
        &self,
        budget: &mut CrossRailBudget,
        hold: Hold,
        actual: Actual,
    ) -> Result<(Verdict, Cents), GateError> {
        use crate::budget::SettleOutcome;
        let outcome = budget
            .settle(hold, actual)
            .map_err(|e| GateError::Registry(format!("settle: {e}")))?;
        match outcome {
            SettleOutcome::Advanced { new_settled_cents } => {
                Ok((Verdict::Allowed, new_settled_cents))
            }
            SettleOutcome::RolledBack {
                presented_cents,
                high_water_cents,
            } => Ok((
                Verdict::UsageCounterRolledBack {
                    presented_cents,
                    high_water_cents,
                },
                high_water_cents,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_to_capability_map() {
        assert_eq!(
            ToolCall {
                tool: "read_file".into(),
                args: serde_json::json!({}),
                cost_cents: Cents::ZERO,
            }
            .capability(),
            Capability("fs.read".into())
        );
        assert_eq!(
            ToolCall {
                tool: "write_file".into(),
                args: serde_json::json!({}),
                cost_cents: Cents::ZERO,
            }
            .capability(),
            Capability("fs.write".into())
        );
        // An unknown tool fails closed (a capability the delegator never granted).
        assert_eq!(
            ToolCall {
                tool: "rm_rf".into(),
                args: serde_json::json!({}),
                cost_cents: Cents::ZERO,
            }
            .capability(),
            Capability("tool.rm_rf".into())
        );
    }

    #[test]
    fn canonical_bytes_are_stable() {
        let a = ToolCall {
            tool: "read_file".into(),
            args: serde_json::json!({ "path": "README.md", "a": 1 }),
            cost_cents: Cents::ZERO,
        };
        let b = ToolCall {
            tool: "read_file".into(),
            // Different key order — canonicalization must collapse to the same bytes.
            args: serde_json::json!({ "a": 1, "path": "README.md" }),
            cost_cents: Cents::ZERO,
        };
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn commit_verdict_maps_to_gate_verdict() {
        assert_eq!(
            Verdict::from_commit_verdict(&CommitVerdict::Valid {
                signer_did: "did:keri:Eagent".into(),
                root_did: "did:keri:Eroot".into(),
                duplicitous_root: false,
            }),
            Verdict::Allowed
        );
        assert_eq!(
            Verdict::from_commit_verdict(&CommitVerdict::OutsideAgentScope {
                signer_did: "did:keri:Eagent".into(),
                capability: "fs.write".into(),
            }),
            Verdict::OutsideAgentScope {
                capability: Capability("fs.write".into())
            }
        );
        assert_eq!(
            Verdict::from_commit_verdict(&CommitVerdict::DeviceRevoked),
            Verdict::Revoked
        );
        // A bad signature is an unauthentic proof — fail closed.
        assert!(matches!(
            Verdict::from_commit_verdict(&CommitVerdict::SshSignatureInvalid),
            Verdict::ProofUnauthentic { .. }
        ));
    }
}
