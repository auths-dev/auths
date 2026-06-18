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

/// A serialized MCP `tools/call` the gate judges. The canonical bytes (tool name
/// + sorted args) are what gets signed as the auths artifact.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolCall {
    /// The downstream tool name (e.g. `read_file`).
    pub tool: String,
    /// The canonical JSON of the call arguments.
    pub args: serde_json::Value,
    /// The metered cost this call would incur (cents), if the tool is metered.
    #[serde(default)]
    pub cost_cents: u64,
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
    UsageCapExceeded { cap_cents: u64, would_be_cents: u64 },
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
        presented_cents: u64,
        high_water_cents: u64,
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
    pub cumulative_cents: u64,
    /// The reserved ceiling the pre-authorization took (0 for a non-paid/refused call).
    pub reserved_cents: u64,
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
    ) -> crate::audit::AuditVerdict {
        crate::audit::audit_spend_log(
            records,
            &self.agent_kel,
            &self.delegator_kel,
            std::slice::from_ref(&self.delegator_did),
            now,
        )
        .await
    }

    /// Judge one `tools/call`, given the bytes of the agent's signed proof, the rail
    /// it would settle on, the ceiling it reserves, and the cross-rail budget it
    /// PRE-AUTHORIZES against.
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
    ///    the call is metered (`reserve_ceiling > 0`), RESERVE the ceiling against the
    ///    cross-rail budget's `available = cap − settled − Σ(holds)` BEFORE the rail is
    ///    touched. A reservation that would cross the cap is refused
    ///    [`Verdict::UsageCapExceeded`] and **no hold is taken** (the metered
    ///    downstream is never invoked). On success the verdict is [`Verdict::Allowed`]
    ///    and the [`Decision`] carries the [`Hold`] the caller SETTLES after the
    ///    downstream returns (advancing the monotonic SETTLED counter by the *actual*
    ///    and releasing the slack).
    ///
    /// The cap-crossing refusal is computed against the ONE cross-rail counter, so a
    /// call that would exceed the cap across rails is refused even when a per-rail silo
    /// would still read in-budget. The settle (and its monotonic rollback guard) is the
    /// caller's post-downstream step ([`PerCallGate::settle`]).
    pub async fn judge(
        &self,
        rail: Option<&str>,
        reserve_ceiling_cents: u64,
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
                reserved_cents: 0,
                hold: None,
                rail: rail.map(str::to_string),
            });
        }

        // Authenticated + in-scope + live. Pre-authorize the spend BEFORE the rail is touched.
        // A payment rail is set but no amount was declared → the gate cannot reserve, hence cannot
        // bound, this charge, so it refuses fail-closed: forwarding would let the rail charge while
        // the durable cap never advanced. An omitted amount must not skip the meter.
        if let Some(rail_name) = rail
            && reserve_ceiling_cents == 0
        {
            return Ok(Decision {
                verdict: Verdict::MeteredAmountRequired {
                    rail: rail_name.to_string(),
                },
                cumulative_cents: settled,
                reserved_cents: 0,
                hold: None,
                rail: Some(rail_name.to_string()),
            });
        }
        // No rail and no declared cost → non-metered (e.g. fs.read): no reservation, nothing to
        // settle. (A declared cost without a rail name still has ceiling > 0 and reserves below.)
        if reserve_ceiling_cents == 0 {
            return Ok(Decision {
                verdict: Verdict::Allowed,
                cumulative_cents: settled,
                reserved_cents: 0,
                hold: None,
                rail: None,
            });
        }

        let outcome = budget
            .reserve(reserve_ceiling_cents)
            .map_err(|e| GateError::Registry(format!("reserve: {e}")))?;
        match outcome {
            ReserveOutcome::Reserved { hold, .. } => Ok(Decision {
                verdict: Verdict::Allowed,
                cumulative_cents: settled,
                reserved_cents: reserve_ceiling_cents,
                hold: Some(hold),
                rail: rail.map(str::to_string),
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
                reserved_cents: 0,
                hold: None,
                rail: rail.map(str::to_string),
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
        actual_cents: u64,
    ) -> Result<(Verdict, u64), GateError> {
        use crate::budget::SettleOutcome;
        let outcome = budget
            .settle(hold, actual_cents)
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
                cost_cents: 0,
            }
            .capability(),
            Capability("fs.read".into())
        );
        assert_eq!(
            ToolCall {
                tool: "write_file".into(),
                args: serde_json::json!({}),
                cost_cents: 0,
            }
            .capability(),
            Capability("fs.write".into())
        );
        // An unknown tool fails closed (a capability the delegator never granted).
        assert_eq!(
            ToolCall {
                tool: "rm_rf".into(),
                args: serde_json::json!({}),
                cost_cents: 0,
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
            cost_cents: 0,
        };
        let b = ToolCall {
            tool: "read_file".into(),
            // Different key order — canonicalization must collapse to the same bytes.
            args: serde_json::json!({ "a": 1, "path": "README.md" }),
            cost_cents: 0,
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
