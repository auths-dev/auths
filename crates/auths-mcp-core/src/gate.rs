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
use crate::session::SessionLedger;

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
/// incumbents cannot express (PRD §2). Each maps to a fail-closed MCP error the
/// model can read and react to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// In scope, in budget, unexpired, unrevoked — forward to the downstream tool.
    Allowed,
    /// The requested capability lies outside the agent's delegator-anchored scope
    /// (maps AGT-1). Carries the offending capability.
    OutsideAgentScope { capability: Capability },
    /// The call would cross the session budget cap (maps AGT-4).
    UsageCapExceeded { cap_cents: u64, would_be_cents: u64 },
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
            Verdict::AgentExpired => "agent-expired",
            Verdict::Revoked => "revoked",
            Verdict::ProofUnauthentic { .. } => "proof-unauthentic",
        }
    }

    /// Map an `auths-verifier` [`CommitVerdict`] (the proven authorization verdict
    /// over the signed call) into the gateway's per-call [`Verdict`]. The scope,
    /// expiry, and revocation rejections come straight from the verifier; anything
    /// else non-`Valid` is an unauthentic proof and fails closed.
    fn from_commit_verdict(v: &CommitVerdict) -> Self {
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

/// One gate decision: the verdict plus the cumulative spend after this call (for
/// the receipt's running total).
#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub cumulative_cents: u64,
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

    /// Judge one `tools/call`, given the bytes of the agent's signed proof.
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
    /// 2. **budget** — only when the proof authenticated, `ledger.spent + cost ≤
    ///    cap`, else [`Verdict::UsageCapExceeded`].
    ///
    /// Returns the verdict plus the cumulative spend *if this call were allowed*
    /// (the receipt's running total); the gateway charges the ledger on `Allowed`.
    pub async fn judge(
        &self,
        call: &ToolCall,
        signed_proof: &[u8],
        now: DateTime<Utc>,
        ledger: &SessionLedger,
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

        let verdict = Verdict::from_commit_verdict(&commit_verdict);

        // Budget is the second gate, applied only to an authenticated, in-scope,
        // live call. The quantitative-cap enforcement is wired here over the session
        // ledger (the cross-rail budget product surface builds on this counter).
        let (verdict, cumulative) = if matches!(verdict, Verdict::Allowed) {
            if ledger.would_stay_within(call.cost_cents) {
                (
                    Verdict::Allowed,
                    ledger.spent_cents.saturating_add(call.cost_cents),
                )
            } else {
                (
                    Verdict::UsageCapExceeded {
                        cap_cents: ledger.cap_cents(),
                        would_be_cents: ledger.spent_cents.saturating_add(call.cost_cents),
                    },
                    ledger.spent_cents,
                )
            }
        } else {
            // A refused call is never charged; the running total is unchanged.
            (verdict, ledger.spent_cents)
        };

        Ok(Decision {
            verdict,
            cumulative_cents: cumulative,
        })
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
