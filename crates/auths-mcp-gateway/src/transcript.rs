//! The frozen-transcript schema the replay gate drives the gateway from (PRD §7).
//!
//! A transcript captures a prior run's grant and the agent's `tools/call`
//! sequence, plus the per-call verdict expectation. Replay re-derives each verdict
//! from the chain (no model, no network) and asserts it matches — so a transcript
//! edited to drop a proof or forge a wider scope still fails closed.

use std::path::Path;

use serde::Deserialize;

/// One transcript: the grant the agent was delegated and the sequence of steps
/// (tool calls and mid-session events such as a revocation).
#[derive(Debug, Clone, Deserialize)]
pub struct Transcript {
    /// The delegation the agent holds for this session.
    pub grant: Grant,
    /// The ordered steps of the session — `tools/call`s interleaved with events.
    pub calls: Vec<Step>,
}

/// The agent's delegation: the scope, budget, and TTL its parent anchored.
#[derive(Debug, Clone, Deserialize)]
pub struct Grant {
    /// The capabilities granted (e.g. `["fs.read"]`).
    pub scope: Vec<String>,
    /// The session budget string (e.g. `"$5.00"`, `"20calls"`).
    #[serde(default)]
    pub budget: Option<String>,
    /// The grant TTL string (e.g. `"30m"`). Carried for completeness; expiry is
    /// enforced from the delegator-anchored seal at verify time, not from this
    /// field — so it is parsed but not read by the gate.
    #[serde(default)]
    #[allow(dead_code)]
    pub ttl: Option<String>,
}

/// One step in the transcript: either a `tools/call` or a mid-session event.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Step {
    /// A mid-session control event (e.g. `{ "event": "revoke" }`).
    Event {
        /// The event name (`revoke`).
        event: String,
    },
    /// A `tools/call` the agent emitted.
    Call(Call),
}

/// A single `tools/call` the agent emitted, plus its expected verdict.
#[derive(Debug, Clone, Deserialize)]
pub struct Call {
    /// The downstream tool name (e.g. `read_file`).
    pub tool: String,
    /// The call arguments.
    #[serde(default)]
    pub args: serde_json::Value,
    /// The metered cost in cents this call would incur (0 for non-metered tools).
    #[serde(default)]
    pub cost_cents: u64,
    /// The verdict this call is expected to produce (e.g. `allowed`,
    /// `outside-agent-scope`). Replay asserts the re-derived verdict matches.
    #[serde(default)]
    pub expect: Option<String>,
}

impl Transcript {
    /// Load and parse a transcript from disk.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read transcript {}: {e}", path.display()))?;
        let t: Transcript = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parse transcript {}: {e}", path.display()))?;
        Ok(t)
    }
}
