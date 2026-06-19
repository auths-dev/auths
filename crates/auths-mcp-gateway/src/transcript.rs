//! The frozen-transcript schema the replay gate drives the gateway from.
//!
//! A transcript captures a prior run's grant and the agent's `tools/call`
//! sequence, plus the per-call verdict expectation. Replay re-derives each verdict
//! from the chain (no model, no network) and asserts it matches — so a transcript
//! edited to drop a proof or forge a wider scope still fails closed.

use std::path::Path;

use auths_mcp_core::Cents;
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
    /// The payment rail this metered call settles on (e.g. `stripe`, `x402`). One
    /// `$5` cap is metered across BOTH rails into a single cross-rail counter (D8);
    /// a per-rail-siloed budget would miss the cross-over. Non-metered calls omit it.
    #[serde(default)]
    pub rail: Option<String>,
    /// The call arguments.
    #[serde(default)]
    pub args: serde_json::Value,
    /// The metered cost in cents this call would incur (0 for non-metered tools).
    /// For a metered call this is the *actual* the rail reports on the response —
    /// what gets SETTLED into the monotonic counter after the call returns.
    #[serde(default = "Cents::zero")]
    pub cost_cents: Cents,
    /// The ceiling RESERVED before the rail is touched (the pre-authorization hold,
    /// D8). For a known-cost call this equals `cost_cents`; for a metered call whose
    /// final cost is bounded but not yet known it is the ceiling. The reservation is
    /// what `available = cap − settled − Σ(holds)` is checked against; the slack
    /// (`ceiling − actual`) is RELEASED on settle. Defaults to `cost_cents`.
    #[serde(default)]
    pub reserve_ceiling_cents: Option<Cents>,
    /// The recorded rail-response fixture the gateway EXTRACTS this call's cost from
    /// (e.g. `stripe-charge.test.json`), resolved under `AUTHS_MCP_RAIL_FIXTURES`. When
    /// present, the cost is NOT taken from `cost_cents` — it is read out of the rail's
    /// own response (the documented charge amount), so an agent under-declaring the cost
    /// cannot change what is metered (the metered-rail cost extraction). The
    /// reserved ceiling and the settled actual both come from this response.
    #[serde(default)]
    pub response_fixture: Option<String>,
    /// The documented response field the cost is extracted from (e.g.
    /// `charge.amount_captured`). Carried for self-description / audit; the extractor is
    /// dispatched by `rail`, so this names — for a reader of the transcript — exactly
    /// which field of the recorded response is the authoritative cost.
    #[serde(default)]
    #[allow(dead_code)]
    pub extract: Option<String>,
    /// The verdict this call is expected to produce (e.g. `allowed`,
    /// `outside-agent-scope`). Replay asserts the re-derived verdict matches.
    #[serde(default)]
    pub expect: Option<String>,
}

impl Call {
    /// The ceiling this call reserves before the rail is touched — the metered
    /// `reserve_ceiling_cents` if present, else the known `cost_cents`.
    pub fn reserve_ceiling(&self) -> Cents {
        self.reserve_ceiling_cents.unwrap_or(self.cost_cents)
    }

    /// The rail this metered call settles on, for the cross-rail attribution in the
    /// receipt. A non-metered call (no rail) settles on no rail.
    pub fn rail(&self) -> Option<&str> {
        self.rail.as_deref()
    }

    /// The recorded rail-response fixture this call extracts its cost from, if any. When
    /// `Some`, the cost is rail-response-authoritative (read from the response), not the
    /// transcript's `cost_cents`.
    pub fn response_fixture(&self) -> Option<&str> {
        self.response_fixture.as_deref()
    }
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
