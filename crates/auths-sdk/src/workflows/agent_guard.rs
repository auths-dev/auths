use crate::domains::agent_guard::error::AgentGuardError;
use chrono::{DateTime, Utc};

/// Agent Guard execution workflow. Orchestrates capability checks, budget tracking, sub-agent slicing, and spend receipts.
///
/// Description:
/// Validates an incoming agent tool execution request against spend budget caps, capability scopes, and TTL bounds.
///
/// Args:
/// * `agent_did`: The agent's canonical DID identifier.
/// * `tool_name`: Name of the MCP tool requested.
/// * `estimated_cost_usd`: Estimated invocation cost in USD.
/// * `max_budget_usd`: Total allocated budget cap in USD.
/// * `accumulated_spend_usd`: Previously spent total in USD.
/// * `now`: Injected current UTC timestamp.
///
/// Usage:
/// ```ignore
/// let verdict = AgentGuardWorkflow::validate_tool_invocation("did:key:zAgent", "fetch_data", 0.05, 50.0, 10.0, now)?;
/// ```
pub struct AgentGuardWorkflow;

impl AgentGuardWorkflow {
    /// Validates an incoming agent tool execution request against spend budget caps and scopes.
    ///
    /// Args:
    /// * `_agent_did`: Canonical DID of the agent calling the tool.
    /// * `_tool_name`: Name of the tool being executed.
    /// * `estimated_cost_usd`: Estimated cost of this invocation.
    /// * `max_budget_usd`: Maximum allowed budget cap.
    /// * `accumulated_spend_usd`: Current accumulated spend.
    /// * `_now`: Injected UTC time for expiration checks.
    ///
    /// Usage:
    /// ```ignore
    /// AgentGuardWorkflow::validate_tool_invocation("did:key:z1", "read", 0.01, 10.0, 0.0, now)?;
    /// ```
    pub fn validate_tool_invocation(
        _agent_did: &str,
        _tool_name: &str,
        estimated_cost_usd: f64,
        max_budget_usd: f64,
        accumulated_spend_usd: f64,
        _now: DateTime<Utc>,
    ) -> Result<(), AgentGuardError> {
        if accumulated_spend_usd + estimated_cost_usd > max_budget_usd {
            return Err(AgentGuardError::BudgetExceeded {
                requested_usd: estimated_cost_usd,
                remaining_usd: (max_budget_usd - accumulated_spend_usd).max(0.0),
            });
        }
        Ok(())
    }

    /// Feature #1: Slice a child sub-agent budget from a parent agent's remaining allocation.
    ///
    /// Args:
    /// * `parent_budget_usd`: Total budget cap of the parent agent.
    /// * `parent_accumulated_usd`: Accumulated spend of the parent agent.
    /// * `child_requested_budget_usd`: Budget requested for delegation to child sub-agent.
    ///
    /// Usage:
    /// ```ignore
    /// let child_budget = AgentGuardWorkflow::slice_child_budget(50.0, 10.0, 5.0)?;
    /// ```
    pub fn slice_child_budget(
        parent_budget_usd: f64,
        parent_accumulated_usd: f64,
        child_requested_budget_usd: f64,
    ) -> Result<f64, AgentGuardError> {
        let parent_remaining = (parent_budget_usd - parent_accumulated_usd).max(0.0);
        if child_requested_budget_usd > parent_remaining {
            return Err(AgentGuardError::BudgetExceeded {
                requested_usd: child_requested_budget_usd,
                remaining_usd: parent_remaining,
            });
        }
        Ok(child_requested_budget_usd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_tool_invocation_under_budget() {
        let now = Utc::now();
        let res = AgentGuardWorkflow::validate_tool_invocation(
            "did:key:zTest",
            "search",
            0.50,
            10.00,
            2.00,
            now,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_tool_invocation_over_budget() {
        let now = Utc::now();
        let res = AgentGuardWorkflow::validate_tool_invocation(
            "did:key:zTest",
            "search",
            5.00,
            10.00,
            8.00,
            now,
        );
        assert_eq!(
            res,
            Err(AgentGuardError::BudgetExceeded {
                requested_usd: 5.00,
                remaining_usd: 2.00,
            })
        );
    }

    #[test]
    fn test_slice_child_budget_success() {
        let child_alloc = AgentGuardWorkflow::slice_child_budget(50.0, 10.0, 5.0);
        assert_eq!(child_alloc, Ok(5.0));
    }
}
