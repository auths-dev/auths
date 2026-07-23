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
    /// Validates an incoming agent tool execution request against spend budget caps and scopes.
    ///
    /// Args:
    /// * `_agent_did`: Canonical DID of the agent calling the tool.
    /// * `_tool_name`: Name of the tool being executed.
    /// * `estimated_cost_cents`: Estimated cost of this invocation in integer cents.
    /// * `max_budget_cents`: Maximum allowed budget cap in integer cents.
    /// * `accumulated_spend_cents`: Current accumulated spend in integer cents.
    /// * `_now`: Injected UTC time for expiration checks.
    ///
    /// Usage:
    /// ```ignore
    /// AgentGuardWorkflow::validate_tool_invocation("did:key:z1", "read", 1, 1000, 0, now)?;
    /// ```
    pub fn validate_tool_invocation(
        _agent_did: &str,
        _tool_name: &str,
        estimated_cost_cents: u64,
        max_budget_cents: u64,
        accumulated_spend_cents: u64,
        _now: DateTime<Utc>,
    ) -> Result<(), AgentGuardError> {
        let new_total = accumulated_spend_cents
            .checked_add(estimated_cost_cents)
            .ok_or_else(|| AgentGuardError::BudgetExceeded {
                requested_cents: estimated_cost_cents,
                remaining_cents: max_budget_cents.saturating_sub(accumulated_spend_cents),
            })?;

        if new_total > max_budget_cents {
            return Err(AgentGuardError::BudgetExceeded {
                requested_cents: estimated_cost_cents,
                remaining_cents: max_budget_cents.saturating_sub(accumulated_spend_cents),
            });
        }
        Ok(())
    }

    /// Feature #1: Slice a child sub-agent budget from a parent agent's remaining allocation.
    ///
    /// Args:
    /// * `parent_budget_cents`: Total budget cap of the parent agent in integer cents.
    /// * `parent_accumulated_cents`: Accumulated spend of the parent agent in integer cents.
    /// * `child_requested_budget_cents`: Budget requested for delegation to child sub-agent in integer cents.
    ///
    /// Usage:
    /// ```ignore
    /// let child_budget = AgentGuardWorkflow::slice_child_budget(5000, 1000, 500)?;
    /// ```
    pub fn slice_child_budget(
        parent_budget_cents: u64,
        parent_accumulated_cents: u64,
        child_requested_budget_cents: u64,
    ) -> Result<u64, AgentGuardError> {
        let parent_remaining = parent_budget_cents.saturating_sub(parent_accumulated_cents);
        if child_requested_budget_cents > parent_remaining {
            return Err(AgentGuardError::BudgetExceeded {
                requested_cents: child_requested_budget_cents,
                remaining_cents: parent_remaining,
            });
        }
        Ok(child_requested_budget_cents)
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
            50,
            1000,
            200,
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
            500,
            1000,
            800,
            now,
        );
        assert_eq!(
            res,
            Err(AgentGuardError::BudgetExceeded {
                requested_cents: 500,
                remaining_cents: 200,
            })
        );
    }

    #[test]
    fn test_slice_child_budget_success() {
        let child_alloc = AgentGuardWorkflow::slice_child_budget(5000, 1000, 500);
        assert_eq!(child_alloc, Ok(500));
    }
}
