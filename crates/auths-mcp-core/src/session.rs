//! Session budget accounting — where the authoritative cumulative-spend counter
//! lives (gateway-held ledger v0, per PRD §5 Build item 4 / Open Q2). The gate
//! reads `spent` and supplies it to the verify so the call that would cross the
//! cap is refused `UsageCapExceeded` before the metered tool is invoked.
//!
//! The counter is wired and advanced on every allowed call so the receipt carries
//! an honest running total; the quantitative-cap refusal (`UsageCapExceeded`) is a
//! thin predicate over this ledger.

/// A quantitative budget on an agent's session (maps AGT-4). Either a spend cap in
/// cents or a call-count cap — the boolean-scope incumbents cannot express either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Budget {
    /// A monetary cap, in cents (e.g. `$5.00` → `Cents(500)`).
    Cents(u64),
    /// A maximum number of brokered calls.
    Calls(u64),
}

impl Budget {
    /// Parse a budget from the grant string in a transcript (e.g. `"$5.00"`,
    /// `"$5"`, `"20calls"`). Defaults to a generous cap when unparseable so a
    /// malformed budget never silently blocks an in-scope call.
    pub fn parse(raw: &str) -> Self {
        let raw = raw.trim();
        if let Some(rest) = raw.strip_suffix("calls")
            && let Ok(n) = rest.trim().parse::<u64>()
        {
            return Budget::Calls(n);
        }
        let dollars = raw.trim_start_matches('$');
        if let Ok(cents) = parse_dollars_to_cents(dollars) {
            return Budget::Cents(cents);
        }
        // Permissive default: a budget we cannot read does not block MCP-1.
        Budget::Cents(u64::MAX)
    }
}

/// Parse a dollar string like `5`, `5.00`, `4.99` into integer cents.
fn parse_dollars_to_cents(s: &str) -> Result<u64, ()> {
    let s = s.trim();
    match s.split_once('.') {
        None => s.parse::<u64>().map(|d| d * 100).map_err(|_| ()),
        Some((d, c)) => {
            let dollars: u64 = if d.is_empty() {
                0
            } else {
                d.parse().map_err(|_| ())?
            };
            // Pad/truncate the cents field to exactly two digits.
            let mut cents_str = c.to_string();
            cents_str.truncate(2);
            while cents_str.len() < 2 {
                cents_str.push('0');
            }
            let cents: u64 = cents_str.parse().map_err(|_| ())?;
            Ok(dollars * 100 + cents)
        }
    }
}

/// The gateway-held running ledger for one agent session. The authoritative
/// counter the gate consults on every call; anchored TEL increments are the
/// hardened follow-up (Open Q2).
#[derive(Debug, Clone)]
pub struct SessionLedger {
    pub budget: Budget,
    /// Cumulative cents spent so far this session.
    pub spent_cents: u64,
    /// Cumulative brokered-call count so far this session.
    pub call_count: u64,
}

impl SessionLedger {
    /// Open a fresh ledger for a session under the given budget.
    pub fn open(budget: Budget) -> Self {
        Self {
            budget,
            spent_cents: 0,
            call_count: 0,
        }
    }

    /// Would charging `cost_cents` keep this session inside its budget?
    ///
    /// The quantitative-cap predicate the verify reads: `spent + cost ≤ cap` for a
    /// monetary cap, or `count + 1 ≤ cap` for a call cap.
    pub fn would_stay_within(&self, cost_cents: u64) -> bool {
        match self.budget {
            Budget::Cents(cap) => self.spent_cents.saturating_add(cost_cents) <= cap,
            Budget::Calls(cap) => self.call_count.saturating_add(1) <= cap,
        }
    }

    /// The budget cap expressed in cents, for the `UsageCapExceeded` verdict
    /// (a call cap reports its count cap directly).
    pub fn cap_cents(&self) -> u64 {
        match self.budget {
            Budget::Cents(cap) => cap,
            Budget::Calls(cap) => cap,
        }
    }

    /// Commit an allowed call's cost to the running total.
    pub fn charge(&mut self, cost_cents: u64) {
        self.spent_cents = self.spent_cents.saturating_add(cost_cents);
        self.call_count = self.call_count.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dollar_budgets() {
        assert_eq!(Budget::parse("$5.00"), Budget::Cents(500));
        assert_eq!(Budget::parse("$5"), Budget::Cents(500));
        assert_eq!(Budget::parse("$4.99"), Budget::Cents(499));
        assert_eq!(Budget::parse("20calls"), Budget::Calls(20));
    }

    #[test]
    fn ledger_charges_and_bounds() {
        let mut l = SessionLedger::open(Budget::Cents(500));
        assert!(l.would_stay_within(300));
        l.charge(300);
        assert_eq!(l.spent_cents, 300);
        assert!(l.would_stay_within(200));
        assert!(!l.would_stay_within(300));
    }
}
