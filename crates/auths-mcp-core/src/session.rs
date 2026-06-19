//! Budget parsing for an agent's session.
//!
//! This module once held the authoritative cumulative-spend counter as a
//! gateway-held, in-RAM per-session tally (`SessionLedger`, budget v0). **D8
//! supersedes that tally**: the authoritative cross-rail counter is now the
//! verifier-held monotonic SETTLED high-water keyed to the agent delegation, plus a
//! transient set of RESERVED holds — see [`crate::budget`] ([`crate::budget::
//! CrossRailBudget`]). The gateway no longer meters the paid path against an
//! undifferentiated RAM tally; it pre-authorizes against the durable cross-rail
//! engine. What remains here is the budget *parser* (`$5.00` → `Cents(500)`), which
//! the gateway uses to read the cap off the grant before opening the cross-rail
//! budget at that cap.

use crate::money::Cents;

/// A quantitative budget on an agent's session (maps AGT-4). Either a spend cap in
/// cents or a call-count cap — the boolean-scope incumbents cannot express either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Budget {
    /// A monetary cap, in cents (e.g. `$5.00` → `Cents(500)`).
    Cents(Cents),
    /// A maximum number of brokered calls.
    Calls(u64),
}

/// A budget string that is neither a dollar amount nor a call count. Parsing a budget returns this
/// rather than defaulting, so a malformed budget can never silently become an unbounded cap on the
/// real-money path — the caller decides (the payment path refuses fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("budget {0:?} is neither a dollar amount (e.g. $5.00) nor a call count (e.g. 20calls)")]
pub struct BudgetParseError(String);

impl Budget {
    /// Parse a budget from the grant string (e.g. `"$5.00"`, `"$5"`, `"20calls"`), or
    /// [`BudgetParseError`] when it is neither. A PRESENT-but-malformed budget is an error, never a
    /// silent cap — so a typo on a payment wrap cannot disable the spend cap.
    ///
    /// Args:
    /// * `raw`: the budget string from the grant/CLI.
    ///
    /// Usage:
    /// ```ignore
    /// let cap = Budget::parse("$5.00")?.cap_cents();
    /// ```
    pub fn parse(raw: &str) -> Result<Self, BudgetParseError> {
        let trimmed = raw.trim();
        if let Some(rest) = trimmed.strip_suffix("calls")
            && let Ok(n) = rest.trim().parse::<u64>()
        {
            return Ok(Budget::Calls(n));
        }
        let dollars = trimmed.trim_start_matches('$');
        if let Ok(cents) = parse_dollars_to_cents(dollars) {
            // Wrap the parsed cent count at this string-parse boundary.
            return Ok(Budget::Cents(Cents::new(cents)));
        }
        Err(BudgetParseError(raw.to_string()))
    }

    /// An explicit unbounded cap — the non-payment path's deliberate choice when no budget is set.
    /// Named so an "infinite cap" is always a decision a caller makes on purpose, never the silent
    /// fallback of a parse failure.
    pub fn unbounded() -> Self {
        Budget::Cents(Cents::new(u64::MAX))
    }

    /// The cap expressed in cents — the value the cross-rail budget is opened at. A
    /// call cap reports its count directly (the cross-rail engine is for the metered,
    /// cents-denominated path; the call-cap path is non-metered and reserves nothing).
    pub fn cap_cents(&self) -> Cents {
        match self {
            Budget::Cents(c) => *c,
            Budget::Calls(c) => Cents::new(*c),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dollar_budgets() {
        assert_eq!(Budget::parse("$5.00"), Ok(Budget::Cents(Cents::new(500))));
        assert_eq!(Budget::parse("$5"), Ok(Budget::Cents(Cents::new(500))));
        assert_eq!(Budget::parse("$4.99"), Ok(Budget::Cents(Cents::new(499))));
        assert_eq!(Budget::parse("20calls"), Ok(Budget::Calls(20)));
    }

    #[test]
    fn cap_cents_reads_the_bound() {
        assert_eq!(Budget::parse("$5.00").unwrap().cap_cents(), Cents::new(500));
        assert_eq!(
            Budget::parse("20calls").unwrap().cap_cents(),
            Cents::new(20)
        );
    }

    #[test]
    fn a_malformed_budget_is_refused_not_an_infinite_cap() {
        // A budget that parses to neither dollars nor calls is an error, not a silent u64::MAX cap,
        // which on a payment wrap would be unbounded spend.
        assert!(Budget::parse("garbage").is_err());
        assert!(Budget::parse("$").is_err());
        assert!(Budget::parse("12cows").is_err());
        // The unbounded cap is a deliberate, named choice — not a parse fallback.
        assert_eq!(Budget::unbounded(), Budget::Cents(Cents::new(u64::MAX)));
    }
}
