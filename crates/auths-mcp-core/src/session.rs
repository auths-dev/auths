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
            // Wrap the parsed cent count at this string-parse boundary.
            return Budget::Cents(Cents::new(cents));
        }
        // Permissive default: a budget we cannot read does not block a non-payment wrap.
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
        assert_eq!(Budget::parse("$5.00"), Budget::Cents(Cents::new(500)));
        assert_eq!(Budget::parse("$5"), Budget::Cents(Cents::new(500)));
        assert_eq!(Budget::parse("$4.99"), Budget::Cents(Cents::new(499)));
        assert_eq!(Budget::parse("20calls"), Budget::Calls(20));
    }

    #[test]
    fn cap_cents_reads_the_bound() {
        assert_eq!(Budget::parse("$5.00").cap_cents(), Cents::new(500));
        assert_eq!(Budget::parse("20calls").cap_cents(), Cents::new(20));
    }
}
