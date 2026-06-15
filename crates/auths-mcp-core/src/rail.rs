//! Rail-response cost EXTRACTION — the authoritative settle amount comes from the
//! rail's own response, never from an agent-declared number.
//!
//! ## Why this exists (the hinge)
//!
//! The cross-rail counter (D8, [`crate::budget`]) meters a "this call costs X cents"
//! signal. The question this module answers is *where X comes from*. The live wrap
//! path's interim wiring read X from an agent-supplied request field — untrusted: a
//! malicious agent could declare `0` and bypass metering entirely. This module
//! replaces that with **extraction of the SETTLED amount from the rail's RESPONSE**:
//! the cost the gateway reserves and settles is read out of the bytes the rail itself
//! returned, so the settle is authoritative regardless of what the agent declared.
//!
//! ## Bound, don't build (PRD §11)
//!
//! `auths-mcp-core` holds **zero** payment code beyond reading a rail's documented
//! response shape. Each rail is a wrapped downstream MCP server; this module is the
//! only place that knows a rail's response schema. It does **not** call any rail, hold
//! any key, or settle anything on-chain — it parses a response the rail (or, in the
//! hermetic probe, a recorded fixture) already produced and reports the cost + the
//! receipt-grade reference (the charge id) a stranger can use to re-derive the metered
//! cost from that same response.
//!
//! ## Stripe (the Stripe-test rail, PRD §11)
//!
//! The Stripe rail returns a Charge object
//! ([docs.stripe.com/api/charges/object](https://docs.stripe.com/api/charges/object)).
//! The settled amount is `charge.amount_captured` (already in cents — Stripe's minor
//! unit for USD), and the reference is `charge.id` (`ch_…`). Extraction is tight to
//! the documented shape so adding a real `sk_test_…` key (the live evidence leg) makes
//! the same code path read a real test-mode charge with minimal reconciliation.

use serde::Deserialize;

/// The cost EXTRACTED from a rail's response: the settled amount in cents, the rail it
/// settled on, and the rail-native reference (a charge id / settlement tx) a stranger
/// re-derives the cost from. This is what the gate RESERVES and SETTLES — sourced from
/// the response, not from any agent-declared number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedCost {
    /// The settled amount in cents, read from the rail's response.
    pub amount_cents: u64,
    /// The rail this response settled on (e.g. `stripe`).
    pub rail: String,
    /// The rail-native reference the receipt names so the metered cost is re-derivable
    /// from the recorded response (e.g. a Stripe charge id `ch_…`).
    pub reference: String,
}

/// Errors extracting a cost from a rail response (could-not-measure — the response did
/// not carry the documented fields, so there is no authoritative cost to meter).
#[derive(Debug, thiserror::Error)]
pub enum RailError {
    #[error("rail response was not valid JSON: {0}")]
    Parse(String),
    #[error("rail response did not carry the documented cost field: {0}")]
    MissingField(String),
    #[error("unknown rail `{0}` — no documented response extractor")]
    UnknownRail(String),
}

/// A recorded (or live) Stripe **Charge** response, parsed to the documented fields the
/// cost extraction reads. Only the fields the metering needs are modeled; the rest of
/// the Charge object is ignored (serde drops unknown fields), so this stays tight to
/// the documented shape without re-modeling all of Stripe.
#[derive(Debug, Clone, Deserialize)]
struct StripeChargeResponse {
    /// The wrapped Charge object.
    charge: StripeCharge,
}

/// The documented fields of a Stripe Charge object the cost extraction reads
/// (docs.stripe.com/api/charges/object). `amount_captured` is the SETTLED amount in the
/// currency's minor unit (cents for USD) — the authoritative cost. `id` (`ch_…`) is the
/// receipt-grade reference.
#[derive(Debug, Clone, Deserialize)]
struct StripeCharge {
    /// The charge id (`ch_…`) — the reference the receipt names.
    id: String,
    /// The amount CAPTURED (settled), in the currency's minor unit (cents for USD). The
    /// authoritative metered cost — read from the response, never agent-declared.
    amount_captured: u64,
    /// The currency (e.g. `usd`). Carried so a non-USD charge is not silently metered as
    /// if its minor unit were cents.
    currency: String,
}

/// Extract the settled cost from a recorded/live **Stripe Charge** response.
///
/// Reads `charge.amount_captured` (cents) as the authoritative cost and `charge.id`
/// (`ch_…`) as the receipt reference. The amount comes from the RESPONSE — an agent that
/// under-declared the cost on its request cannot change what is metered. USD only (the
/// minor unit is cents); a non-USD charge is refused rather than mis-metered.
pub fn extract_stripe(response_bytes: &[u8]) -> Result<ExtractedCost, RailError> {
    let parsed: StripeChargeResponse = serde_json::from_slice(response_bytes)
        .map_err(|e| RailError::Parse(format!("stripe charge: {e}")))?;
    let charge = parsed.charge;
    if !charge.currency.eq_ignore_ascii_case("usd") {
        return Err(RailError::MissingField(format!(
            "stripe charge currency `{}` is not usd — the cents minor unit does not apply",
            charge.currency
        )));
    }
    if charge.id.is_empty() {
        return Err(RailError::MissingField(
            "stripe charge.id is empty".to_string(),
        ));
    }
    Ok(ExtractedCost {
        amount_cents: charge.amount_captured,
        rail: "stripe".to_string(),
        reference: charge.id,
    })
}

/// Extract the settled cost from a rail's response, dispatching on the rail name. This
/// is the near-pluggable seam: a new rail adds an extractor here (and only here —
/// nothing else in the core learns about a rail's response shape).
pub fn extract(rail: &str, response_bytes: &[u8]) -> Result<ExtractedCost, RailError> {
    match rail {
        "stripe" => extract_stripe(response_bytes),
        other => Err(RailError::UnknownRail(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A doc-accurate Stripe TEST-MODE Charge response (the shape the recorded fixture
    /// and a live `sk_test_…` charge both return), $3.00 captured.
    const STRIPE_CHARGE_3USD: &str = r#"{
        "rail": "stripe",
        "charge": {
            "id": "ch_3MmlLrLkdIwHu7ix0snN0B15",
            "object": "charge",
            "amount": 300,
            "amount_captured": 300,
            "amount_refunded": 0,
            "currency": "usd",
            "captured": true,
            "paid": true,
            "status": "succeeded",
            "livemode": false
        }
    }"#;

    #[test]
    fn extracts_amount_captured_and_charge_id_from_the_response() {
        let cost = extract_stripe(STRIPE_CHARGE_3USD.as_bytes()).unwrap();
        assert_eq!(
            cost.amount_cents, 300,
            "the cost is read from amount_captured"
        );
        assert_eq!(cost.rail, "stripe");
        assert_eq!(cost.reference, "ch_3MmlLrLkdIwHu7ix0snN0B15");
    }

    #[test]
    fn the_cost_is_the_response_amount_not_an_agent_number() {
        // The whole point: the extracted cost is whatever the RESPONSE captured, so an
        // agent that declared a different (lower) number cannot change what is metered.
        // amount_captured=600 → $6.00 regardless of any agent-declared value.
        let over =
            STRIPE_CHARGE_3USD.replace("\"amount_captured\": 300", "\"amount_captured\": 600");
        let cost = extract_stripe(over.as_bytes()).unwrap();
        assert_eq!(cost.amount_cents, 600);
    }

    #[test]
    fn non_usd_charge_is_refused_not_mis_metered() {
        let eur = STRIPE_CHARGE_3USD.replace("\"currency\": \"usd\"", "\"currency\": \"eur\"");
        assert!(extract_stripe(eur.as_bytes()).is_err());
    }

    #[test]
    fn missing_charge_object_is_an_error() {
        assert!(extract_stripe(b"{\"rail\":\"stripe\"}").is_err());
        assert!(extract_stripe(b"not json").is_err());
    }

    #[test]
    fn dispatch_by_rail_name() {
        let cost = extract("stripe", STRIPE_CHARGE_3USD.as_bytes()).unwrap();
        assert_eq!(cost.amount_cents, 300);
        assert!(matches!(
            extract("x402", STRIPE_CHARGE_3USD.as_bytes()),
            Err(RailError::UnknownRail(_))
        ));
    }
}
