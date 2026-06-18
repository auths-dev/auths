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
//!
//! ## x402 / USDC (the second rail — cross-rail summing, PRD §11)
//!
//! The x402 rail settles a metered tool call in USDC and returns an x402
//! `SettlementResponse` alongside the `PaymentRequirements` it was settled against
//! (coinbase/x402 spec v1). The settled amount is `requirements.maxAmountRequired` —
//! but in **atomic** USDC units (USDC has 6 decimals), so `1500000` atomic = 1.50 USDC
//! = 150 cents. Extraction converts atomic-USDC → cents (`atomic * 100 / 1e6`,
//! exact-division-only — a sub-cent residue is refused, not silently truncated). The
//! reference is the on-chain settlement tx (`settlement.transaction`, `0x…`) a stranger
//! re-derives the cost by. The **network must be a testnet** (`base-sepolia`): a mainnet
//! network is refused rather than mis-metered, mirroring Stripe's USD-only / live-key
//! guard — and honestly flagging that the LIVE on-chain settle needs a funded testnet
//! wallet + facilitator (out of hermetic scope), not a key alone. The extracted cost
//! settles into the **same** [`crate::budget::CrossRailBudget`] as Stripe — one cap
//! across both rails (the moat a per-rail silo cannot express).

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

/// USDC has 6 decimals: `maxAmountRequired` is in ATOMIC units, so `1_000_000` atomic =
/// 1 USDC. Cents are USDC's two-decimal minor unit, so 1 USDC = 100 cents and the
/// atomic-per-cent divisor is `1e6 / 100 = 10_000`.
pub const USDC_ATOMIC_PER_CENT: u64 = 10_000;

/// Convert an atomic-USDC amount to cents, rounding UP — the reserve ceiling the gateway holds
/// before a metered call, so the hold always covers the amount the settle reports (the SETTLE reads
/// the exact cents the rail response carries). Lives beside the rail's decimal count so the
/// ceiling and the exact-division settle rule stay in the one module that owns the rail's decimals.
pub fn atomic_usdc_to_cents_ceiling(atomic: u64) -> u64 {
    atomic.div_ceil(USDC_ATOMIC_PER_CENT)
}

/// The set of x402 networks this rail meters — **testnets only**. A mainnet network is
/// refused, not mis-metered (the moat's honesty: the LIVE x402 settle needs a funded
/// testnet wallet + facilitator, out of hermetic scope — never real-money mainnet here).
const X402_TESTNETS: &[&str] = &["base-sepolia"];

/// A recorded (or live) **x402 settlement** response, parsed to the documented fields
/// the cost extraction reads (coinbase/x402 spec v1: `SettlementResponse` +
/// `PaymentRequirements`). Only the metering-relevant fields are modeled; serde drops
/// the rest, keeping this tight to the documented shape.
#[derive(Debug, Clone, Deserialize)]
struct X402SettlementResponse {
    /// The `PaymentRequirements` this call was settled against — carries the amount.
    requirements: X402Requirements,
    /// The on-chain `SettlementResponse` — carries the tx the receipt names.
    settlement: X402Settlement,
}

/// The x402 `PaymentRequirements` fields the cost extraction reads. `maxAmountRequired`
/// is the settled amount in ATOMIC USDC (6 decimals) — a string in the spec, parsed
/// here. `network` pins the chain (testnet-only is enforced).
#[derive(Debug, Clone, Deserialize)]
struct X402Requirements {
    /// The settled amount in ATOMIC USDC units (6 decimals), as a decimal string per the
    /// x402 spec. Converted atomic-USDC → cents by the extractor.
    #[serde(rename = "maxAmountRequired")]
    max_amount_required: String,
    /// The x402 network (e.g. `base-sepolia`). A mainnet network is refused.
    network: String,
}

/// The x402 `SettlementResponse` fields the cost extraction reads. `transaction` (`0x…`)
/// is the on-chain settlement tx the receipt names so the metered cost is re-derivable.
#[derive(Debug, Clone, Deserialize)]
struct X402Settlement {
    /// Whether the on-chain settle succeeded.
    success: bool,
    /// The settlement tx hash (`0x…`) — the receipt-grade reference.
    transaction: String,
}

/// Extract the settled cost from a recorded/live **x402/USDC settlement** response.
///
/// Reads `requirements.maxAmountRequired` (ATOMIC USDC, 6 decimals) and converts it to
/// cents (`atomic * 100 / 1e6`, i.e. `atomic / 10_000`) as the authoritative cost, and
/// `settlement.transaction` (`0x…`) as the receipt reference. The amount comes from the
/// RESPONSE — an agent that under-declared the cost cannot change what is metered. The
/// network must be a **testnet** (`base-sepolia`): a mainnet network is refused rather
/// than mis-metered (mirrors Stripe's USD-only / live-key guard). A sub-cent atomic
/// residue (an amount not an exact number of cents) is refused, not silently truncated —
/// the metered cost must equal the settled amount exactly.
pub fn extract_x402(response_bytes: &[u8]) -> Result<ExtractedCost, RailError> {
    let parsed: X402SettlementResponse = serde_json::from_slice(response_bytes)
        .map_err(|e| RailError::Parse(format!("x402 settlement: {e}")))?;

    // Testnet-only: a mainnet network is refused (the live leg needs a funded testnet
    // wallet + facilitator, never real-money mainnet here).
    let network = parsed.requirements.network.to_ascii_lowercase();
    if !X402_TESTNETS.contains(&network.as_str()) {
        return Err(RailError::MissingField(format!(
            "x402 network `{network}` is not a supported testnet ({}) — refusing rather than \
             mis-metering a mainnet (real-money) settle (the LIVE x402 leg needs a funded \
             testnet wallet + facilitator, out of hermetic scope)",
            X402_TESTNETS.join(", ")
        )));
    }

    // The settle must have succeeded to be metered — a failed settle costs nothing.
    if !parsed.settlement.success {
        return Err(RailError::MissingField(
            "x402 settlement.success is false — a failed settle has no metered cost".to_string(),
        ));
    }

    let tx = parsed.settlement.transaction;
    if !tx.starts_with("0x") || tx.len() <= 2 {
        return Err(RailError::MissingField(format!(
            "x402 settlement.transaction `{tx}` is not a 0x… tx hash"
        )));
    }

    // maxAmountRequired is ATOMIC USDC (6 decimals) as a decimal string.
    let atomic: u64 = parsed
        .requirements
        .max_amount_required
        .parse()
        .map_err(|e| {
            RailError::MissingField(format!(
                "x402 maxAmountRequired `{}` is not a non-negative atomic-USDC integer: {e}",
                parsed.requirements.max_amount_required
            ))
        })?;

    // atomic-USDC → cents, exact-division only: a sub-cent residue is refused so the
    // metered cost equals the settled amount exactly (never silently truncated).
    if !atomic.is_multiple_of(USDC_ATOMIC_PER_CENT) {
        return Err(RailError::MissingField(format!(
            "x402 maxAmountRequired {atomic} atomic USDC is a sub-cent amount \
             (not a whole number of cents) — refusing rather than truncating"
        )));
    }
    let amount_cents = atomic / USDC_ATOMIC_PER_CENT;

    Ok(ExtractedCost {
        amount_cents,
        rail: "x402".to_string(),
        reference: tx,
    })
}

/// Extract the settled cost from a rail's response, dispatching on the rail name. This
/// is the near-pluggable seam: a new rail adds an extractor here (and only here —
/// nothing else in the core learns about a rail's response shape).
pub fn extract(rail: &str, response_bytes: &[u8]) -> Result<ExtractedCost, RailError> {
    match rail {
        "stripe" => extract_stripe(response_bytes),
        "x402" => extract_x402(response_bytes),
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
        // x402 is now a registered rail (PAY-2): a stripe-shaped body handed to it fails
        // on the missing x402 fields (Parse), NOT UnknownRail.
        assert!(matches!(
            extract("x402", STRIPE_CHARGE_3USD.as_bytes()),
            Err(RailError::Parse(_))
        ));
        let x402 = extract("x402", X402_SETTLE_150C.as_bytes()).unwrap();
        assert_eq!(x402.amount_cents, 150);
        assert_eq!(x402.rail, "x402");
        // An unknown rail still has no extractor.
        assert!(matches!(
            extract("paypal", STRIPE_CHARGE_3USD.as_bytes()),
            Err(RailError::UnknownRail(_))
        ));
    }

    // ── x402 / USDC rail extraction (the second rail, cross-rail summing) ──────────

    /// A doc-accurate x402 settlement response (the shape the recorded fixture and a
    /// live base-sepolia settle both return), maxAmountRequired=1500000 atomic USDC
    /// (6 decimals) = 1.50 USDC = 150 cents.
    const X402_SETTLE_150C: &str = r#"{
        "rail": "x402",
        "requirements": {
            "scheme": "exact",
            "network": "base-sepolia",
            "maxAmountRequired": "1500000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "extra": { "name": "USDC", "version": "2" }
        },
        "settlement": {
            "success": true,
            "transaction": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "network": "base-sepolia",
            "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66"
        }
    }"#;

    #[test]
    fn extracts_atomic_usdc_as_cents_and_the_settlement_tx() {
        // 1500000 atomic USDC (6 decimals) → 1.50 USDC → 150 cents; reference is the tx.
        let cost = extract_x402(X402_SETTLE_150C.as_bytes()).unwrap();
        assert_eq!(
            cost.amount_cents, 150,
            "atomic-USDC → cents: 1500000 / 10000 = 150"
        );
        assert_eq!(cost.rail, "x402");
        assert!(
            cost.reference.starts_with("0x1234567890abcdef"),
            "the receipt names the 0x… settlement tx, got {}",
            cost.reference
        );
    }

    #[test]
    fn the_x402_cost_is_the_response_amount_not_an_agent_number() {
        // The over-cap (cross-rail cap-crosser) fixture: 600000 atomic = $0.60 — read
        // from the RESPONSE, so an agent that under-declared cannot change it.
        let small = X402_SETTLE_150C.replace("\"1500000\"", "\"600000\"");
        let cost = extract_x402(small.as_bytes()).unwrap();
        assert_eq!(cost.amount_cents, 60, "600000 / 10000 = 60 cents");
    }

    #[test]
    fn mainnet_network_is_refused_not_mis_metered() {
        // A mainnet network (real-money USDC) is refused — the live x402 leg needs a
        // funded TESTNET wallet + facilitator, never real-money mainnet here.
        let mainnet = X402_SETTLE_150C.replace("\"base-sepolia\"", "\"base\"");
        assert!(extract_x402(mainnet.as_bytes()).is_err());
        let eth = X402_SETTLE_150C.replace("\"base-sepolia\"", "\"ethereum\"");
        assert!(extract_x402(eth.as_bytes()).is_err());
    }

    #[test]
    fn sub_cent_atomic_amount_is_refused_not_truncated() {
        // 1500050 atomic = 1.50005 USDC = 150.005 cents — a sub-cent residue. Refused
        // rather than silently truncated, so the metered cost equals the settle exactly.
        let residue = X402_SETTLE_150C.replace("\"1500000\"", "\"1500050\"");
        assert!(extract_x402(residue.as_bytes()).is_err());
    }

    #[test]
    fn failed_or_malformed_settlement_is_refused() {
        // A failed on-chain settle has no metered cost.
        let failed = X402_SETTLE_150C.replace("\"success\": true", "\"success\": false");
        assert!(extract_x402(failed.as_bytes()).is_err());
        // A non-0x tx hash is refused.
        let bad_tx = X402_SETTLE_150C.replace(
            "\"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\"",
            "\"not-a-tx\"",
        );
        assert!(extract_x402(bad_tx.as_bytes()).is_err());
        // Missing the requirements/settlement objects entirely.
        assert!(extract_x402(b"{\"rail\":\"x402\"}").is_err());
        assert!(extract_x402(b"not json").is_err());
    }
}
