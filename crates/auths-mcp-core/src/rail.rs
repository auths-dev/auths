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
//! ## Bound, don't build
//!
//! `auths-mcp-core` holds **zero** payment code beyond reading a rail's documented
//! response shape. Each rail is a wrapped downstream MCP server; this module is the
//! only place that knows a rail's response schema. It does **not** call any rail, hold
//! any key, or settle anything on-chain — it parses a response the rail (or, in the
//! hermetic probe, a recorded fixture) already produced and reports the cost + the
//! receipt-grade reference (the charge id) a stranger can use to re-derive the metered
//! cost from that same response.
//!
//! ## Stripe (the Stripe-test rail)
//!
//! The Stripe rail returns a Charge object
//! ([docs.stripe.com/api/charges/object](https://docs.stripe.com/api/charges/object)).
//! The settled amount is `charge.amount_captured` (already in cents — Stripe's minor
//! unit for USD), and the reference is `charge.id` (`ch_…`). Extraction is tight to
//! the documented shape so adding a real `sk_test_…` key (the live evidence leg) makes
//! the same code path read a real test-mode charge with minimal reconciliation.
//!
//! ## x402 / USDC (the second rail — cross-rail summing)
//!
//! The x402 rail settles a metered tool call in USDC and returns an x402
//! `SettlementResponse` alongside the `PaymentRequirements` it was settled against
//! (coinbase/x402 spec v1). The settled amount is `requirements.maxAmountRequired` —
//! but in **atomic** USDC units (USDC has 6 decimals), so `1500000` atomic = 1.50 USDC
//! = 150 cents. Extraction converts atomic-USDC → cents (`atomic * 100 / 1e6`,
//! exact-division-only — a sub-cent residue is refused, not silently truncated). The
//! reference is the on-chain settlement tx (`settlement.transaction`, `0x…`) a stranger
//! re-derives the cost by. The **network gate follows the payment mode**
//! ([`crate::paymode`]): a testnet (`base-sepolia`) is metered in any mode, but a mainnet
//! (`base`, REAL money) is metered ONLY when the gateway resolved to real mode — under
//! `--test-mode` a mainnet settle is refused rather than mis-metered, so the sandbox switch
//! can never move real money (mirrors Stripe's USD-only / live-key guard). The extracted cost
//! settles into the **same** [`crate::budget::CrossRailBudget`] as Stripe — one cap
//! across both rails (the moat a per-rail silo cannot express).

use crate::money::{AtomicUsdc, Cents};
use crate::paymode::PaymentMode;
use serde::Deserialize;

/// The cost EXTRACTED from a rail's response: the settled amount in cents, the rail it
/// settled on, and the rail-native reference (a charge id / settlement tx) a stranger
/// re-derives the cost from. This is what the gate RESERVES and SETTLES — sourced from
/// the response, not from any agent-declared number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedCost {
    /// The settled amount in cents, read from the rail's response.
    pub amount_cents: Cents,
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
        amount_cents: Cents::new(charge.amount_captured),
        rail: "stripe".to_string(),
        reference: charge.id,
    })
}

/// The x402 TESTNET networks this rail meters — valueless USDC, metered in any mode.
const X402_TESTNETS: &[&str] = &["base-sepolia"];

/// The x402 MAINNET networks this rail meters — REAL money. Metered ONLY when the gateway
/// resolved to [`PaymentMode::Real`] (no `--test-mode`); under the sandbox opt-in a mainnet
/// settle is refused rather than mis-metered, so the test switch can never move real money.
const X402_MAINNETS: &[&str] = &["base"];

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

/// Strongly-typed USDC settlement network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsdcNetwork {
    /// Real-money mainnet chains
    Mainnet(MainnetChain),
    /// Sandbox testnet chains
    Testnet(TestnetChain),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainnetChain {
    Base,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestnetChain {
    BaseSepolia,
}

impl std::str::FromStr for UsdcNetwork {
    type Err = RailError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "base" => Ok(UsdcNetwork::Mainnet(MainnetChain::Base)),
            "base-sepolia" => Ok(UsdcNetwork::Testnet(TestnetChain::BaseSepolia)),
            other => Err(RailError::MissingField(format!(
                "x402 network `{other}` is not a known USDC network (testnets: {}; mainnets: {})",
                X402_TESTNETS.join(", "),
                X402_MAINNETS.join(", ")
            ))),
        }
    }
}

impl UsdcNetwork {
    /// Parses a raw network string and validates mode compatibility at the parsing boundary.
    pub fn parse_for_mode(raw_network: &str, mode: PaymentMode) -> Result<Self, RailError> {
        let network: UsdcNetwork = raw_network.parse()?;
        match (network, mode) {
            (UsdcNetwork::Mainnet(chain), PaymentMode::Real) => Ok(UsdcNetwork::Mainnet(chain)),
            (UsdcNetwork::Testnet(chain), PaymentMode::Test) => Ok(UsdcNetwork::Testnet(chain)),
            (UsdcNetwork::Testnet(_), PaymentMode::Real) => Err(RailError::MissingField(format!(
                "x402 network `{raw_network}` is a testnet but gateway is running in REAL mode — refusing testnet settlement in production"
            ))),
            (UsdcNetwork::Mainnet(_), PaymentMode::Test) => Err(RailError::MissingField(format!(
                "x402 network `{raw_network}` is a MAINNET (REAL money) but the gateway is in test mode — refusing to mis-meter a real-money settle under --test-mode (omit --test-mode for live)"
            ))),
        }
    }
}

/// Extract the settled cost from a recorded/live **x402/USDC settlement** response.
///
/// Reads `requirements.maxAmountRequired` (ATOMIC USDC, 6 decimals) and converts it to
/// cents (`atomic * 100 / 1e6`, i.e. `atomic / 10_000`) as the authoritative cost, and
/// `settlement.transaction` (`0x…`) as the receipt reference. The amount comes from the
/// RESPONSE — an agent that under-declared the cost cannot change what is metered. The
/// network gate follows `mode`: a **testnet** (`base-sepolia`) meters in any mode, but a
/// **mainnet** (`base`, REAL money) meters ONLY under [`PaymentMode::Real`] — a mainnet
/// settle under `--test-mode` is refused rather than mis-metered (mirrors Stripe's live-key
/// guard). A sub-cent atomic residue (an amount not an exact number of cents) is refused,
/// not silently truncated — the metered cost must equal the settled amount exactly.
pub fn extract_x402(response_bytes: &[u8], mode: PaymentMode) -> Result<ExtractedCost, RailError> {
    let parsed: X402SettlementResponse = serde_json::from_slice(response_bytes)
        .map_err(|e| RailError::Parse(format!("x402 settlement: {e}")))?;

    // Parse, don't validate: Parse raw network string directly into mode-checked UsdcNetwork type
    let _network = UsdcNetwork::parse_for_mode(&parsed.requirements.network, mode)?;

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
    let atomic = AtomicUsdc::new(
        parsed
            .requirements
            .max_amount_required
            .parse()
            .map_err(|e| {
                RailError::MissingField(format!(
                    "x402 maxAmountRequired `{}` is not a non-negative atomic-USDC integer: {e}",
                    parsed.requirements.max_amount_required
                ))
            })?,
    );

    // atomic-USDC → cents, exact only: a sub-cent residue is refused so the metered cost equals the
    // settled amount exactly (never silently truncated).
    let amount_cents = atomic.to_cents_exact().ok_or_else(|| {
        RailError::MissingField(format!(
            "x402 maxAmountRequired {} atomic USDC is a sub-cent amount \
             (not a whole number of cents) — refusing rather than truncating",
            atomic.get()
        ))
    })?;

    Ok(ExtractedCost {
        amount_cents,
        rail: "x402".to_string(),
        reference: tx,
    })
}

/// Extract the settled cost from a rail's response, dispatching on the rail name. This
/// is the near-pluggable seam: a new rail adds an extractor here (and only here —
/// nothing else in the core learns about a rail's response shape).
pub fn extract(
    rail: &str,
    response_bytes: &[u8],
    mode: PaymentMode,
) -> Result<ExtractedCost, RailError> {
    match rail {
        "stripe" => extract_stripe(response_bytes),
        "x402" => extract_x402(response_bytes, mode),
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
            cost.amount_cents,
            Cents::new(300),
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
        assert_eq!(cost.amount_cents, Cents::new(600));
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
        let cost = extract("stripe", STRIPE_CHARGE_3USD.as_bytes(), PaymentMode::Test).unwrap();
        assert_eq!(cost.amount_cents, Cents::new(300));
        // x402 is now a registered rail (PAY-2): a stripe-shaped body handed to it fails
        // on the missing x402 fields (Parse), NOT UnknownRail.
        assert!(matches!(
            extract("x402", STRIPE_CHARGE_3USD.as_bytes(), PaymentMode::Test),
            Err(RailError::Parse(_))
        ));
        let x402 = extract("x402", X402_SETTLE_150C.as_bytes(), PaymentMode::Test).unwrap();
        assert_eq!(x402.amount_cents, Cents::new(150));
        assert_eq!(x402.rail, "x402");
        // An unknown rail still has no extractor.
        assert!(matches!(
            extract("paypal", STRIPE_CHARGE_3USD.as_bytes(), PaymentMode::Test),
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
        let cost = extract_x402(X402_SETTLE_150C.as_bytes(), PaymentMode::Test).unwrap();
        assert_eq!(
            cost.amount_cents,
            Cents::new(150),
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
        let cost = extract_x402(small.as_bytes(), PaymentMode::Test).unwrap();
        assert_eq!(
            cost.amount_cents,
            Cents::new(60),
            "600000 / 10000 = 60 cents"
        );
    }

    #[test]
    fn mainnet_network_meters_only_in_real_mode() {
        let mainnet = X402_SETTLE_150C.replace("\"base-sepolia\"", "\"base\"");
        // Under --test-mode (sandbox), a mainnet (real-money) settle is REFUSED — the sandbox
        // switch can never mis-meter real money.
        assert!(
            extract_x402(mainnet.as_bytes(), PaymentMode::Test).is_err(),
            "mainnet must be refused in test mode"
        );
        // In real mode (no --test-mode, the deliberate default), the same settle METERS.
        let cost = extract_x402(mainnet.as_bytes(), PaymentMode::Real).unwrap();
        assert_eq!(
            cost.amount_cents,
            Cents::new(150),
            "real-mode mainnet meters the settled amount exactly"
        );
        // An UNKNOWN network is refused in BOTH modes (not a known USDC network).
        let eth = X402_SETTLE_150C.replace("\"base-sepolia\"", "\"ethereum\"");
        assert!(extract_x402(eth.as_bytes(), PaymentMode::Test).is_err());
        assert!(extract_x402(eth.as_bytes(), PaymentMode::Real).is_err());
    }

    #[test]
    fn sub_cent_atomic_amount_is_refused_not_truncated() {
        // 1500050 atomic = 1.50005 USDC = 150.005 cents — a sub-cent residue. Refused
        // rather than silently truncated, so the metered cost equals the settle exactly.
        let residue = X402_SETTLE_150C.replace("\"1500000\"", "\"1500050\"");
        assert!(extract_x402(residue.as_bytes(), PaymentMode::Test).is_err());
    }

    #[test]
    fn failed_or_malformed_settlement_is_refused() {
        // A failed on-chain settle has no metered cost.
        let failed = X402_SETTLE_150C.replace("\"success\": true", "\"success\": false");
        assert!(extract_x402(failed.as_bytes(), PaymentMode::Test).is_err());
        // A non-0x tx hash is refused.
        let bad_tx = X402_SETTLE_150C.replace(
            "\"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\"",
            "\"not-a-tx\"",
        );
        assert!(extract_x402(bad_tx.as_bytes(), PaymentMode::Test).is_err());
        // Missing the requirements/settlement objects entirely.
        assert!(extract_x402(b"{\"rail\":\"x402\"}", PaymentMode::Test).is_err());
        assert!(extract_x402(b"not json", PaymentMode::Test).is_err());
    }
}
