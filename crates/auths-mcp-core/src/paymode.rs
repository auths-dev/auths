//! The payment-mode port — REAL money is the **default**, sandbox is a single opt-in.
//!
//! ## The decision this encodes (a deliberate operator inversion)
//!
//! An operator who wraps a payment rail almost always means it: the gateway sits in
//! front of real Stripe and real on-chain settlement. So the default is **REAL** —
//! with no flag, the rails resolve to live Stripe (`api.stripe.com`, an `sk_live_…`
//! key) and x402 on **base mainnet** (real USDC). Sandbox is the single, deliberate
//! opt-in: `--test-mode` on the wrap line (or `AUTHS_MCP_TEST_MODE=1` for the
//! adapter) flips the same port to test rails (Stripe `sk_test_…`, x402 on
//! `base-sepolia`). There is exactly one switch, and it costs an explicit action to
//! make spend safe rather than an explicit action to make it real.
//!
//! ## Why a port (ports & adapters)
//!
//! This is the I/O edge of the payment story: which endpoints, which key prefix,
//! which network a wrapped rail resolves to. The core logic (the cross-rail budget,
//! the gate) never imports it; the `wrap` boundary resolves a [`PaymentMode`] from
//! the operator's single switch and asks it to [`disclose`](PaymentMode::disclose)
//! itself. Resolution is total — [`PaymentMode::resolve`] always returns a
//! fully-formed mode, never a half-checked string a downstream re-validates.
//!
//! ## Two safety properties this port carries
//!
//! Because real money is the default, two things become load-bearing and live here
//! as types, not as scattered conditionals:
//!
//! * **The cap is mandatory.** A payment rail must not be wrapped without a budget —
//!   [`require_budget`] refuses, fail-closed, in *both* modes. Real-by-default with a
//!   skippable cap would be a foot-gun aimed at a live card; the seatbelt is not
//!   optional.
//! * **The mode is disclosed.** Every resolution carries a machine-readable
//!   `mode=real|test` token and a human banner ([`PaymentMode::disclosure`]), so an
//!   operator can never have live rails active silently.
//!
//! This module holds **no** payment code: it does not call Stripe, hold a key, or
//! settle on-chain. It names *which* endpoints/keys/networks a mode would use, so an
//! operator can read the resolution before any rail is touched. The actual metering
//! of a settled charge is [`crate::rail`]; the actual cross-rail cap is
//! [`crate::budget`].

use std::fmt;

/// Which payment world a wrapped rail resolves to. REAL is the default; TEST is the
/// single opt-in. The variants are the only two payment worlds the gateway knows —
/// there is no third "unset" state, because resolution is total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentMode {
    /// Live rails — real money. Stripe `api.stripe.com` (`sk_live_…`), x402 base
    /// mainnet (real USDC). The default when no opt-in is present.
    Real,
    /// Sandbox rails — no real money. Stripe `sk_test_…`, x402 `base-sepolia`. The
    /// single opt-in (`--test-mode` / `AUTHS_MCP_TEST_MODE=1`).
    Test,
}

/// The environment variable that opts the adapter into test mode (the env twin of the
/// `--test-mode` flag). Set to `1` (or `true`/`yes`/`on`) to select [`PaymentMode::Test`].
pub const TEST_MODE_ENV: &str = "AUTHS_MCP_TEST_MODE";

/// Whether the `AUTHS_MCP_TEST_MODE` value opts into test mode — the truthy parse for
/// the env twin of `--test-mode`. The wrap boundary reads the env var (the I/O edge)
/// and passes the value here, so the truthiness rule lives in one place while this
/// port reads no environment itself. `None` (unset) is not opted in.
pub fn env_opts_into_test(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

impl PaymentMode {
    /// Resolve the payment mode from the operator's single opt-in switch.
    ///
    /// `opted_into_test` is whether the operator opted into sandbox rails. The wrap
    /// boundary derives it from the `--test-mode` flag OR its environment twin
    /// `AUTHS_MCP_TEST_MODE` (see [`env_opts_into_test`]); this port stays pure and
    /// reads no environment itself. Absent the opt-in, the mode is
    /// [`PaymentMode::Real`] — real money is the default. Resolution is total: it
    /// always returns a fully-formed mode.
    pub fn resolve(opted_into_test: bool) -> Self {
        if opted_into_test {
            PaymentMode::Test
        } else {
            PaymentMode::Real
        }
    }

    /// The machine-readable mode token (`real` | `test`) — the stable key the
    /// disclosure and any receipt name so the mode is never inferred.
    pub fn token(self) -> &'static str {
        match self {
            PaymentMode::Real => "real",
            PaymentMode::Test => "test",
        }
    }

    /// True when this mode resolves to live rails (real money is active).
    pub fn is_real(self) -> bool {
        matches!(self, PaymentMode::Real)
    }

    /// The Stripe rail this mode resolves to.
    pub fn stripe(self) -> StripeRail {
        match self {
            PaymentMode::Real => StripeRail {
                endpoint: "api.stripe.com",
                key_expected: "sk_live_",
                livemode: true,
            },
            PaymentMode::Test => StripeRail {
                endpoint: "api.stripe.com",
                key_expected: "sk_test_",
                livemode: false,
            },
        }
    }

    /// The x402 rail this mode resolves to.
    pub fn x402(self) -> X402Rail {
        match self {
            PaymentMode::Real => X402Rail {
                network: "base",
                testnet: false,
                asset: "USDC",
            },
            PaymentMode::Test => X402Rail {
                network: "base-sepolia",
                testnet: true,
                asset: "USDC",
            },
        }
    }

    /// The human-facing startup banner naming whether real money is live and how to
    /// switch. Surfaced both at startup and by the resolve-and-disclose dry-run.
    pub fn banner(self) -> &'static str {
        match self {
            PaymentMode::Real => {
                "REAL MONEY MODE — live payment rails are active (Stripe live + x402 base \
                 mainnet). Pass --test-mode for sandbox."
            }
            PaymentMode::Test => {
                "TEST MODE — sandbox payment rails (Stripe test + x402 base-sepolia). No real \
                 money. Omit --test-mode for live."
            }
        }
    }

    /// The full disclosure of this resolution: the mode token, the banner, and the
    /// resolved rails. This is what the resolve-and-disclose dry-run prints and a
    /// receipt embeds — the operator's evidence of which world is live.
    pub fn disclosure(self) -> ModeDisclosure {
        ModeDisclosure {
            mode: self,
            banner: self.banner(),
            stripe: self.stripe(),
            x402: self.x402(),
        }
    }
}

impl fmt::Display for PaymentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// The Stripe rail a [`PaymentMode`] resolves to — which endpoint, which key prefix
/// an operator should hold, and whether it is livemode. Named, never charged here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StripeRail {
    /// The Stripe API endpoint the resolved key talks to.
    pub endpoint: &'static str,
    /// The key prefix this mode expects (`sk_live_` for real, `sk_test_` for test).
    pub key_expected: &'static str,
    /// Whether this is a live-money Stripe key.
    pub livemode: bool,
}

/// The x402/USDC rail a [`PaymentMode`] resolves to — which network and whether it is
/// a testnet. Named, never settled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X402Rail {
    /// The x402 network (`base` mainnet for real, `base-sepolia` for test).
    pub network: &'static str,
    /// Whether the network is a testnet (no real money).
    pub testnet: bool,
    /// The settled asset (USDC).
    pub asset: &'static str,
}

/// A resolved payment mode plus the rails it names — the disclosure surface an
/// operator reads before any rail is touched. Renders both a one-line human summary
/// and a machine-readable `mode=…` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeDisclosure {
    /// The resolved mode.
    pub mode: PaymentMode,
    /// The human banner.
    pub banner: &'static str,
    /// The resolved Stripe rail.
    pub stripe: StripeRail,
    /// The resolved x402 rail.
    pub x402: X402Rail,
}

impl ModeDisclosure {
    /// The machine-readable disclosure line an operator tool reads: `mode=real` (or
    /// `mode=test`) followed by the resolved rail summary. The `mode=` token is the
    /// stable contract; the rest is human-readable context.
    pub fn machine_line(&self) -> String {
        format!(
            "mode={} stripe.endpoint={} stripe.key_expected={} stripe.livemode={} \
             x402.network={} x402.testnet={} x402.asset={}",
            self.mode.token(),
            self.stripe.endpoint,
            self.stripe.key_expected,
            self.stripe.livemode,
            self.x402.network,
            self.x402.testnet,
            self.x402.asset,
        )
    }
}

/// The fail-closed refusal when a payment rail is wrapped without a budget. Because
/// real money is the default, the cross-rail cap is the safety seatbelt and is
/// mandatory — there is no allowed shape of "a live rail with no cap".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "budget-required: refusing to wrap a payment rail without a --budget: real money is the \
     default and the cross-rail cap is mandatory (the safety seatbelt). Pass --budget '$N', or \
     --test-mode for sandbox rails (still requires --budget)."
)]
pub struct BudgetRequired;

impl BudgetRequired {
    /// The stable reason code a tool/receipt names.
    pub fn code(&self) -> &'static str {
        "budget-required"
    }
}

/// Enforce the mandatory cap: a payment rail must carry a budget, in BOTH modes.
///
/// `wraps_payment_rail` is whether the session grants a payment capability (a rail
/// that can spend). `budget` is the operator's `--budget`. A payment rail with no
/// budget is refused [`BudgetRequired`], fail-closed, regardless of mode — the
/// seatbelt cannot be skipped. A non-payment session, or a payment session with a
/// budget, is permitted.
pub fn require_budget(
    wraps_payment_rail: bool,
    budget: Option<&str>,
) -> Result<(), BudgetRequired> {
    if wraps_payment_rail && budget.map(str::trim).unwrap_or("").is_empty() {
        return Err(BudgetRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_is_the_default_no_opt_in() {
        let mode = PaymentMode::resolve(false);
        assert_eq!(mode, PaymentMode::Real);
        assert!(mode.is_real());
        assert_eq!(mode.token(), "real");
        assert_eq!(mode.stripe().key_expected, "sk_live_");
        assert!(mode.stripe().livemode);
        assert_eq!(mode.x402().network, "base");
        assert!(!mode.x402().testnet);
    }

    #[test]
    fn the_opt_in_selects_test() {
        let mode = PaymentMode::resolve(true);
        assert_eq!(mode, PaymentMode::Test);
        assert!(!mode.is_real());
        assert_eq!(mode.token(), "test");
        assert_eq!(mode.stripe().key_expected, "sk_test_");
        assert!(!mode.stripe().livemode);
        assert_eq!(mode.x402().network, "base-sepolia");
        assert!(mode.x402().testnet);
    }

    #[test]
    fn the_env_value_is_the_adapter_twin_of_the_flag() {
        // The truthy parse of AUTHS_MCP_TEST_MODE (the env twin of --test-mode). The
        // boundary reads the var; this pure helper decides the opt-in.
        assert!(env_opts_into_test(Some("1")));
        assert!(env_opts_into_test(Some("true")));
        assert!(env_opts_into_test(Some(" YES ")));
        assert!(env_opts_into_test(Some("on")));
        assert!(!env_opts_into_test(Some("0")));
        assert!(!env_opts_into_test(Some("")));
        assert!(!env_opts_into_test(None));
        // And it composes: a truthy env value resolves to test mode.
        assert_eq!(
            PaymentMode::resolve(env_opts_into_test(Some("1"))),
            PaymentMode::Test
        );
    }

    #[test]
    fn the_disclosure_names_the_mode_and_the_resolved_rails() {
        let real = PaymentMode::Real.disclosure();
        let line = real.machine_line();
        assert!(line.contains("mode=real"), "{line}");
        assert!(line.contains("sk_live_"), "{line}");
        assert!(real.banner.contains("REAL MONEY"));
        let test = PaymentMode::Test.disclosure();
        let line = test.machine_line();
        assert!(line.contains("mode=test"), "{line}");
        assert!(line.contains("base-sepolia"), "{line}");
        assert!(test.banner.contains("TEST MODE"));
    }

    #[test]
    fn the_cap_is_mandatory_in_both_modes() {
        // A payment rail with no budget is refused, fail-closed, regardless of mode.
        assert!(require_budget(true, None).is_err());
        assert!(require_budget(true, Some("")).is_err());
        assert!(require_budget(true, Some("   ")).is_err());
        // With a budget it is permitted.
        assert!(require_budget(true, Some("$5")).is_ok());
        // A non-payment session needs no budget.
        assert!(require_budget(false, None).is_ok());
    }

    #[test]
    fn the_budget_required_refusal_carries_its_code() {
        let err = require_budget(true, None).unwrap_err();
        assert_eq!(err.code(), "budget-required");
        assert!(format!("{err}").contains("budget-required"));
        assert!(format!("{err}").contains("mandatory"));
    }
}
