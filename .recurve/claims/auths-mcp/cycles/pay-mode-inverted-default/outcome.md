# Outcome: pay-mode-inverted-default

**Status:** closed — AGENT-PAY-3 promoted open → closed.
**Gate:** `recurve matrix --gate` green fleet-wide (exit 0): holding 11,
ready_to_close 0, zero regressions/broken/stale/missing, 13/13 traps RED,
leakcheck clean, federated `auths-mcp` wrapper gate OK.

## What changed (the smallest honest change)

A clean **PaymentMode port** where REAL money is the default and sandbox is a
single opt-in — built at the engine + boundary, never with payment code.

- **`crates/auths-mcp-core/src/paymode.rs`** (new) — the port:
  - `PaymentMode::{Real, Test}`, `resolve(opted_into_test) -> PaymentMode`
    (total; REAL when not opted in). The port reads no environment itself.
  - `env_opts_into_test(Option<&str>)` — the pure truthy parse for the
    `AUTHS_MCP_TEST_MODE` env twin of `--test-mode` (one source of truth for the
    opt-in rule; the boundary reads the var and passes the value in).
  - `StripeRail` / `X402Rail` resolution: REAL → `api.stripe.com` `sk_live_…`
    (livemode) + x402 `base` mainnet; TEST → `sk_test_…` + x402 `base-sepolia`.
  - `ModeDisclosure` (banner + machine `mode=…` line) — the operator's evidence.
  - `require_budget(wraps_payment_rail, budget) -> Result<(), BudgetRequired>` —
    the mandatory-cap seatbelt: a payment rail with no `--budget` is refused
    `budget-required`, fail-closed, in BOTH modes.
- **`crates/auths-mcp-core/src/lib.rs`** — re-export the port surface.
- **`crates/auths-mcp-gateway/src/main.rs`** — `WrapArgs` gains `--test-mode`
  and `--show-mode`; plumbed into `WrapConfig`.
- **`crates/auths-mcp-gateway/src/proxy.rs`** — `WrapConfig.{test_mode,
  show_mode}` + `wraps_payment_rail()` (a session granting `paid.call`).
  `disclose_payment_mode()` runs FIRST in `serve()`: resolves the mode (flag OR
  env), discloses it (startup banner + machine line), enforces the mandatory
  cap, and — under `--show-mode` — prints the resolved rails and exits
  `served:false charged:false` without touching a rail or downstream.

## Why it is honest

- HERMETIC: `--show-mode` resolves + discloses and exits; it never serves the
  proxy and never charges. No live keys, no real money, in either mode.
- The mode is never silent: a payment-rail wrap (and every `--show-mode`)
  prints `mode=real|test` + a banner before anything is served.
- Fail-closed cap: a budget-less payment-rail wrap is refused `budget-required`
  before any rail/downstream is touched, in real AND test mode.

## Verdict deltas

- AGENT-PAY-3: RED/open → GREEN/closed.
- AGENT-PAY-1, AGENT-PAY-2: GREEN (unchanged — they drive `replay`, not the
  `wrap` disclosure path; no harness flip was needed).
- AGENT-MCP-1..5/7/8: GREEN (unchanged).
- AGENT-MCP-6: RED/open (untouched — blocked on the AGT-3 live runtime, #279).
- Traps: cap-omitted-allowed and mode-not-disclosed both still RED (discriminate).

## Quality

- `cargo build --release -p auths-mcp-gateway` clean.
- `cargo clippy --release -p auths-mcp-core -p auths-mcp-gateway -- -D warnings`
  clean (the port is env-pure so the engine crate's `disallowed_methods` lint is
  satisfied; the env read lives at the gateway boundary).
- `cargo test --release -p auths-mcp-core -p auths-mcp-gateway`: 32 + 9 pass
  (6 new paymode unit tests). No suppressions.
