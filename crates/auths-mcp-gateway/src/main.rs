// This is a CLI process boundary: it prints to stdout/stderr (the verdict +
// receipt stream and the proxy's diagnostics), reads its environment configuration
// directly, and uses wall-clock `now` at the boundary where it injects it into the
// gate. These are the sanctioned boundary allowances every `auths` binary takes.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::disallowed_methods)]

//! # auths-mcp-gateway — the bounded-agent MCP gateway (the binary)
//!
//! The real-MCP proxy (PRD §5, Build item 2). It speaks MCP JSON-RPC up to the
//! agent and down to a wrapped downstream server; on each `tools/call` it
//! canonicalizes + signs the call, runs `auths-mcp-core`'s per-call gate (proof
//! authenticity + scope ⊆ parent · budget · expiry · revocation), forwards only on
//! pass, and otherwise returns a fail-closed MCP error carrying the distinct
//! verdict — plus a signed receipt either way.
//!
//! Two entrypoints:
//!
//! * `wrap` — the live proxy a user prepends to any MCP server line in their client
//!   config. Speaks MCP up to the agent (an `rmcp` server over stdio) and down to
//!   the wrapped downstream (an `rmcp` child-process client), proxying `tools/list`
//!   and `tools/call`, gating each call.
//! * `replay` — the hermetic gate / `--check` entrypoint (PRD §7). Drives the same
//!   per-call gate from a frozen transcript of a prior run's `tools/call` sequence —
//!   no model, no network — to deterministic verdicts the probes assert. It builds
//!   a throwaway delegation chain in the sandbox registry, has the agent sign each
//!   call, authenticates the signed call through `auths-mcp-core`, returns the
//!   downstream result on pass, and emits a receipt `auths verify` accepts.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod chain;
mod proxy;
mod replay;
mod transcript;

#[derive(Parser)]
#[command(
    name = "auths-mcp-gateway",
    about = "The bounded-agent MCP gateway — broker each tools/call through a cryptographic delegation",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wrap a downstream MCP server, bounding the agent to a scope, budget, and TTL.
    ///
    /// Everything after `--` is the downstream command the gateway proxies.
    Wrap(WrapArgs),

    /// Drive the gateway from a frozen transcript of a prior live run (the hermetic
    /// gate / `--check` entrypoint, PRD §7). No model, no network — deterministic
    /// verdicts the probes assert.
    Replay(ReplayArgs),
}

#[derive(Parser)]
struct WrapArgs {
    /// The capabilities the agent is granted (repeatable), e.g. `--scope fs.read`.
    #[arg(long = "scope", value_name = "CAP")]
    scope: Vec<String>,

    /// The quantitative budget for the session, e.g. `--budget '$5'` or `--budget 20calls`.
    ///
    /// The cap is enforced from the DURABLE, verifier-held cross-rail counter (D8) —
    /// the SAME monotonic SETTLED counter (persisted under the verifier's
    /// `budget-ledger`, keyed to the agent delegation, summed across ALL rails) the
    /// hermetic gate drives, not an in-memory per-session tally. One cap binds spend
    /// across every rail and tool by pre-authorization (reserve before the rail is
    /// touched, settle the actual after), so the live wire cannot allow a cross-rail
    /// call the gate refuses (#281).
    #[arg(long = "budget", value_name = "BUDGET")]
    budget: Option<String>,

    /// The grant time-to-live, e.g. `--ttl 30m`.
    #[arg(long = "ttl", value_name = "TTL")]
    ttl: Option<String>,

    /// Opt into SANDBOX payment rails (Stripe test `sk_test_…`, x402 `base-sepolia`).
    ///
    /// Real money is the DEFAULT: with no flag the gateway resolves to live Stripe
    /// (`api.stripe.com`, an `sk_live_…` key) and x402 on base mainnet (real USDC).
    /// This single flag is the deliberate opt-in to sandbox rails so no real money is
    /// spent; `AUTHS_MCP_TEST_MODE=1` is its environment twin. The mode is always
    /// disclosed (a `mode=real|test` banner at startup) so live rails are never silent.
    #[arg(long = "test-mode")]
    test_mode: bool,

    /// Resolve the payment mode and DISCLOSE it, then exit — a dry run that touches no
    /// rail and charges nothing.
    ///
    /// Prints which mode the operator's switches resolve to (`mode=real` by default,
    /// `mode=test` under `--test-mode`), the resolved Stripe/x402 rails, and the
    /// startup banner — then exits without serving the proxy. Use it to confirm
    /// whether real money would be live before wrapping for real. The mandatory-cap
    /// seatbelt still applies: a payment-rail wrap with no `--budget` is refused here
    /// too, in both modes.
    #[arg(long = "show-mode")]
    show_mode: bool,

    /// The agent delegation identifier (`did:keri:…`) the durable cross-rail counter is
    /// keyed to — the verifier-held SETTLED counter sums every rail's spend for THIS
    /// delegation. Optional: when the live-agent harness has not yet bound the agent's
    /// delegation on the wire, a stable session key roots the durable counter.
    #[arg(long = "agent-delegation", value_name = "DID")]
    agent_delegation: Option<String>,

    /// A downstream credential the GATEWAY custodies and injects into the wrapped
    /// downstream (repeatable), e.g. `--custody-credential DOWNSTREAM_API_KEY=sk-…`
    /// (PRD §12, the custody broker). The gateway holds the downstream tool's
    /// secret and injects it into the spawned downstream's environment on the
    /// brokered path; the agent connects with only its auths delegation and never
    /// sees or carries this secret. An agent that bypasses the gateway reaches the
    /// raw downstream with NO credential, so the call fails — the boundary is
    /// unbypassable by construction for credentialed resources. The value is read
    /// from the gateway's own config/environment, never from the agent's request,
    /// and is never logged or echoed into receipts/stdout.
    ///
    /// `NAME=VALUE` injects `VALUE`; bare `NAME` adopts the value from the
    /// gateway's own environment (so an operator can pass the secret out-of-band as
    /// `--custody-credential DOWNSTREAM_API_KEY` with the value only in the
    /// gateway's env, never on the agent-visible command line).
    #[arg(long = "custody-credential", value_name = "NAME[=VALUE]")]
    custody_credential: Vec<String>,

    /// The downstream MCP server command (everything after `--`).
    #[arg(last = true, value_name = "DOWNSTREAM", required = true)]
    downstream: Vec<String>,
}

#[derive(Parser)]
struct ReplayArgs {
    /// The frozen transcript of `tools/call`s to drive the gateway with.
    #[arg(long = "transcript", value_name = "FILE")]
    transcript: std::path::PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("auths-mcp-gateway: could not start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match cli.command {
        Command::Wrap(args) => runtime.block_on(run_wrap(args)),
        Command::Replay(args) => runtime.block_on(run_replay(args)),
    }
}

/// The live proxy: speak MCP up to the agent and down to the wrapped downstream,
/// gating each `tools/call` through `auths-mcp-core`.
async fn run_wrap(args: WrapArgs) -> ExitCode {
    let custody = match proxy::CustodyVault::from_specs(&args.custody_credential) {
        Ok(v) => v,
        Err(e) => {
            // Never echo a credential spec back; report only the offending NAME.
            eprintln!("auths-mcp-gateway: invalid --custody-credential: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cfg = proxy::WrapConfig {
        scope: args.scope,
        budget: args.budget,
        ttl: args.ttl,
        agent_delegation: args.agent_delegation,
        custody,
        downstream: args.downstream,
        test_mode: args.test_mode,
        show_mode: args.show_mode,
    };
    match proxy::serve(cfg).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("auths-mcp-gateway: wrap proxy exited: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The hermetic gate: drive the per-call gate from a frozen transcript.
async fn run_replay(args: ReplayArgs) -> ExitCode {
    match replay::run(&args.transcript).await {
        Ok(true) => ExitCode::SUCCESS,
        // A transcript whose verdicts all matched their expectations but which
        // legitimately expected a refusal exits 0 too; `Ok(false)` is reserved for a
        // verdict mismatch (the gate caught a divergence), which is a hard failure.
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!(
                "auths-mcp-gateway: replay could not drive the gateway over `{}`: {e}",
                args.transcript.display(),
            );
            ExitCode::FAILURE
        }
    }
}
