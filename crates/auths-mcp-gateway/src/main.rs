// This is a CLI process boundary: it prints to stdout/stderr (the verdict +
// receipt stream and the proxy's diagnostics), reads its environment configuration
// directly, and uses wall-clock `now` at the boundary where it injects it into the
// gate. These are the sanctioned boundary allowances every `auths` binary takes.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::disallowed_methods)]

//! # auths-mcp-gateway — the bounded-agent MCP gateway (the binary)
//!
//! The real-MCP proxy. It speaks MCP JSON-RPC up to the
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
//! * `replay` — the hermetic gate / `--check` entrypoint. Drives the same
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
mod spend_log;
mod transcript;
mod treasury;

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
    /// gate / `--check` entrypoint). No model, no network — deterministic
    /// verdicts the probes assert.
    Replay(ReplayArgs),

    /// Independently audit a persisted spend log OFFLINE: re-verify every
    /// signed proof through the same verifier the gate uses + re-derive the spend, with NO
    /// trust in the operator that produced the log. Exits non-zero on any non-`consistent`
    /// verdict. Needs the issuer's registry to resolve the agent + delegator KELs.
    VerifySpend(VerifySpendArgs),

    /// The fleet treasury coordinator: ONE spending cap across N gateway processes.
    ///
    /// Gateways point `TREASURY_URL=tcp://host:port` at it; each metered call
    /// reserves fleet capacity here BEFORE the local budget, so the tighter cap
    /// always governs. Signs periodic `{fleet, count, cumulative}` checkpoints
    /// that `verify-spend --treasury-checkpoints` cross-checks offline.
    #[command(subcommand)]
    Treasury(TreasuryCommand),
}

#[derive(Subcommand)]
enum TreasuryCommand {
    /// Serve the fleet counter until killed.
    Serve(TreasuryServeArgs),
}

#[derive(Parser)]
struct TreasuryServeArgs {
    /// `host:port` to listen on, e.g. `127.0.0.1:7801`.
    #[arg(long = "listen", value_name = "ADDR")]
    listen: String,

    /// The fleet identifier — by convention the delegator root `did:keri:…`.
    #[arg(long = "fleet", value_name = "ID")]
    fleet: String,

    /// The fleet-wide cap, e.g. `--cap '$5'`.
    #[arg(long = "cap", value_name = "BUDGET")]
    cap: String,

    /// Where the durable ledger and the signed checkpoint trail persist.
    #[arg(long = "state-dir", value_name = "DIR")]
    state_dir: std::path::PathBuf,

    /// Hex seed for the P-256 checkpoint-signing key; generated fresh when omitted.
    #[arg(long = "signing-seed", value_name = "HEX", env = "TREASURY_SIGNING_SEED")]
    signing_seed: Option<String>,

    /// Seconds between checkpoint signatures (written only when the counter moved).
    #[arg(long = "checkpoint-secs", value_name = "SECS", default_value = "5")]
    checkpoint_secs: u64,
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

    /// The payment rail the WRAPPED downstream settles on, e.g. `--rail x402` or `--rail stripe`.
    /// When set, EVERY call to the downstream is metered on this rail: the gateway reads the ACTUAL
    /// cost from the rail's own response and meters it into the cross-rail cap, so an agent cannot
    /// bypass the cap by omitting a per-call declaration. Omit for a non-payment downstream.
    #[arg(long = "rail", value_name = "RAIL")]
    rail: Option<String>,

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

    /// A downstream credential the GATEWAY custodies and injects into the wrapped
    /// downstream (repeatable), e.g. `--custody-credential DOWNSTREAM_API_KEY=sk-…`
    /// (the custody broker). The gateway holds the downstream tool's
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

#[derive(Parser)]
struct VerifySpendArgs {
    /// The spend log (JSONL) to audit, e.g. `<repo>/spend-log/<delegation>.jsonl`.
    #[arg(long = "log", value_name = "FILE")]
    log: std::path::PathBuf,

    /// The issuer's registry the agent + delegator KELs are resolved from — the SAME local KEL
    /// resolution the live gate uses, run OFFLINE by anyone holding a copy of the registry.
    #[arg(long = "registry", value_name = "DIR")]
    registry: std::path::PathBuf,

    /// The agent's delegated `did:keri:…` whose signed proofs are re-verified.
    #[arg(long = "agent", value_name = "DID")]
    agent: String,

    /// The delegator/root `did:keri:…` the grant is anchored to (the pinned trust root).
    #[arg(long = "root", value_name = "DID")]
    root: String,

    /// A treasury checkpoint trail (`checkpoints.jsonl`) to cross-check: every
    /// signature must verify, the trail must be monotonic, and with
    /// `--expect-cumulative` the final total must equal the re-derived sum.
    #[arg(long = "treasury-checkpoints", value_name = "FILE")]
    treasury_checkpoints: Option<std::path::PathBuf>,

    /// Pin the coordinator's checkpoint-signing public key (compressed P-256, hex).
    #[arg(long = "treasury-pubkey", value_name = "HEX")]
    treasury_pubkey: Option<String>,

    /// Assert the final checkpointed cumulative equals this many cents (the caller's
    /// re-derived fleet-wide sum across every delegation log).
    #[arg(long = "expect-cumulative", value_name = "CENTS")]
    expect_cumulative: Option<u64>,
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
        Command::VerifySpend(args) => runtime.block_on(run_verify_spend(args)),
        Command::Treasury(TreasuryCommand::Serve(args)) => {
            runtime.block_on(run_treasury_serve(args))
        }
    }
}

/// The fleet treasury coordinator process: parse the cap, then serve until killed.
async fn run_treasury_serve(args: TreasuryServeArgs) -> ExitCode {
    let cap_cents = match auths_mcp_core::Budget::parse(&args.cap) {
        Ok(budget) => budget.cap_cents(),
        Err(e) => {
            eprintln!("auths-mcp-gateway: invalid --cap `{}`: {e}", args.cap);
            return ExitCode::FAILURE;
        }
    };
    let cfg = treasury::ServeConfig {
        listen: args.listen,
        fleet: args.fleet,
        cap_cents,
        state_dir: args.state_dir,
        signing_seed_hex: args.signing_seed,
        checkpoint_secs: args.checkpoint_secs,
    };
    match treasury::serve(cfg).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("auths-mcp-gateway: treasury serve exited: {e}");
            ExitCode::FAILURE
        }
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
        rail: args.rail,
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

/// The offline auditor: re-verify a persisted spend log against the issuer's
/// registry with the gate's OWN `verify_commit_against_kel_scoped` + `audit_spend_log` — run by
/// anyone, with no trust in the operator that produced the log. Exits non-zero on any
/// non-`consistent` verdict.
async fn run_verify_spend(args: VerifySpendArgs) -> ExitCode {
    use auths_mcp_core::PerCallGate;
    use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};

    let records = match auths_mcp_core::read_spend_log(&args.log) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "auths-mcp-gateway: cannot read spend log `{}`: {e}",
                args.log.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let registry =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&args.registry));
    let gate = match PerCallGate::resolve(&registry, &args.agent, &args.root) {
        Ok(g) => g,
        Err(e) => {
            eprintln!(
                "auths-mcp-gateway: cannot resolve KELs from registry `{}`: {e}",
                args.registry.display()
            );
            return ExitCode::FAILURE;
        }
    };
    // Locate the durable counter the SAME way the wire did (from this --registry + --agent), so the
    // audit cross-checks the re-derived total against the counter the wire advanced — a tail-truncated
    // log re-derives below it and is caught.
    let counter = match auths_mcp_core::CounterRef::for_agent(&args.registry, &args.agent) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "auths-mcp-gateway: cannot locate the durable counter for agent `{}`: {e}",
                args.agent
            );
            return ExitCode::FAILURE;
        }
    };
    // The facilitator key that would verify a captured rail attestation is supplied out-of-band once
    // the wire captures one (a follow-on); without it the offline audit still re-derives the spend.
    let verdict = gate
        .audit_spend_log(&records, chrono::Utc::now().timestamp(), &counter, None)
        .await;
    println!("verify-spend: {} — {verdict}", verdict.code());
    if !verdict.is_consistent() {
        return ExitCode::FAILURE;
    }
    if let Some(path) = &args.treasury_checkpoints
        && !cross_check_treasury(
            path,
            args.treasury_pubkey.as_deref(),
            args.expect_cumulative,
        )
    {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Cross-check a treasury checkpoint trail: signatures, monotonicity, and (when
/// asserted) the final cumulative against the caller's re-derived fleet total.
fn cross_check_treasury(
    path: &std::path::Path,
    expect_pubkey: Option<&str>,
    expect_cumulative: Option<u64>,
) -> bool {
    use auths_crypto::ring_provider::RingCryptoProvider;
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!(
                "auths-mcp-gateway: cannot read treasury checkpoints `{}`: {e}",
                path.display()
            );
            return false;
        }
    };
    let lines: Vec<String> = raw.lines().map(str::to_string).collect();
    let last = match auths_mcp_core::verify_checkpoint_trail(&lines, expect_pubkey, |pk, m, s| {
        RingCryptoProvider::p256_verify(pk, m, s).is_ok()
    }) {
        Ok(last) => last,
        Err(e) => {
            println!("treasury-checkpoints: invalid — {e}");
            return false;
        }
    };
    if let Some(expected) = expect_cumulative
        && last.cumulative_cents.get() != expected
    {
        println!(
            "treasury-checkpoints: invalid — {}",
            auths_mcp_core::TreasuryError::CumulativeMismatch {
                checkpointed: last.cumulative_cents.get(),
                rederived: expected,
            }
        );
        return false;
    }
    println!(
        "treasury-checkpoints: valid — fleet {} at count {}, cumulative {} cents",
        last.fleet,
        last.count,
        last.cumulative_cents.get()
    );
    true
}
