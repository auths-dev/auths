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
mod channel;
mod inproc_sign;
mod metrics_http;
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

    /// Payment channels: open a metered capacity reservation, stream rail-free
    /// per-call spend against it (the signed spend log IS the channel state), and
    /// close with ONE netted rail action plus a settlement record citing the
    /// exact log_hash it was re-derived from. Rail legs are env-gated, never faked.
    #[command(subcommand)]
    Channel(ChannelCommand),

    /// One-shot verifier-ready export: flatten the delegation's (rotated) spend log
    /// into `spend.jsonl`, write `audit.json` naming `registry_git_url`, `agent`,
    /// and `root`, and leave the registry working files committed — everything a
    /// stranger needs to run `verify-spend` with no trust in this operator.
    ExportSpendBundle(ExportSpendBundleArgs),

    /// Emit the signed aggregate `activity/v1` attestation: re-derive the LOCAL,
    /// PRIVATE spend log, compute `{head, count, cumulative_cents}`, stamp `as_of`,
    /// and sign with the agent key under the root. No per-call data leaves the
    /// process — the market earns proven-live from witnessed monotone growth of
    /// this aggregate, never from the raw log (which exposes the counterparty
    /// graph and is never published).
    ExportAttestation(ExportAttestationArgs),
}

#[derive(Parser)]
struct ExportAttestationArgs {
    /// The gateway live dir (holds `registry/` with the spend log + counter).
    #[arg(long = "live-dir", value_name = "DIR", env = "AUTHS_MCP_LIVE_DIR")]
    live_dir: std::path::PathBuf,

    /// The agent delegation whose aggregate is attested.
    #[arg(long = "agent", value_name = "DID")]
    agent: String,

    /// The delegator/root the attestation chains to.
    #[arg(long = "root", value_name = "DID")]
    root: String,

    /// The agent's keychain alias (its delegate signing key).
    #[arg(
        long = "agent-label",
        value_name = "ALIAS",
        env = "AUTHS_MCP_AGENT_LABEL",
        default_value = "agent"
    )]
    agent_label: String,

    /// Where `activity.json` is written.
    #[arg(long = "out", value_name = "FILE")]
    out: std::path::PathBuf,

    /// The public URL a verifier fetches the identity registry from; when set, a
    /// sibling `audit.json` (`{registry_git_url, root, agent}` — identity/key
    /// resolution ONLY, never a spend log) is written beside `--out`.
    #[arg(long = "registry-url", value_name = "URL")]
    registry_url: Option<String>,

    /// A treasury/witness checkpoint trail to embed as the `as_of.anchor`
    /// countersignature tier.
    #[arg(long = "anchor", value_name = "FILE")]
    anchor: Option<std::path::PathBuf>,
}

#[derive(Parser)]
struct ExportSpendBundleArgs {
    /// The gateway live dir (holds `registry/` with the spend log + counter).
    #[arg(long = "live-dir", value_name = "DIR", env = "AUTHS_MCP_LIVE_DIR")]
    live_dir: std::path::PathBuf,

    /// The agent delegation whose log is exported.
    #[arg(long = "agent", value_name = "DID")]
    agent: String,

    /// The delegator/root the grant is anchored to.
    #[arg(long = "root", value_name = "DID")]
    root: String,

    /// The URL a verifier fetches the registry from (recorded in audit.json).
    #[arg(long = "registry-url", value_name = "URL")]
    registry_url: String,

    /// Where `spend.jsonl` + `audit.json` are written.
    #[arg(long = "out", value_name = "DIR")]
    out: std::path::PathBuf,
}

#[derive(Subcommand)]
enum ChannelCommand {
    /// Record a funded (or stated-unfunded) capacity reservation.
    Open(ChannelOpenArgs),
    /// Re-derive the streamed total from the signed log and emit the netted settlement.
    Close(ChannelCloseArgs),
}

#[derive(Parser)]
struct ChannelOpenArgs {
    /// The seller identity the channel streams to.
    #[arg(long = "seller", value_name = "DID")]
    seller: String,

    /// The reserved channel capacity, e.g. `--capacity '$50'`.
    #[arg(long = "capacity", value_name = "BUDGET")]
    capacity: String,

    /// The settling rail: `x402` or `stripe`.
    #[arg(long = "rail", value_name = "RAIL")]
    rail: String,

    /// The gateway live dir the channel record persists under.
    #[arg(long = "live-dir", value_name = "DIR", env = "AUTHS_MCP_LIVE_DIR")]
    live_dir: std::path::PathBuf,
}

#[derive(Parser)]
struct ChannelCloseArgs {
    /// The channel id to close (from `channel open`).
    #[arg(long = "channel", value_name = "ID")]
    channel: String,

    /// The spend log whose agent-signed cumulative is the closing state.
    #[arg(long = "log", value_name = "FILE")]
    log: std::path::PathBuf,

    /// The gateway live dir holding the channel record.
    #[arg(long = "live-dir", value_name = "DIR", env = "AUTHS_MCP_LIVE_DIR")]
    live_dir: std::path::PathBuf,
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
    #[arg(
        long = "signing-seed",
        value_name = "HEX",
        env = "TREASURY_SIGNING_SEED"
    )]
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

    /// A dispute reference stamped into every settlement receipt this session
    /// writes, so a dispute-evidence bundle can be found later by the payment it
    /// disputes. Producer-side only — consumers read it off the receipt.
    #[arg(long = "dispute-ref", value_name = "REF")]
    dispute_ref: Option<String>,

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

    /// Resume after an already-verified prefix of this many RECORDS (from a prior
    /// run's `checkpoint:` line). Requires `--resume-binding` and `--resume-cents`.
    #[arg(long = "resume-index", value_name = "N", requires_all = ["resume_binding", "resume_cents"])]
    resume_index: Option<usize>,

    /// The verified prefix's final commit binding (`checkpoint:` line `binding=`).
    #[arg(long = "resume-binding", value_name = "HASH")]
    resume_binding: Option<String>,

    /// The verified prefix's re-derived settled cents (`checkpoint:` line `settled_cents=`).
    #[arg(long = "resume-cents", value_name = "CENTS")]
    resume_cents: Option<u64>,
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
        Command::Channel(cmd) => run_channel(cmd),
        Command::ExportSpendBundle(args) => run_export_spend_bundle(args),
        Command::ExportAttestation(args) => runtime.block_on(run_export_attestation(args)),
    }
}

/// The attestation producer: re-derive the LOCAL private log with the one shared
/// implementation, aggregate, sign with the agent key, and write `activity.json`
/// (plus the identity-only `audit.json` sibling when `--registry-url` is given).
async fn run_export_attestation(args: ExportAttestationArgs) -> ExitCode {
    let registry = args.live_dir.join("registry");
    let log = auths_mcp_core::resolve_spend_log(&registry, &args.agent);
    let spend = match auths_evidence::verify_spend(
        auths_evidence::VerifyOpts::new(&log, &registry, &args.agent, &args.root),
        chrono::Utc::now(),
    )
    .await
    {
        Ok(spend) => spend,
        Err(e) => {
            eprintln!("auths-mcp-gateway: export-attestation: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Never attest an inconsistent log — the aggregate must commit to a chain
    // that re-derives, or the market's verification is attesting garbage.
    if !spend.report.consistent {
        eprintln!(
            "auths-mcp-gateway: export-attestation refused — the local log re-derives `{}`, not consistent",
            spend.report.code
        );
        return ExitCode::FAILURE;
    }
    let head = spend
        .report
        .checkpoint
        .as_ref()
        .map(|cp| cp.binding.clone())
        .unwrap_or_else(|| auths_mcp_core::SPEND_LOG_GENESIS.to_string());
    let anchor = match &args.anchor {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(raw) => {
                let lines: Vec<String> = raw.lines().map(str::to_string).collect();
                Some(serde_json::json!({ "tier": "treasury", "checkpoints": lines }))
            }
            Err(e) => {
                eprintln!(
                    "auths-mcp-gateway: cannot read --anchor `{}`: {e}",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };
    let (seed, curve) = match crate::inproc_sign::load_agent_signing_key(&args.agent_label) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("auths-mcp-gateway: export-attestation: {e}");
            return ExitCode::FAILURE;
        }
    };
    let suite = match curve {
        auths_crypto::CurveType::Ed25519 => "json-canon/ed25519",
        auths_crypto::CurveType::P256 => "json-canon/p256",
    };
    let mut doc = auths_evidence::ActivityV1 {
        version: auths_evidence::ACTIVITY_VERSION.to_string(),
        suite: suite.to_string(),
        subject: auths_evidence::Subject {
            root: args.root.clone(),
            agent: args.agent.clone(),
        },
        head,
        count: spend
            .report
            .checkpoint
            .as_ref()
            .map(|cp| cp.records as u64)
            .unwrap_or(0),
        cumulative_cents: spend.report.settled_cents,
        as_of: auths_evidence::ActivityAsOf {
            ts: chrono::Utc::now(),
            anchor,
        },
        signature: String::new(),
    };
    let result = (|| -> anyhow::Result<()> {
        let message = auths_evidence::activity_signing_bytes(&doc)
            .map_err(|e| anyhow::anyhow!("canonicalize: {e}"))?;
        let signature =
            auths_crypto::typed_sign(&seed, &message).map_err(|e| anyhow::anyhow!("sign: {e}"))?;
        use base64::Engine as _;
        doc.signature = base64::engine::general_purpose::STANDARD.encode(signature);
        if let Some(dir) = args.out.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&args.out, serde_json::to_vec_pretty(&doc)?)?;
        if let Some(url) = &args.registry_url {
            let manifest = serde_json::json!({
                "registry_git_url": url,
                "agent": args.agent,
                "root": args.root,
            });
            let sibling = args
                .out
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("audit.json");
            std::fs::write(sibling, serde_json::to_vec_pretty(&manifest)?)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            println!(
                "export-attestation: head {}… count {} cumulative {}c → {}",
                &doc.head[..16.min(doc.head.len())],
                doc.count,
                doc.cumulative_cents,
                args.out.display(),
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("auths-mcp-gateway: export-attestation: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Flatten the (possibly rotated) spend log, emit the audit manifest, and commit
/// the registry working state so a fetched copy re-derives the same counter.
fn run_export_spend_bundle(args: ExportSpendBundleArgs) -> ExitCode {
    let registry = args.live_dir.join("registry");
    let source = auths_mcp_core::resolve_spend_log(&registry, &args.agent);
    let records = match auths_mcp_core::read_spend_log(&source) {
        Ok(records) => records,
        Err(e) => {
            eprintln!(
                "auths-mcp-gateway: cannot read the spend log at `{}`: {e}",
                source.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let result = (|| -> anyhow::Result<()> {
        std::fs::create_dir_all(&args.out)?;
        let mut flat = String::new();
        for record in &records {
            flat.push_str(&serde_json::to_string(record)?);
            flat.push('\n');
        }
        std::fs::write(args.out.join("spend.jsonl"), flat)?;
        let manifest = serde_json::json!({
            "registry_git_url": args.registry_url,
            "agent": args.agent,
            "root": args.root,
        });
        std::fs::write(
            args.out.join("audit.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
        let add = std::process::Command::new("git")
            .args(["-C", &registry.to_string_lossy(), "add", "-A"])
            .envs(chain::default_git_identity())
            .output()?;
        if !add.status.success() {
            anyhow::bail!(
                "git add in the registry failed: {}",
                String::from_utf8_lossy(&add.stderr)
            );
        }
        // A clean tree is fine — the working files may already be committed.
        let _ = std::process::Command::new("git")
            .args([
                "-C",
                &registry.to_string_lossy(),
                "commit",
                "--quiet",
                "-m",
                "spend bundle export",
            ])
            .envs(chain::default_git_identity())
            .output()?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            println!(
                "export-spend-bundle: {} record(s) → {} (spend.jsonl + audit.json; registry committed)",
                records.len(),
                args.out.display(),
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("auths-mcp-gateway: export-spend-bundle: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The channel CLI: pure record I/O — no async, no rail touch.
fn run_channel(cmd: ChannelCommand) -> ExitCode {
    let result = match cmd {
        ChannelCommand::Open(args) => {
            channel::open(&args.seller, &args.capacity, &args.rail, &args.live_dir)
        }
        ChannelCommand::Close(args) => channel::close(&args.channel, &args.log, &args.live_dir),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("auths-mcp-gateway: channel: {e}");
            ExitCode::FAILURE
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
        dispute_ref: args.dispute_ref,
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

/// The offline auditor — a THIN caller of the single re-derivation in
/// `auths-evidence` (`verify_spend`), which the tool servers and every language
/// binding share. This CLI only parses flags and prints the stable output lines;
/// the trust logic lives in one place and cannot diverge.
async fn run_verify_spend(args: VerifySpendArgs) -> ExitCode {
    let resume = args.resume_index.map(|index| {
        #[allow(clippy::expect_used)] // INVARIANT: clap requires_all guarantees both flags
        auths_mcp_core::AuditResume {
            prior_records: index,
            prior_binding: args.resume_binding.clone().expect("required by clap"),
            prior_settled_cents: auths_mcp_core::Cents::new(
                args.resume_cents.expect("required by clap"),
            ),
        }
    });
    let spend = match auths_evidence::verify_spend(
        auths_evidence::VerifyOpts {
            log: &args.log,
            registry: &args.registry,
            agent: &args.agent,
            root: &args.root,
            treasury_checkpoints: None,
            treasury_pubkey: None,
            expect_cumulative: None,
            resume,
            facilitator_pubkey: None,
        },
        chrono::Utc::now(),
    )
    .await
    {
        Ok(spend) => spend,
        Err(e) => {
            eprintln!("auths-mcp-gateway: verify-spend: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "verify-spend: {} — {}",
        spend.report.code, spend.report.verdict
    );
    if !spend.report.consistent {
        return ExitCode::FAILURE;
    }
    // The resumable end state a checkpointing caller stores for its next run.
    if let Some(cp) = &spend.report.checkpoint {
        println!(
            "checkpoint: records={} settled_cents={} binding={}",
            cp.records, cp.settled_cents, cp.binding
        );
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
/// Thin over `auths_evidence::check_trail` — the one trail verification.
fn cross_check_treasury(
    path: &std::path::Path,
    expect_pubkey: Option<&str>,
    expect_cumulative: Option<u64>,
) -> bool {
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
    let last = match auths_evidence::check_trail(&lines, expect_pubkey) {
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
