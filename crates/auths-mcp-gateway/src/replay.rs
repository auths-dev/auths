//! The hermetic replay gate — the deterministic, no-model/no-network entrypoint.
//!
//! Drives the per-call gate from a frozen transcript: builds a throwaway
//! delegation chain in the sandbox registry, then for each step has the agent sign
//! the canonical `tools/call`, authenticates the signed call natively through
//! `auths-mcp-core` against the agent's delegator-anchored grant, returns the real
//! (replay-stub) downstream result on pass, and emits a receipt. No model, no
//! network — the verdicts are deterministic, so a transcript edited to drop a proof
//! or forge a wider scope still fails closed.

use std::path::Path;

use auths_mcp_core::{Budget, PerCallGate, Receipt, SessionLedger, ToolCall, Verdict};
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};
use chrono::Utc;

use crate::chain::Chain;
use crate::transcript::{Step, Transcript};

/// Run the replay gate over `transcript`. Returns `Ok(true)` when every step's
/// re-derived verdict matched its transcript expectation (the gate held),
/// `Ok(false)` when a verdict diverged from its expectation (the gate caught a
/// regression), and `Err` when the gate could not be driven at all.
pub async fn run(transcript_path: &Path) -> anyhow::Result<bool> {
    let transcript = Transcript::load(transcript_path)?;

    // The sandbox HOME the probe exported is our lab root.
    let lab = std::env::var("LAB_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("mcp-replay-{}", std::process::id()))
        });
    std::fs::create_dir_all(&lab)?;

    println!(
        "▸ replay: bounding the agent to scope={:?} budget={:?} over {} step(s)",
        transcript.grant.scope,
        transcript.grant.budget,
        transcript.calls.len(),
    );

    // 1. Build the delegation chain: parent root + delegated scoped agent.
    let mut chain = Chain::build(&lab, &transcript.grant.scope)?;
    println!(
        "▸ chain: identity={} device={}",
        chain.root_did, chain.agent_did
    );

    // 2. The native per-call gate, resolving both KELs from the org registry. This
    //    is the security boundary — in-process, no shelling (D2).
    let registry =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(chain.org_repo()));
    let mut gate = PerCallGate::resolve(&registry, &chain.agent_did, &chain.root_did)?;

    // 3. The session ledger (budget v0 — permissive for MCP-1, wired for MCP-3).
    let budget = transcript
        .grant
        .budget
        .as_deref()
        .map(Budget::parse)
        .unwrap_or(Budget::Cents(u64::MAX));
    let mut ledger = SessionLedger::open(budget);

    let mut all_matched = true;
    let mut call_idx = 0usize;

    for step in &transcript.calls {
        match step {
            Step::Event { event } if event == "revoke" => {
                chain.revoke()?;
                // Re-resolve the gate so the next call re-derives liveness from the
                // chain (the revocation is now anchored in the registry).
                gate = PerCallGate::resolve(&registry, &chain.agent_did, &chain.root_did)?;
                println!("▸ event: revoke — the parent killed the delegation mid-session");
            }
            Step::Event { event } => {
                println!("▸ event: {event} (ignored)");
            }
            Step::Call(call) => {
                let matched = drive_call(&gate, &chain, &mut ledger, call_idx, call).await?;
                all_matched &= matched;
                call_idx += 1;
            }
        }
    }

    if all_matched {
        println!("▸ replay: every verdict matched its transcript expectation");
    } else {
        println!("▸ replay: a verdict diverged from its transcript expectation — gate caught it");
    }
    Ok(all_matched)
}

/// Drive one `tools/call` through the gate: sign it as the agent, authenticate the
/// signed call, emit the verdict + receipt, and (on pass) return the downstream
/// result. Returns whether the re-derived verdict matched the call's expectation.
async fn drive_call(
    gate: &PerCallGate,
    chain: &Chain,
    ledger: &mut SessionLedger,
    idx: usize,
    call: &crate::transcript::Call,
) -> anyhow::Result<bool> {
    let tool_call = ToolCall {
        tool: call.tool.clone(),
        args: call.args.clone(),
        cost_cents: call.cost_cents,
    };
    let capability = tool_call.capability();
    let canonical = tool_call.canonical_bytes();

    // The agent signs the canonical call as an auths artifact (its delegated key).
    let (mut proof_bytes, proof_sha) = chain.sign_call(idx, &canonical, capability.as_str())?;

    // Adversarial harness hook: when AUTHS_MCP_REPLAY_TAMPER is set, flip a byte of
    // the signed proof AFTER signing. The downstream tool must never be invoked on a
    // tampered proof — the native gate authenticates the signature and fails closed.
    // Never set in normal operation.
    if std::env::var_os("AUTHS_MCP_REPLAY_TAMPER").is_some()
        && let Some(b) = proof_bytes.iter_mut().find(|b| **b == b'a')
    {
        *b = b'b';
    }

    // Authenticate + gate natively (proof authenticity + scope + expiry +
    // revocation + budget). This is the boundary: a forged/tampered proof yields a
    // non-Allowed verdict here, before any downstream tool is invoked.
    let now = Utc::now();
    let decision = gate.judge(&tool_call, &proof_bytes, now, ledger).await?;

    let verdict_code = decision.verdict.code();

    // The receipt — device=agent, identity=parent-root — names the signed-call
    // proof `auths verify` accepts and carries the running total.
    let receipt = Receipt::for_call(
        &chain.agent_did,
        &chain.root_did,
        &tool_call,
        &proof_sha,
        decision.verdict.clone(),
        decision.cumulative_cents,
        now,
    );
    let receipt_digest = receipt
        .digest()
        .map_err(|e| anyhow::anyhow!("receipt digest: {e}"))?;
    let receipt_json = serde_json::to_string(&receipt)?;

    if decision.forwards() {
        // Charge the ledger and "forward" to the downstream — in replay the
        // downstream result is the stub real result for the proven tool.
        ledger.charge(call.cost_cents);
        let result = downstream_result(&tool_call);
        println!(
            "▸ call[{idx}] {tool} → {verdict} (device=agent identity=parent-root) \
             result={result} receipt={digest} proof={proof}",
            tool = call.tool,
            verdict = verdict_code,
            result = result,
            digest = receipt_digest,
            proof = &proof_sha[..proof_sha.len().min(12)],
        );
    } else {
        // Fail-closed: the downstream tool was never invoked. The receipt still
        // records the refusal.
        let detail = match &decision.verdict {
            Verdict::OutsideAgentScope { capability } => {
                format!(" capability={}", capability.as_str())
            }
            Verdict::UsageCapExceeded {
                cap_cents,
                would_be_cents,
            } => format!(" cap_cents={cap_cents} would_be_cents={would_be_cents}"),
            Verdict::ProofUnauthentic { reason } => format!(" reason={reason}"),
            _ => String::new(),
        };
        println!(
            "▸ call[{idx}] {tool} → {verdict}{detail} (downstream NOT invoked) receipt={digest}",
            tool = call.tool,
            verdict = verdict_code,
            digest = receipt_digest,
        );
    }

    // Machine-readable line the harness can also key on if it wants the raw verdict.
    println!("  verdict={verdict_code} receipt_json={receipt_json}");

    // Assert the re-derived verdict matches the transcript's expectation.
    let matched = match &call.expect {
        Some(expected) => expected == verdict_code,
        None => true,
    };
    if !matched {
        println!(
            "  MISMATCH: transcript expected `{}`, gate derived `{}`",
            call.expect.as_deref().unwrap_or("?"),
            verdict_code,
        );
    }
    Ok(matched)
}

/// The replay-stub downstream result for an allowed call — what a real wrapped MCP
/// server would return. Kept deterministic so the gate is byte-stable.
fn downstream_result(call: &ToolCall) -> String {
    match call.tool.as_str() {
        "read_file" | "read" => {
            let path = call
                .args
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            format!("\"# {path}\\n…contents of {path}…\"")
        }
        "paid_call" | "paid.call" => "\"{\\\"ok\\\":true}\"".to_string(),
        "create_comment" | "comment" => "\"{\\\"posted\\\":true}\"".to_string(),
        other => format!("\"{{\\\"tool\\\":\\\"{other}\\\",\\\"ok\\\":true}}\""),
    }
}
