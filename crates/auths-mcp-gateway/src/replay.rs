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

use auths_mcp_core::{Budget, CrossRailBudget, PerCallGate, Receipt, ToolCall, Verdict};
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};
use chrono::Utc;

use crate::chain::Chain;
use crate::transcript::{Call, Step, Transcript};

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

    // 3. The cross-rail budget engine (D8) — the authoritative counter that
    //    SUPERSEDES the gateway-held SessionLedger tally. ONE cap, summed across all
    //    rails: the verifier-held monotonic SETTLED counter (persisted under the org
    //    registry the verifier replays, keyed to the AGENT DELEGATION) + the transient
    //    RESERVED holds. `available = cap − settled − Σ(holds)`.
    let budget_spec = transcript
        .grant
        .budget
        .as_deref()
        .map(Budget::parse)
        .unwrap_or(Budget::Cents(u64::MAX));
    let mut budget =
        CrossRailBudget::open(chain.org_repo(), &chain.agent_did, budget_spec.cap_cents())?;
    println!(
        "▸ budget: one ${cap}.{rem:02} cap across ALL rails (verifier-held SETTLED counter keyed to the agent delegation + reserved holds)",
        cap = budget.cap_cents() / 100,
        rem = budget.cap_cents() % 100,
    );

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
                let matched = drive_call(&gate, &chain, &mut budget, call_idx, call).await?;
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

/// Drive one `tools/call` through the gate with the D8 cross-rail pre-authorization
/// flow: sign it as the agent, RESERVE its ceiling against the cross-rail budget
/// BEFORE the rail is touched (a reservation that would cross the cap is refused
/// `usage-cap-exceeded` and the downstream is never invoked), forward on pass, then
/// SETTLE the actual cost into the verifier-held monotonic SETTLED counter and release
/// the slack. Emits a receipt naming the rail it settled on and the running cross-rail
/// total. Returns whether the re-derived verdict matched the call's expectation.
async fn drive_call(
    gate: &PerCallGate,
    chain: &Chain,
    budget: &mut CrossRailBudget,
    idx: usize,
    call: &Call,
) -> anyhow::Result<bool> {
    let tool_call = ToolCall {
        tool: call.tool.clone(),
        args: call.args.clone(),
        cost_cents: call.cost_cents,
    };
    let capability = tool_call.capability();
    let canonical = tool_call.canonical_bytes();
    let rail = call.rail();
    let reserve_ceiling = call.reserve_ceiling();

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

    // Authenticate + PRE-AUTHORIZE natively (proof authenticity + scope + expiry +
    // revocation, then RESERVE against the cross-rail budget). This is the boundary:
    // a forged/tampered proof OR a reservation that would cross the cap yields a
    // non-Allowed verdict here, BEFORE any downstream tool/rail is invoked.
    let now = Utc::now();
    let decision = gate
        .judge(rail, reserve_ceiling, &proof_bytes, now, budget)
        .await?;

    // Track the verdict + the running cross-rail total to record. For a forwarded paid
    // call these are updated by the SETTLE below (the actual, not the reservation).
    let mut verdict = decision.verdict.clone();
    let mut cumulative = decision.cumulative_cents;

    let forwarded_result = if decision.forwards() {
        // Forward to the downstream (in replay, the stub real result), THEN settle the
        // ACTUAL cost into the monotonic counter and release the hold's slack.
        let result = downstream_result(&tool_call);
        if let Some(hold) = decision.hold {
            let (settle_verdict, new_cumulative) = gate.settle(budget, hold, call.cost_cents)?;
            // A clean settle keeps Allowed; a rollback (replayed/stale total) flips the
            // verdict to usage-counter-rolled-back (the D8 monotonicity guard).
            verdict = settle_verdict;
            cumulative = new_cumulative;
        }
        Some(result)
    } else {
        None
    };

    let verdict_code = verdict.code();

    // The receipt — device=agent, identity=parent-root — names the signed-call proof
    // `auths verify` accepts and carries the CROSS-RAIL running total + the rail it
    // settled on + the reserved-vs-settled split.
    let receipt = Receipt::for_call(
        &chain.agent_did,
        &chain.root_did,
        &tool_call,
        &proof_sha,
        verdict.clone(),
        rail,
        decision.reserved_cents,
        cumulative,
        now,
    );
    let receipt_digest = receipt
        .digest()
        .map_err(|e| anyhow::anyhow!("receipt digest: {e}"))?;
    let receipt_json = serde_json::to_string(&receipt)?;

    let rail_tag = rail.map(|r| format!(" rail={r}")).unwrap_or_default();

    if let Some(result) = forwarded_result {
        // Forwarded: name the rail it settled on, the reserved ceiling, and the running
        // cross-rail SETTLED total (the slack between reserved and the settled delta is
        // released, never permanently consumed).
        println!(
            "▸ call[{idx}] {tool}{rail_tag} → {verdict} (device=agent identity=parent-root) \
             reserved={reserved} settled_actual={actual} cross_rail_cumulative={cum} \
             result={result} receipt={digest} proof={proof}",
            tool = call.tool,
            verdict = verdict_code,
            reserved = fmt_cents(decision.reserved_cents),
            actual = fmt_cents(call.cost_cents),
            cum = fmt_cents(cumulative),
            result = result,
            digest = receipt_digest,
            proof = &proof_sha[..proof_sha.len().min(12)],
        );
    } else {
        // Fail-closed: the downstream tool/rail was never touched. The receipt still
        // records the refusal and the unchanged cross-rail total.
        let detail = match &verdict {
            Verdict::OutsideAgentScope { capability } => {
                format!(" capability={}", capability.as_str())
            }
            Verdict::UsageCapExceeded {
                cap_cents,
                would_be_cents,
            } => format!(
                " cap_cents={cap_cents} would_be_cents={would_be_cents} \
                 (cross-rail reservation refused BEFORE the rail was touched)"
            ),
            Verdict::UsageCounterRolledBack {
                presented_cents,
                high_water_cents,
            } => format!(" presented_cents={presented_cents} high_water_cents={high_water_cents}"),
            Verdict::ProofUnauthentic { reason } => format!(" reason={reason}"),
            _ => String::new(),
        };
        println!(
            "▸ call[{idx}] {tool}{rail_tag} → {verdict}{detail} cross_rail_cumulative={cum} \
             (downstream NOT invoked) receipt={digest}",
            tool = call.tool,
            verdict = verdict_code,
            cum = fmt_cents(cumulative),
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

/// Format cents as `$D.CC` for the human verdict line.
fn fmt_cents(cents: u64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
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
