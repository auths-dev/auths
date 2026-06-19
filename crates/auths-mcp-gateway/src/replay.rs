//! The hermetic replay gate — the deterministic, no-model/no-network entrypoint.
//!
//! Drives the per-call gate from a frozen transcript: builds a throwaway
//! delegation chain in the sandbox registry, then for each step has the agent sign
//! the canonical `tools/call`, authenticates the signed call natively through
//! `auths-mcp-core` against the agent's delegator-anchored grant, returns the real
//! (replay-stub) downstream result on pass, and emits a receipt. No model, no
//! network — the verdicts are deterministic, so a transcript edited to drop a proof
//! or forge a wider scope still fails closed.

use std::path::{Path, PathBuf};

use auths_mcp_core::{
    Budget, Cents, CrossRailBudget, ExtractedCost, PerCallGate, Receipt, SpendLogRecord, ToolCall,
    Verdict,
};
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};
use chrono::Utc;

use crate::chain::Chain;
use crate::transcript::{Call, Step, Transcript};

/// The cost source for a paid call: where the amount the gate RESERVES and SETTLES comes
/// from. The whole point of the metered-rail cost extraction is that for a
/// metered rail the amount is read out of the rail's own RESPONSE — never an
/// agent-declared number.
struct CallCost {
    /// The ceiling reserved before the rail is touched.
    reserve_ceiling_cents: Cents,
    /// The actual settled into the monotonic counter after the rail returns.
    settle_cents: Cents,
    /// The rail-native reference the cost was extracted from (a Stripe charge id),
    /// present only when the cost is rail-response-authoritative.
    charge_ref: Option<String>,
    /// True when the cost was EXTRACTED from the rail's recorded response (vs. read from
    /// the transcript's known `cost_cents`) — drives the receipt's extraction evidence.
    extracted: bool,
    /// The rail's RAW recorded response bytes the cost was extracted from (`None` when the
    /// cost is the transcript's known number, not rail-extracted). Retained for the spend log
    /// so the offline audit re-extracts + cross-checks the cost against the signed cost.
    rail_response: Option<Vec<u8>>,
}

/// Resolve a paid call's cost. When the call names a `response_fixture`, the cost is
/// EXTRACTED from that recorded rail response (`charge.amount_captured` → cents, plus the
/// `ch_…` reference) under `AUTHS_MCP_RAIL_FIXTURES` — rail-response-authoritative, so an
/// agent under-declaring the cost cannot change what is metered. Otherwise the cost is the
/// transcript's known `cost_cents` / `reserve_ceiling_cents` (the existing metered path).
fn resolve_call_cost(call: &Call) -> anyhow::Result<CallCost> {
    let Some(fixture) = call.response_fixture() else {
        return Ok(CallCost {
            reserve_ceiling_cents: call.reserve_ceiling(),
            settle_cents: call.cost_cents,
            charge_ref: None,
            extracted: false,
            rail_response: None,
        });
    };

    // The rail's recorded response lives under the suite fixtures dir the probe exported.
    // The cost the gate reserves AND settles is read from this response — never a number
    // supplied in the transcript (the PAY-1 transcript deliberately supplies none).
    let rail = call
        .rail()
        .ok_or_else(|| anyhow::anyhow!("a response_fixture call must name its rail"))?;
    let dir = std::env::var("AUTHS_MCP_RAIL_FIXTURES").map_err(|_| {
        anyhow::anyhow!(
            "AUTHS_MCP_RAIL_FIXTURES is not set — cannot resolve the recorded rail response `{fixture}`"
        )
    })?;
    let path = PathBuf::from(dir).join(fixture);
    let bytes = std::fs::read(&path)
        .map_err(|e| anyhow::anyhow!("read recorded rail response {}: {e}", path.display()))?;

    let ExtractedCost {
        amount_cents,
        reference,
        rail: extracted_rail,
    } = auths_mcp_core::extract_rail_cost(rail, &bytes)
        .map_err(|e| anyhow::anyhow!("extract cost from {}: {e}", path.display()))?;
    debug_assert_eq!(extracted_rail, rail);

    // Both the reservation ceiling and the settled actual are the amount the rail's
    // response captured — a charge that exceeds the cap is refused on its extracted
    // ceiling BEFORE the rail's settle is metered, so the over-cap charge is never
    // settled into the counter.
    Ok(CallCost {
        reserve_ceiling_cents: amount_cents,
        settle_cents: amount_cents,
        charge_ref: Some(reference),
        extracted: true,
        rail_response: Some(bytes),
    })
}

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
    // Grant the agent a narrow `settle` capability so it can SIGN its own settlement commits
    // (attest its spend). It is non-weaponizable — it authorizes no tool call and no rail, only
    // the settlement attestation — so it does NOT widen tool access (write_file still refused).
    let mut scope = transcript.grant.scope.clone();
    if !scope.iter().any(|c| c == "settle") {
        scope.push("settle".to_string());
    }
    let mut chain = Chain::build(&lab, &scope)?;
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
        .unwrap_or(Budget::Cents(Cents::new(u64::MAX)));
    let mut budget =
        CrossRailBudget::open(chain.org_repo(), &chain.agent_did, budget_spec.cap_cents())?;
    println!(
        "▸ budget: one ${cap}.{rem:02} cap across ALL rails (verifier-held SETTLED counter keyed to the agent delegation + reserved holds)",
        cap = budget.cap_cents().get() / 100,
        rem = budget.cap_cents().get() % 100,
    );

    let mut all_matched = true;
    let mut call_idx = 0usize;
    // The hash of the prior persisted record, threaded into each call's signed `Auths-Prev` so the
    // spend log is a continuous chain; the first record links to the genesis sentinel.
    let mut prev_binding = auths_mcp_core::SPEND_LOG_GENESIS.to_string();

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
                let (matched, new_binding) =
                    drive_call(&gate, &chain, &mut budget, call_idx, call, &prev_binding).await?;
                all_matched &= matched;
                prev_binding = new_binding;
                call_idx += 1;
            }
        }
    }

    if all_matched {
        println!("▸ replay: every verdict matched its transcript expectation");
    } else {
        println!("▸ replay: a verdict diverged from its transcript expectation — gate caught it");
    }

    // Self-audit the spend log THIS run just wrote, OFFLINE, with the gate's own resolved KELs:
    // re-verify every signed proof + re-derive spend with no trust in the run that produced it.
    // A clean run audits `consistent`; with AUTHS_MCP_REPLAY_TAMPER set, the forged proof in the
    // log is CAUGHT here as `tampered-proof`.
    let log_path = auths_mcp_core::spend_log_path(chain.org_repo(), &chain.agent_did);
    match auths_mcp_core::read_spend_log(&log_path) {
        Ok(records) => {
            let verdict = gate.audit_spend_log(&records, Utc::now().timestamp()).await;
            println!("▸ audit: {} — {verdict}", verdict.code());
            // Emit the exact args to re-run the audit as a STANDALONE process (`verify-spend`),
            // so an external party (and the smoke) can re-derive this verdict from disk alone.
            println!(
                "▸ audit-cmd: --log {} --registry {} --agent {} --root {}",
                log_path.display(),
                chain.org_repo().display(),
                chain.agent_did,
                chain.root_did,
            );
        }
        Err(e) => println!("▸ audit: SKIPPED — no spend log to audit ({e})"),
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
    prev_binding: &str,
) -> anyhow::Result<(bool, String)> {
    // The cost source: for a metered rail with a recorded response fixture the amount is
    // EXTRACTED from the rail's own response (the metered-rail cost extraction);
    // otherwise it is the transcript's known cost. The reserve ceiling and the settled
    // actual both come from this source — for an extracted call, from the response,
    // never an agent number.
    let cost = resolve_call_cost(call)?;
    let tool_call = ToolCall {
        tool: call.tool.clone(),
        args: call.args.clone(),
        cost_cents: cost.settle_cents,
    };
    let capability = tool_call.capability();
    let canonical = tool_call.canonical_bytes();
    let rail = call.rail();
    let reserve_ceiling = cost.reserve_ceiling_cents;

    // The agent signs the canonical call as an auths artifact (its delegated key).
    let (mut proof_bytes, proof_sha) =
        chain.sign_call(idx, &canonical, capability.as_str(), prev_binding)?;

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

    // The receipt names the extracted charge id ONLY when the call actually settled it: a
    // refused (over-cap) charge was never metered — the rail's settle was never reached —
    // so its receipt names no settled charge (the reservation refused before the rail).
    let settled_charge_ref = if decision.forwards() {
        cost.charge_ref.as_deref()
    } else {
        None
    };

    let forwarded_result = if decision.forwards() {
        // Forward to the downstream (in replay, the stub real result), THEN settle the
        // ACTUAL cost into the monotonic counter and release the hold's slack.
        let result = downstream_result(&tool_call);
        if let Some(hold) = decision.hold {
            // Settle the ACTUAL the rail's response reports — for an extracted call this
            // is `charge.amount_captured` read from the response, not an agent number.
            let (settle_verdict, new_cumulative) = gate.settle(budget, hold, cost.settle_cents)?;
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
        settled_charge_ref,
        decision.reserved_cents,
        cumulative,
        now,
    );
    let receipt_digest = receipt
        .digest()
        .map_err(|e| anyhow::anyhow!("receipt digest: {e}"))?;
    let receipt_json = serde_json::to_string(&receipt)?;

    // For a metered call that SETTLED, the agent signs a settlement commit anchoring the ACTUAL
    // cost in signed `Auths-Settle-*` trailers under the `settle` capability — so the audit sums
    // the AGENT-SIGNED cost (un-forgeable by the operator), not just the rail-attested number.
    let settlement_commit = match (forwarded_result.is_some(), rail, settled_charge_ref) {
        (true, Some(rail_name), Some(charge)) if !cost.settle_cents.is_zero() => {
            // Bind the settlement to THIS call by the hash of its signed commit bytes.
            let call_binding = if std::env::var_os("AUTHS_MCP_SETTLE_REBIND").is_some() {
                // Adversarial harness hook: stamp a binding for a DIFFERENT call — simulating an
                // operator that moves a genuinely-signed (cheaper) settlement onto another call.
                // The settlement signature stays VALID, but its binding no longer matches this
                // call, so the audit must reject it on the binding check. Never set in normal use.
                auths_mcp_core::call_commit_binding(b"a different call commit")
            } else {
                auths_mcp_core::call_commit_binding(&proof_bytes)
            };
            let (mut bytes, _sha) = chain.sign_settlement(
                idx,
                &call_binding,
                rail_name,
                cost.settle_cents,
                charge,
                cumulative,
            )?;
            // Adversarial harness hook: when AUTHS_MCP_SETTLE_TAMPER is set, flip a byte of the
            // SIGNED settlement after signing — simulating an operator that alters the agent's
            // settled cost. The signature no longer matches, so the offline audit catches it.
            // Never set in normal operation.
            if std::env::var_os("AUTHS_MCP_SETTLE_TAMPER").is_some()
                && let Some(b) = bytes.iter_mut().find(|b| **b == b'a')
            {
                *b = b'b';
            }
            Some(bytes)
        }
        _ => None,
    };

    // This record's binding — what the NEXT call's `Auths-Prev` links to, so the audit can verify
    // the log is a continuous chain. Computed from the bytes about to be stored.
    let new_binding = auths_mcp_core::call_commit_binding(&proof_bytes);

    // Persist the per-call proof+receipt+rail-response(+settlement) record to the append-only spend
    // log under `<org_repo>/spend-log/<delegation>.jsonl`, so an offline `auths verify-spend`
    // re-verifies the SIGNED `call_commit` bytes + sums the AGENT-SIGNED cost with NO trust in the
    // operator.
    crate::spend_log::append(
        chain.org_repo(),
        &chain.agent_did,
        &SpendLogRecord {
            call_commit: proof_bytes,
            receipt,
            rail: rail.map(|r| r.to_string()),
            // Only a call that actually FORWARDED touched the rail, so only it has a response to
            // re-extract. A refused call (out-of-scope / over-cap / unauthentic) carries none — the
            // audit relies on `rail_response present ⟺ the call settled` (with the proof re-verified).
            rail_response: if forwarded_result.is_some() {
                cost.rail_response.clone()
            } else {
                None
            },
            settlement_commit,
        },
    )?;

    let rail_tag = rail.map(|r| format!(" rail={r}")).unwrap_or_default();
    // When the cost was EXTRACTED from the rail's response, name the charge id it was
    // extracted from + the extracted amount — the receipt-grade evidence that the metered
    // cost came from the response (the `ch_…` a stranger re-derives the cost by), not an
    // agent-declared number (the metered-rail cost extraction).
    let charge_tag = match (&cost.charge_ref, cost.extracted) {
        (Some(reference), true) => format!(
            " charge={reference} extracted={amt}",
            amt = fmt_cents(cost.settle_cents)
        ),
        _ => String::new(),
    };

    if let Some(result) = forwarded_result {
        // Forwarded: name the rail it settled on, the reserved ceiling, and the running
        // cross-rail SETTLED total (the slack between reserved and the settled delta is
        // released, never permanently consumed).
        println!(
            "▸ call[{idx}] {tool}{rail_tag} → {verdict}{charge_tag} (device=agent identity=parent-root) \
             reserved={reserved} settled_actual={actual} cross_rail_cumulative={cum} \
             result={result} receipt={digest} proof={proof}",
            tool = call.tool,
            verdict = verdict_code,
            reserved = fmt_cents(decision.reserved_cents),
            actual = fmt_cents(cost.settle_cents),
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
                " cap_cents={} would_be_cents={} \
                 (cross-rail reservation refused BEFORE the rail was touched)",
                cap_cents.get(),
                would_be_cents.get()
            ),
            Verdict::UsageCounterRolledBack {
                presented_cents,
                high_water_cents,
            } => format!(
                " presented_cents={} high_water_cents={}",
                presented_cents.get(),
                high_water_cents.get()
            ),
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
    Ok((matched, new_binding))
}

/// Format cents as `$D.CC` for the human verdict line.
fn fmt_cents(cents: Cents) -> String {
    format!("${}.{:02}", cents.get() / 100, cents.get() % 100)
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
