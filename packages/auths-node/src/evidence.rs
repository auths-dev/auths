//! Evidence-layer bindings: the `auths-evidence` trust core re-exported verbatim
//! into `@auths-dev/sdk`. Every function returns the versioned JSON contract
//! (`audit/v1`, `receipts/v1`, `activity/v1`) — formatters over verified facts,
//! never a second implementation.

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Re-derive an agent's spend from its signed log — the same single
/// implementation behind `verify-spend` and `receipt_build`. Returns the
/// `audit/v1` report as JSON.
///
/// Args:
/// * `log_path`: the spend log (JSONL file or rotated directory).
/// * `registry_path`: the issuer's registry.
/// * `agent` / `root`: the delegation to audit.
///
/// Usage:
/// ```ignore
/// const report = JSON.parse(await verifySpend(log, registry, agent, root));
/// ```
#[napi]
pub async fn verify_spend(
    log_path: String,
    registry_path: String,
    agent: String,
    root: String,
) -> Result<String> {
    #[allow(clippy::disallowed_methods)] // binding boundary: wall clock injected here
    let now = chrono::Utc::now();
    let spend = auths_evidence::verify_spend(
        auths_evidence::VerifyOpts::new(
            std::path::Path::new(&log_path),
            std::path::Path::new(&registry_path),
            &agent,
            &root,
        ),
        now,
    )
    .await
    .map_err(|e| Error::from_reason(e.to_string()))?;
    serde_json::to_string(&spend.report).map_err(|e| Error::from_reason(e.to_string()))
}

/// Fully-offline verification of a `receipts/v1` EvidenceBundle: signature →
/// proof replay → head recompute → anchor tier → verdict recompute → the S4
/// binding echo. Returns the OfflineVerdict as JSON; the CALLER must assert the
/// echoed subject/tx/callIndex match its own payment ref.
///
/// Usage:
/// ```ignore
/// const v = JSON.parse(await verifyOffline(bundleJson));
/// if (!v.ok || v.tx !== myDisputedTx) deny();
/// ```
#[napi]
pub async fn verify_offline(bundle_json: String) -> Result<String> {
    let bundle: auths_evidence::EvidenceBundle =
        serde_json::from_str(&bundle_json).map_err(|e| Error::from_reason(e.to_string()))?;
    let verdict = auths_evidence::verify_offline(&bundle).await;
    serde_json::to_string(&verdict).map_err(|e| Error::from_reason(e.to_string()))
}

/// Verify a published `activity/v1` attestation against a fetched registry copy:
/// resolve the agent's current keys from the KEL (identity resolution ONLY —
/// never a spend log), require its delegator to be the claimed root, verify the
/// signature. Returns `{ok, reason?, head, count, cumulativeCents, asOfTs,
/// subjectRoot, subjectAgent}` as JSON — everything the market's receipts worker
/// needs, as verdict fields (the report is the only API).
///
/// Usage:
/// ```ignore
/// const check = JSON.parse(verifyActivityAttestation(doc, registryDir));
/// if (!check.ok) markStale(check.reason);
/// ```
#[napi]
pub fn verify_activity_attestation(
    attestation_json: String,
    registry_path: String,
) -> Result<String> {
    let doc: auths_evidence::ActivityV1 = match serde_json::from_str(&attestation_json) {
        Ok(doc) => doc,
        Err(e) => {
            return serde_json::to_string(&serde_json::json!({
                "ok": false, "reason": format!("not activity/v1-shaped: {e}"),
            }))
            .map_err(|e| Error::from_reason(e.to_string()));
        }
    };
    let outcome = auths_evidence::verify_activity_against_registry(
        &doc,
        std::path::Path::new(&registry_path),
    );
    let body = match outcome {
        Ok(()) => serde_json::json!({
            "ok": true,
            "head": doc.head,
            "count": doc.count,
            "cumulativeCents": doc.cumulative_cents,
            "asOfTs": doc.as_of.ts.to_rfc3339(),
            "subjectRoot": doc.subject.root,
            "subjectAgent": doc.subject.agent,
        }),
        Err(e) => serde_json::json!({ "ok": false, "reason": e.to_string() }),
    };
    serde_json::to_string(&body).map_err(|e| Error::from_reason(e.to_string()))
}

/// The monotonicity check between a stored attestation checkpoint and a freshly
/// fetched one. Returns the named violation, or null when acceptable.
///
/// Args:
/// * `prev_head` / `prev_count` / `prev_cents` / `prev_ts_iso`: the stored checkpoint.
/// * `next_json`: the freshly fetched `activity/v1` document.
///
/// Usage:
/// ```ignore
/// const violation = attestationMonotonicityViolation(head, count, cents, ts, doc);
/// ```
#[napi]
pub fn attestation_monotonicity_violation(
    prev_head: String,
    prev_count: i64,
    prev_cents: i64,
    prev_ts_iso: String,
    next_json: String,
) -> Result<Option<String>> {
    let next: auths_evidence::ActivityV1 =
        serde_json::from_str(&next_json).map_err(|e| Error::from_reason(e.to_string()))?;
    let prev_ts = chrono::DateTime::parse_from_rfc3339(&prev_ts_iso)
        .map_err(|e| Error::from_reason(format!("prev ts: {e}")))?
        .with_timezone(&chrono::Utc);
    Ok(auths_evidence::monotonicity_violation(
        Some((&prev_head, prev_count as u64, prev_cents as u64, prev_ts)),
        &next,
    )
    .map(str::to_string))
}

/// Verify a `reversal/v1` determination against the bundle it cites: signature,
/// direction, and that amount + parties + basis re-derive from the signed
/// evidence. Returns `{ok, reason?}` as JSON.
#[napi]
pub async fn verify_reversal_determination(
    determination_json: String,
    bundle_json: String,
) -> Result<String> {
    let det: auths_evidence::ReversalDetermination =
        serde_json::from_str(&determination_json).map_err(|e| Error::from_reason(e.to_string()))?;
    let bundle: auths_evidence::EvidenceBundle =
        serde_json::from_str(&bundle_json).map_err(|e| Error::from_reason(e.to_string()))?;
    let body = match auths_evidence::verify_determination(&det, &bundle).await {
        Ok(()) => serde_json::json!({ "ok": true }),
        Err(e) => serde_json::json!({ "ok": false, "reason": e.to_string() }),
    };
    serde_json::to_string(&body).map_err(|e| Error::from_reason(e.to_string()))
}

/// Fetch a public identity registry into a local directory, fully in-process
/// (libgit2 with its own HTTPS transport — no `git` binary on the host, so it
/// works inside serverless functions). Fetches identity refs and heads only —
/// this is key resolution; no spend data exists at a registry URL — and
/// materializes the first fetched branch's working files, matching the layout
/// the CLI writes.
///
/// Args:
/// * `url`: the public registry's git URL (`registry_git_url` from `audit.json`).
/// * `dest`: an empty local directory to fetch into.
///
/// Usage:
/// ```ignore
/// fetchRegistry(manifest.registry_git_url, registryDir);
/// const check = JSON.parse(verifyActivityAttestation(doc, registryDir));
/// ```
#[napi]
pub fn fetch_registry(url: String, dest: String) -> Result<()> {
    let map =
        |stage: &'static str| move |e: git2::Error| Error::from_reason(format!("{stage}: {e}"));
    // An unused initial head name, so fetching the remote's `refs/heads/main`
    // never collides with the checked-out branch.
    let mut init = git2::RepositoryInitOptions::new();
    init.initial_head("_verifier");
    let repo = git2::Repository::init_opts(std::path::Path::new(&dest), &init)
        .map_err(map("init registry dir"))?;
    let mut remote = repo.remote_anonymous(&url).map_err(map("remote"))?;
    remote
        .fetch(
            &["+refs/auths/*:refs/auths/*", "+refs/heads/*:refs/heads/*"],
            None,
            None,
        )
        .map_err(map("fetch registry"))?;
    drop(remote);

    let mut branch: Option<String> = None;
    for reference in repo.references_glob("refs/heads/*").map_err(map("list heads"))? {
        let reference = reference.map_err(map("read head"))?;
        let name = reference.name().map_err(map("head name"))?;
        if name != "refs/heads/_verifier" {
            branch = Some(name.to_string());
            break;
        }
    }
    if let Some(name) = branch {
        repo.set_head(&name).map_err(map("set head"))?;
        let mut checkout = git2::build::CheckoutBuilder::new();
        checkout.force();
        repo.checkout_head(Some(&mut checkout))
            .map_err(map("materialize working tree"))?;
    }
    Ok(())
}

/// The embedded JSON schema for the `receipts/v1` wire contract.
#[napi]
pub fn receipts_v1_schema() -> String {
    auths_evidence::RECEIPTS_V1_SCHEMA.to_string()
}

/// The embedded JSON schema for the `audit/v1` report.
#[napi]
pub fn audit_v1_schema() -> String {
    auths_evidence::AUDIT_V1_SCHEMA.to_string()
}
