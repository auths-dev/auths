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

/// Options for [`verify_activity_attestation`].
#[napi(object)]
pub struct VerifyActivityOpts {
    /// Fail the whole document when there is no verified witness anchor — promotes
    /// the anchor from an additive assurance tier to a required gate.
    pub require_witness: Option<bool>,
    /// An independently-known witness tip index for this seed, if the caller has
    /// one. A tip greater than the document's count marks the anchor `stale`.
    pub witness_tip_index: Option<i64>,
}

impl From<VerifyActivityOpts> for auths_evidence::VerifyActivityOpts {
    fn from(o: VerifyActivityOpts) -> Self {
        Self {
            require_witness: o.require_witness.unwrap_or(false),
            witness_tip_index: o.witness_tip_index.map(|v| v as u64),
        }
    }
}

/// Verify a published `activity/v1` attestation against a fetched registry copy:
/// resolve the agent's current keys from the KEL (identity resolution ONLY —
/// never a spend log), require its delegator to be the claimed root, verify the
/// signature — including the embedded quorum anchor when one is present, or as a
/// required gate under `opts.requireWitness` (a document with a bad or missing
/// anchor fails whole). Returns `{ok, reason?, head, count, cumulativeCents,
/// asOfTs, subjectRoot, subjectAgent, anchor, freshness, headBound}` as JSON —
/// everything the market's receipts worker needs, as verdict fields (the report
/// is the only API). `anchor` is `null` for an unanchored document, else the
/// VERIFIED quorum shape `{tier, threshold, witnesses, cosigners, seedId,
/// witnessSetSaid, stale}` — a relying party never derives a tier from the
/// seller's own claims. `freshness` is `"fresh" | "unknown" | "stale"`;
/// `headBound` is `true` only when a verified witness anchor cosigns the head.
///
/// `cumulativeCents` is a SIGNED CLAIM, not a re-derived fact: the per-call log
/// is structurally private, so the magnitude is provable only when `anchor` is a
/// non-stale `witness` summary. A consumer MUST NOT present `cumulativeCents` as
/// verified earnings unless `anchor?.tier === "witness" && anchor.stale === false`.
/// At first-seen (`anchor === null`) the honest label is "seller-claimed,
/// unwitnessed".
///
/// Usage:
/// ```ignore
/// const check = JSON.parse(verifyActivityAttestation(doc, registryDir, { requireWitness: true }));
/// if (!check.ok) markStale(check.reason);
/// ```
#[napi]
pub fn verify_activity_attestation(
    attestation_json: String,
    registry_path: String,
    opts: Option<VerifyActivityOpts>,
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
    let native_opts = opts
        .map(auths_evidence::VerifyActivityOpts::from)
        .unwrap_or_default();
    #[allow(clippy::disallowed_methods)] // binding boundary: wall clock injected here
    let now = chrono::Utc::now();
    let outcome = auths_evidence::verify_activity_against_registry(
        &doc,
        std::path::Path::new(&registry_path),
        now,
        native_opts,
    );
    let body = match outcome {
        Ok(verdict) => serde_json::json!({
            "ok": true,
            "head": doc.head,
            "count": doc.count,
            "cumulativeCents": doc.cumulative_cents,
            "asOfTs": doc.as_of.ts.to_rfc3339(),
            "subjectRoot": doc.subject.root,
            "subjectAgent": doc.subject.agent,
            // Only reachable when verify_activity_with_keys already re-checked the
            // finalization, so these fields restate proven facts.
            "anchor": verdict.anchor,
            "freshness": verdict.freshness,
            "headBound": verdict.head_bound,
        }),
        // A present-but-bad (or required-but-absent) anchor fails whole AND names
        // the leg the market can gate on.
        Err(auths_evidence::EvidenceError::AnchorInvalid { code, detail }) => serde_json::json!({
            "ok": false,
            "reason": format!("embedded anchor: {detail}"),
            "anchor": { "status": "invalid", "failedCheck": code },
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
    for reference in repo
        .references_glob("refs/heads/*")
        .map_err(map("list heads"))?
    {
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

/// Read a member's Key Event Log out of a `fetchRegistry` mirror as JSON.
///
/// Transport only — this does NOT verify. It emits the member's events plus,
/// for each event, its CESR attachment **hex-encoded** (controller indexed
/// signatures, and any delegation source seal), in exactly the shape
/// `@auths-dev/verifier`'s `validateKelJson(kelJson, attachmentsJson)` consumes:
/// `attachments[i]` is the hex attachment for `events[i]`, strictly equal
/// length and order. The caller (a browser) re-verifies; a compromised mirror
/// can withhold or truncate here, but the client recompute catches that — it
/// cannot forge.
///
/// The registry mirror only carries what rides under `refs/auths/*`, so the
/// attachments are the per-event controller/delegation groups actually stored;
/// witness receipts (a derived index) are served separately by the node's
/// `/witness/{prefix}/receipt/{said}` surface, not here.
///
/// Args:
/// * `registry_dir`: a directory previously populated by `fetchRegistry`.
/// * `prefix`: the member AID (a bare KERI prefix, no `did:keri:`).
///
/// Returns JSON `{ prefix, events, attachments, tip, source }`. Throws when this
/// registry does not hold the prefix.
///
/// Usage:
/// ```ignore
/// fetchRegistry(witnessGitUrl, dir);
/// const { events, attachments } = JSON.parse(readKelJson(dir, prefix));
/// const keyState = JSON.parse(await validateKelJson(
///   JSON.stringify(events), JSON.stringify(attachments)));
/// ```
#[napi]
pub fn read_kel_json(registry_dir: String, prefix: String) -> Result<String> {
    use auths_id::keri::event::Event;
    use auths_id::keri::types::Prefix;
    use auths_storage::git::PerPrefixKelStore;
    use std::ops::ControlFlow;

    #[derive(serde::Serialize)]
    struct TipJson {
        sequence: u128,
        said: String,
    }
    #[derive(serde::Serialize)]
    struct KelReadResult {
        prefix: String,
        events: Vec<Event>,
        attachments: Vec<String>,
        tip: Option<TipJson>,
        source: &'static str,
    }

    let store = PerPrefixKelStore::open(std::path::Path::new(&registry_dir));
    let pfx = Prefix::new_unchecked(prefix.clone());

    // Events in sequence order.
    let mut events: Vec<Event> = Vec::new();
    store
        .visit_events(&pfx, 0, &mut |e: &Event| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .map_err(|e| Error::from_reason(format!("read kel for {prefix}: {e}")))?;

    // Pair each event with its hex-encoded CESR attachment (same order/length).
    let mut attachments: Vec<String> = Vec::with_capacity(events.len());
    for ev in &events {
        let seq = ev.sequence().value();
        let att = store
            .get_attachment(&pfx, seq)
            .map_err(|e| Error::from_reason(format!("read attachment {seq} for {prefix}: {e}")))?
            .unwrap_or_default();
        attachments.push(hex::encode(att));
    }

    let tip = store.get_tip(&pfx).ok().map(|t| TipJson {
        sequence: t.sequence,
        said: t.said.to_string(),
    });

    let out = KelReadResult {
        prefix,
        events,
        attachments,
        tip,
        source: "per-prefix",
    };
    serde_json::to_string(&out).map_err(|e| Error::from_reason(format!("serialize kel: {e}")))
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
