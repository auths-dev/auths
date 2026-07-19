//! The two first-party MCP tool servers (rmcp over stdio): T1 receipts and
//! T2 escrow. Both are DUMB shells — validate, call the `auths-evidence` /
//! domain functions, sign, return. They hold no money and no trust; `wrap`
//! meters them on x402 like any other downstream.

use std::path::PathBuf;
use std::sync::Arc;

use auths_evidence::{
    BuildOpts, BundleGrant, BundleSigner, ChainInput, EvidenceBundle, HoldState, RegistrySource,
    ReversalInputs, ReversalOutcome, TreasuryInput, build_bundle, determine_reversal, locate_call,
    resolve_chain, verify_offline,
};
use auths_mcp_core::{Cents, ChannelRecord};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use rmcp::model::{
    CallToolRequestParam, CallToolResult, Content, ListToolsResult, PaginatedRequestParam,
    ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde::Deserialize;

use crate::dispute::{DisputeInputs, dispute_evidence};
use crate::escrow::{
    EscrowAnchor, EscrowEvent, EscrowEventBody, EscrowRecord, PartySig, evaluate_rule_track,
};
use crate::exhibit::{pdf_exhibit, verification_appendix};
use crate::reversal::rail_for;

/// The injected wall clock — bins pass `Utc::now` at the process boundary; the
/// library never reads a clock itself.
pub type Clock = fn() -> DateTime<Utc>;

/// Shared configuration for the T1 receipts server. All values arrive from the
/// bin's environment parsing — this struct is plain data.
#[derive(Debug, Clone)]
pub struct ReceiptsConfig {
    /// The issuer registry (local path or remote URL).
    pub registry: RegistrySource,
    /// The agent delegation the tools resolve.
    pub agent: String,
    /// The pinned root.
    pub root: String,
    /// The spend log path override, when not the registry's own.
    pub log: Option<PathBuf>,
    /// The session grant facts.
    pub grant: BundleGrant,
    /// The treasury anchor trail, when the deployment has one.
    pub treasury: Option<TreasuryInput>,
    /// CAIP-2 network id for settlement legs.
    pub network: String,
    /// The default resolved counterparty when a call does not name one.
    pub default_counterparty: String,
    /// Where reversal claims are recorded.
    pub claims_dir: PathBuf,
}

impl ReceiptsConfig {
    /// The chain input the tools resolve with.
    pub fn chain_input(&self) -> ChainInput {
        ChainInput {
            agent: self.agent.clone(),
            root: self.root.clone(),
            registry: self.registry.clone(),
            log: self.log.clone(),
            grant: self.grant.clone(),
            treasury: self.treasury.clone(),
            tel_revocation: None,
        }
    }
}

/// The T1 receipts MCP server.
#[derive(Clone)]
pub struct ReceiptsServer {
    cfg: Arc<ReceiptsConfig>,
    signer: Arc<BundleSigner>,
    clock: Clock,
}

impl ReceiptsServer {
    /// Assemble the server.
    pub fn new(cfg: ReceiptsConfig, signer: BundleSigner, clock: Clock) -> Self {
        ReceiptsServer {
            cfg: Arc::new(cfg),
            signer: Arc::new(signer),
            clock,
        }
    }
}

fn tool(name: &'static str, description: &'static str, schema: serde_json::Value) -> Tool {
    let schema = schema
        .as_object()
        .cloned()
        .unwrap_or_default();
    Tool::new(name, description, schema)
}

fn ok_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string(value)
        .map_err(|e| McpError::internal_error(format!("serialize result: {e}"), None))?;
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

fn params<T: for<'de> Deserialize<'de>>(request: &CallToolRequestParam) -> Result<T, McpError> {
    let value = request
        .arguments
        .clone()
        .map(serde_json::Value::Object)
        .unwrap_or(serde_json::Value::Null);
    serde_json::from_value(value)
        .map_err(|e| McpError::invalid_params(format!("invalid arguments: {e}"), None))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BuildParams {
    payment_ref: String,
    counterparty: Option<String>,
    network: Option<String>,
}

#[derive(Deserialize)]
struct VerifyParams {
    bundle: EvidenceBundle,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisputeParams {
    payment_ref: String,
    counterparty: Option<String>,
    escrow_record: Option<serde_json::Value>,
    escrow_anchor_key_hex: Option<String>,
    compliance_receipt: Option<serde_json::Value>,
    head_max_age_secs: Option<u64>,
    /// A TEL/attestation revocation fact the caller's registry probe surfaced —
    /// a revocation that moves no KEL tip (§2.2(c)).
    tel_revocation: Option<auths_evidence::RevocationFact>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportParams {
    bundle: EvidenceBundle,
    format: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReversalParams {
    bundle: EvidenceBundle,
    dispute_ref: Option<String>,
    payee_org: Option<String>,
    payee_settlement_account: Option<String>,
    hold: Option<String>,
    escrow_record: Option<serde_json::Value>,
    milestone: Option<usize>,
}

impl ReceiptsServer {
    async fn receipt_build(&self, p: BuildParams) -> Result<CallToolResult, McpError> {
        let chain = resolve_chain(self.cfg.chain_input(), (self.clock)())
            .await
            .map_err(|e| McpError::internal_error(format!("resolve: {e}"), None))?;
        let index = locate_call(&chain.records, &p.payment_ref)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let bundle = build_bundle(
            &chain,
            index,
            BuildOpts {
                network: p.network.unwrap_or_else(|| self.cfg.network.clone()),
                counterparty: p
                    .counterparty
                    .unwrap_or_else(|| self.cfg.default_counterparty.clone()),
                online_freshness: None,
                escrow: None,
                compliance: None,
                rendered: None,
                allow_first_seen_fallback: true,
            },
            &self.signer,
        )
        .map_err(|e| McpError::internal_error(format!("build: {e}"), None))?;
        ok_json(&bundle)
    }

    async fn receipt_verify(&self, p: VerifyParams) -> Result<CallToolResult, McpError> {
        ok_json(&verify_offline(&p.bundle).await)
    }

    async fn dispute_evidence(&self, p: DisputeParams) -> Result<CallToolResult, McpError> {
        let mut input = self.cfg.chain_input();
        input.tel_revocation = p.tel_revocation.clone();
        let bundle = dispute_evidence(
            input,
            &p.payment_ref,
            self.cfg.network.clone(),
            p.counterparty
                .unwrap_or_else(|| self.cfg.default_counterparty.clone()),
            DisputeInputs {
                escrow_record: p.escrow_record,
                escrow_anchor_key_hex: p.escrow_anchor_key_hex,
                compliance: p.compliance_receipt,
                head_max_age_secs: p.head_max_age_secs,
            },
            &self.signer,
            (self.clock)(),
        )
        .await
        .map_err(|e| McpError::internal_error(format!("dispute: {e}"), None))?;
        ok_json(&bundle)
    }

    async fn evidence_export(&self, p: ExportParams) -> Result<CallToolResult, McpError> {
        let format = p.format.as_deref().unwrap_or("pdf");
        let mut lines: Vec<String> = p
            .bundle
            .rendered
            .as_deref()
            .unwrap_or("(bundle carries no render — verify it directly)")
            .lines()
            .map(str::to_string)
            .collect();
        lines.extend(verification_appendix());
        match format {
            "pdf" => {
                let title = format!(
                    "AUTHS EVIDENCE EXHIBIT — tx {} (call #{})",
                    p.bundle.settlement.tx, p.bundle.call.index
                );
                let pdf = pdf_exhibit(&title, &lines);
                ok_json(&serde_json::json!({
                    "format": "pdf",
                    "base64": BASE64.encode(pdf),
                }))
            }
            "text" => ok_json(&serde_json::json!({ "format": "text", "text": lines.join("\n") })),
            other => Err(McpError::invalid_params(
                format!("unknown format `{other}` (psp mappings are decide-gated — plan RC-E3.4)"),
                None,
            )),
        }
    }

    async fn reversal_determine(&self, p: ReversalParams) -> Result<CallToolResult, McpError> {
        let hold = match p.hold.as_deref() {
            Some("escrow-held") => HoldState::EscrowHeld,
            Some("stripe-auth") => HoldState::StripeAuthUncaptured,
            Some("x402-reversible") => HoldState::X402Reversible,
            Some("none") | None => HoldState::None,
            Some(other) => {
                return Err(McpError::invalid_params(format!("unknown hold `{other}`"), None));
            }
        };
        let outcome = determine_reversal(
            &p.bundle,
            ReversalInputs {
                dispute_ref: p.dispute_ref,
                payee_org: p.payee_org,
                payee_settlement_account: p.payee_settlement_account,
                hold,
            },
            &self.signer,
        )
        .await
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        match outcome {
            ReversalOutcome::WithinRemit => ok_json(&serde_json::json!({
                "determined": false,
                "route": "subjective",
                "why": "the call was within the remit — no auto-reversal; escrow/arbitration decides",
            })),
            ReversalOutcome::Ungrounded(why) => ok_json(&serde_json::json!({
                "determined": false,
                "route": "none",
                "why": why,
            })),
            ReversalOutcome::Determined(det) => {
                let escrow = match (p.escrow_record, p.milestone) {
                    (Some(raw), Some(milestone)) => {
                        let record = EscrowRecord::verify_value(&raw, None)
                            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
                        Some((record, milestone))
                    }
                    _ => None,
                };
                let rail = rail_for(&det, escrow, self.cfg.claims_dir.clone());
                let executed = rail
                    .execute(&det)
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                ok_json(&serde_json::json!({
                    "determined": true,
                    "determination": det,
                    "rail": { "adapter": rail.name(), "result": executed },
                }))
            }
        }
    }
}

impl ServerHandler for ReceiptsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "auths-receipts: turn any settlement into a signed, offline-re-derivable \
                 evidence bundle with an anchored verdict. Nothing here is trusted — \
                 every answer re-derives from signed logs."
                    .to_string(),
            ),
            ..Default::default()
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: vec![
                tool(
                    "receipt_build",
                    "Build a signed, offline-re-derivable EvidenceBundle for a settled call (anchored as-of verdicts).",
                    serde_json::json!({ "type": "object", "required": ["paymentRef"], "properties": {
                        "paymentRef": { "type": "string", "description": "tx hash / charge ref / proof SHA / #index" },
                        "counterparty": { "type": "string" },
                        "network": { "type": "string", "description": "CAIP-2 id" }
                    }}),
                ),
                tool(
                    "receipt_verify",
                    "Re-check an EvidenceBundle fully offline; returns the as-of verdicts plus the S4 binding echo.",
                    serde_json::json!({ "type": "object", "required": ["bundle"], "properties": {
                        "bundle": { "type": "object" }
                    }}),
                ),
                tool(
                    "dispute_evidence",
                    "Assemble the retainer-grade dispute bundle: chain + escrow + minimized compliance + render + freshness stamp.",
                    serde_json::json!({ "type": "object", "required": ["paymentRef"], "properties": {
                        "paymentRef": { "type": "string" },
                        "counterparty": { "type": "string" },
                        "escrowRecord": { "type": "object" },
                        "escrowAnchorKeyHex": { "type": "string" },
                        "complianceReceipt": { "type": "object" },
                        "headMaxAgeSecs": { "type": "integer" },
                        "telRevocation": { "type": "object", "description": "a TEL/attestation revocation fact {source, seq?, ts?} that moves no KEL tip" }
                    }}),
                ),
                tool(
                    "evidence_export",
                    "Export a bundle as a generic exhibit (pdf/text) with the verification appendix.",
                    serde_json::json!({ "type": "object", "required": ["bundle"], "properties": {
                        "bundle": { "type": "object" },
                        "format": { "type": "string", "enum": ["pdf", "text"] }
                    }}),
                ),
                tool(
                    "reversal_determine",
                    "Compute the reversal a remit-violation bundle grounds (reversal/v1) and execute or record it via the rail port.",
                    serde_json::json!({ "type": "object", "required": ["bundle"], "properties": {
                        "bundle": { "type": "object" },
                        "disputeRef": { "type": "string" },
                        "payeeOrg": { "type": "string" },
                        "payeeSettlementAccount": { "type": "string" },
                        "hold": { "type": "string", "enum": ["escrow-held", "stripe-auth", "x402-reversible", "none"] },
                        "escrowRecord": { "type": "object" },
                        "milestone": { "type": "integer" }
                    }}),
                ),
            ],
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match request.name.as_ref() {
            "receipt_build" => self.receipt_build(params(&request)?).await,
            "receipt_verify" => self.receipt_verify(params(&request)?).await,
            "dispute_evidence" => self.dispute_evidence(params(&request)?).await,
            "evidence_export" => self.evidence_export(params(&request)?).await,
            "reversal_determine" => self.reversal_determine(params(&request)?).await,
            other => Err(McpError::invalid_params(format!("unknown tool `{other}`"), None)),
        }
    }
}

/// Configuration for the T2 escrow server.
#[derive(Debug, Clone)]
pub struct EscrowConfig {
    /// Where record pins persist (the availability backstop, design D5).
    pub records_dir: PathBuf,
    /// The anchor committer's P-256 seed (hex) — the rule track's time authority (S1).
    pub anchor_seed_hex: String,
    /// The measured anchor cadence lower bound every objection window must exceed (D3).
    pub anchor_cadence_secs: u64,
}

/// The T2 escrow MCP server.
#[derive(Clone)]
pub struct EscrowServer {
    cfg: Arc<EscrowConfig>,
    signer: Arc<BundleSigner>,
    clock: Clock,
}

#[derive(Deserialize)]
struct OpenParams {
    body: EscrowEventBody,
    sigs: Vec<PartySig>,
    at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct AppendParams {
    record: serde_json::Value,
    event: EscrowEvent,
}

#[derive(Deserialize)]
struct ArbitrateParams {
    record: serde_json::Value,
    index: usize,
    ruling: Option<EscrowEvent>,
}

impl EscrowServer {
    /// Assemble the server.
    pub fn new(cfg: EscrowConfig, signer: BundleSigner, clock: Clock) -> Self {
        EscrowServer {
            cfg: Arc::new(cfg),
            signer: Arc::new(signer),
            clock,
        }
    }

    fn anchor_seed(&self) -> Result<auths_crypto::TypedSeed, McpError> {
        let bytes = (0..self.cfg.anchor_seed_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&self.cfg.anchor_seed_hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| McpError::internal_error(format!("anchor seed: {e}"), None))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| McpError::internal_error("anchor seed must be 32 bytes", None))?;
        Ok(auths_crypto::TypedSeed::from_curve(
            auths_crypto::CurveType::P256,
            seed,
        ))
    }

    /// The pinned anchor committer key (hex) counterparties verify against.
    pub fn anchor_pubkey_hex(&self) -> Result<String, McpError> {
        let seed = self.anchor_seed()?;
        let public = auths_crypto::typed_public_key(&seed)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let mut hex = String::with_capacity(public.len() * 2);
        for byte in &public {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Ok(hex)
    }

    fn anchor_and_pin(&self, record: &mut EscrowRecord) -> Result<(), McpError> {
        let seed = self.anchor_seed()?;
        let anchor = EscrowAnchor::commit(record, (self.clock)(), &seed)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let pinned = self.anchor_pubkey_hex()?;
        record
            .attach_anchor(anchor, &pinned)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        std::fs::create_dir_all(&self.cfg.records_dir)
            .map_err(|e| McpError::internal_error(format!("pin dir: {e}"), None))?;
        let path = self.cfg.records_dir.join(format!("{}.json", record.id));
        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        std::fs::write(&path, json)
            .map_err(|e| McpError::internal_error(format!("pin write: {e}"), None))?;
        Ok(())
    }

    fn verify_record(&self, raw: &serde_json::Value) -> Result<EscrowRecord, McpError> {
        let pinned = self.anchor_pubkey_hex()?;
        EscrowRecord::verify_value(raw, Some(&pinned))
            .map_err(|e| McpError::invalid_params(e.to_string(), None))
    }

    fn escrow_open(&self, p: OpenParams) -> Result<CallToolResult, McpError> {
        let record = EscrowRecord::open(p.body, p.sigs, p.at, self.cfg.anchor_cadence_secs)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let mut record = record;
        self.anchor_and_pin(&mut record)?;
        let funding = match record.open_terms() {
            Ok(EscrowEventBody::Open {
                seller,
                milestones,
                rail,
                ..
            }) => {
                let capacity: u64 = milestones.iter().map(|m| m.amount_cents).sum();
                let channel = ChannelRecord::open(
                    &seller.settlement_address,
                    rail,
                    Cents::new(capacity),
                    &format!("escrow:{}", record.id),
                    (self.clock)(),
                );
                serde_json::json!({
                    "mode": "reserved",
                    "channel": channel,
                    "note": "reserved mode: no funds locked on-chain; the record makes any dispute \
                             cryptographically decidable, and the seller's assurance is reputational",
                })
            }
            _ => serde_json::Value::Null,
        };
        ok_json(&serde_json::json!({
            "record": record,
            "anchorKeyHex": self.anchor_pubkey_hex()?,
            "funding": funding,
        }))
    }

    fn escrow_append(&self, p: AppendParams) -> Result<CallToolResult, McpError> {
        let mut record = self.verify_record(&p.record)?;
        record
            .append(p.event)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        self.anchor_and_pin(&mut record)?;
        ok_json(&serde_json::json!({ "record": record }))
    }

    fn escrow_arbitrate(&self, p: ArbitrateParams) -> Result<CallToolResult, McpError> {
        let mut record = self.verify_record(&p.record)?;
        if let Some(ruling) = p.ruling {
            record
                .append(ruling)
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
            self.anchor_and_pin(&mut record)?;
        }
        let eval = evaluate_rule_track(&record, p.index)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        // The rule-track outcome, signed by the tool as a re-derivable statement.
        // In reserved mode NO outcome moves funds without the buyer's release (S2);
        // the ruling binds reputationally and feeds the reputation oracle.
        let statement = serde_json::json!({
            "escrowId": record.id,
            "milestone": p.index,
            "outcome": eval.outcome,
            "proof": eval.proof,
            "custody": "reserved — this ruling moves no funds; only a buyer-signed release settles",
            "issued_by": self.signer.did,
        });
        let canon = json_canon::to_string(&statement)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let signature = self
            .signer
            .sign_message(canon.as_bytes())
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        ok_json(&serde_json::json!({
            "ruling": statement,
            "signature": signature,
            "record": record,
        }))
    }
}

impl ServerHandler for EscrowServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "auths-escrow: non-custodial milestone escrow between two agents, ruled from \
                 signed facts. Reserved mode — no funds are locked; the record makes disputes \
                 decidable and only the buyer's signature settles."
                    .to_string(),
            ),
            ..Default::default()
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let record_schema = serde_json::json!({ "type": "object" });
        let event_schema = serde_json::json!({ "type": "object", "description": "a fully-signed EscrowEvent" });
        Ok(ListToolsResult {
            tools: vec![
                tool(
                    "escrow_open",
                    "Open a deal: validate the schedule, collect both signatures over r0, anchor, and return the record + reserved-mode funding.",
                    serde_json::json!({ "type": "object", "required": ["body", "sigs", "at"], "properties": {
                        "body": { "type": "object", "description": "the Open event body (kind=open)" },
                        "sigs": { "type": "array", "items": { "type": "object" } },
                        "at": { "type": "string", "format": "date-time" }
                    }}),
                ),
                tool(
                    "escrow_milestone",
                    "Append the seller's signed delivery proof; anchors and re-pins the record.",
                    serde_json::json!({ "type": "object", "required": ["record", "event"], "properties": {
                        "record": record_schema, "event": event_schema
                    }}),
                ),
                tool(
                    "escrow_object",
                    "Append the buyer's signed objection (timely objections convert the milestone to the arbitration track).",
                    serde_json::json!({ "type": "object", "required": ["record", "event"], "properties": {
                        "record": { "type": "object" }, "event": { "type": "object" }
                    }}),
                ),
                tool(
                    "escrow_release",
                    "Append the buyer-signed release — the only event that settles a slice (S2).",
                    serde_json::json!({ "type": "object", "required": ["record", "event"], "properties": {
                        "record": { "type": "object" }, "event": { "type": "object" }
                    }}),
                ),
                tool(
                    "escrow_arbitrate",
                    "Rules first: compute the anchored rule-track outcome; only an objected milestone reaches the named arbiter, whose signed ruling is recorded, never fabricated.",
                    serde_json::json!({ "type": "object", "required": ["record", "index"], "properties": {
                        "record": { "type": "object" },
                        "index": { "type": "integer" },
                        "ruling": { "type": "object", "description": "the named arbiter's signed Ruling event, when the subjective branch applies" }
                    }}),
                ),
            ],
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match request.name.as_ref() {
            "escrow_open" => self.escrow_open(params(&request)?),
            "escrow_milestone" | "escrow_object" | "escrow_release" => {
                self.escrow_append(params(&request)?)
            }
            "escrow_arbitrate" => self.escrow_arbitrate(params(&request)?),
            other => Err(McpError::invalid_params(format!("unknown tool `{other}`"), None)),
        }
    }
}
