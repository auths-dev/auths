//! Non-custodial escrow — the record, its rule track, and the custody bounds
//! (plan §RC-E4.0), reserved mode.
//!
//! The escrow record is an append-only, hash-chained event sequence `r₀…r_k`
//! (the same binding-chain construction the spend log uses) whose head is
//! anchored on whatever tier the deployment has. It travels **by value or by
//! pin** — never through anyone's identity registry.
//!
//! Security invariants encoded here:
//! * **S1** — the pin stores bytes; the anchor stamps time. Every rule-track
//!   outcome reads time ONLY from anchor timestamps, never from a party's or a
//!   pin operator's clock.
//! * **S2** — in reserved mode the arbiter moves nothing: only a buyer-signed
//!   `Release` settles a slice; an arbiter ruling is a signed opinion.
//! * Replay safety — every signature covers the milestone index inside the
//!   signed body, so a release for milestone 2 cannot be replayed against 3.

use auths_crypto::{CurveType, DecodedDidKey, TypedSeed, did_key_decode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The escrow wire version.
pub const ESCROW_VERSION: &str = "escrow/v1";

/// The first event's `prev` sentinel.
pub const ESCROW_GENESIS: &str = "escrow-genesis";

/// Errors the escrow domain surfaces.
#[derive(Debug, Error)]
pub enum EscrowError {
    /// The record failed structural or cryptographic verification.
    #[error("escrow record invalid: {0}")]
    Invalid(String),
    /// An append was rejected.
    #[error("escrow append rejected: {0}")]
    Rejected(String),
    /// A rule-track evaluation could not be established from anchored facts.
    #[error("rule track unestablished: {0}")]
    Unestablished(String),
    /// Signing failed.
    #[error("escrow signing failed: {0}")]
    Signing(String),
}

/// A deal party: its signing identity and the ONLY address funds can ever reach.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Party {
    /// The party's signing `did:key:` (curve-tagged, self-describing).
    pub did: String,
    /// The fixed settlement address funds move to — decided at `r₀`, never again.
    pub settlement_address: String,
}

/// One milestone of the schedule fixed at `r₀`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Milestone {
    /// The milestone amount (cents).
    pub amount_cents: u64,
    /// The delivery deadline `dᵢ`.
    pub deliver_by: DateTime<Utc>,
    /// The objection window `wᵢ` (seconds after the anchored delivery).
    pub objection_window_secs: u64,
}

/// The custody mode. Reserved ships; locked is contract-gated and refused here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EscrowMode {
    /// Gateway payment channel only — no on-chain lock; the record makes disputes
    /// decidable, reputationally binding (honest when labeled).
    Reserved,
    /// On-chain contract escrow — deferred until audit + counsel (plan RC-E4.0).
    Locked,
}

/// A ruling outcome on the rule track or from the named arbiter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RulingOutcome {
    /// Release the milestone amount to the seller's fixed address.
    Release,
    /// Refund the milestone amount to the buyer's fixed address.
    Refund,
    /// The window is still open — nothing to do yet.
    Hold,
    /// A timely objection exists: the subjective branch, for the named arbiter.
    NeedsArbiter,
}

/// The body of one escrow event — everything a signature covers (the milestone
/// index lives INSIDE the signed body, so signatures cannot be replayed across
/// milestones).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EscrowEventBody {
    /// `r₀` — fixes the parties, addresses, schedule, mode, and optional arbiter.
    Open {
        /// The buyer.
        buyer: Party,
        /// The seller.
        seller: Party,
        /// The named arbiter's `did:key:`, when the deal wants one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        arbiter: Option<String>,
        /// The custody mode.
        mode: EscrowMode,
        /// The milestone schedule.
        milestones: Vec<Milestone>,
        /// The settling rail.
        rail: String,
        /// The final timeout `T_end`.
        t_end: DateTime<Utc>,
    },
    /// The seller's signed delivery claim + evidence hash. Custody of proof, not
    /// adjudication of merit.
    Deliver {
        /// The milestone index.
        milestone: usize,
        /// Hash of the delivery evidence (the evidence itself travels elsewhere).
        evidence_hash: String,
    },
    /// The buyer's objection — converts the milestone to the arbitration track
    /// when anchored within the window.
    Object {
        /// The milestone index.
        milestone: usize,
        /// Hash of the objection reason.
        reason_hash: String,
    },
    /// The buyer's release — the ONLY event that settles funds in reserved mode (S2).
    Release {
        /// The milestone index.
        milestone: usize,
        /// The settlement tx, once the rail leg lands.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tx: Option<String>,
    },
    /// The named arbiter's recorded decision on an objected milestone — a signed
    /// opinion; in reserved mode it moves nothing.
    Ruling {
        /// The milestone index.
        milestone: usize,
        /// The outcome.
        outcome: RulingOutcome,
        /// The arbiter's stated reasoning.
        reason: String,
    },
}

/// One party signature over an event's canonical body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartySig {
    /// The signer's `did:key:`.
    pub signer: String,
    /// Base64 signature over `canon({seq, prev, at, body})`.
    pub sig: String,
}

/// One chained escrow event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscrowEvent {
    /// The event's sequence number (0-based).
    pub seq: u64,
    /// The prior event's binding (the genesis sentinel for `r₀`).
    pub prev: String,
    /// The producer's claimed timestamp — NEVER a rule-track time basis (S1).
    pub at: DateTime<Utc>,
    /// The signed body.
    pub body: EscrowEventBody,
    /// The signatures the event's kind requires.
    pub sigs: Vec<PartySig>,
}

/// A time anchor over a record prefix: "events `0..=upto_seq` (head `binding`)
/// existed at `ts`" — committed by a pinned key OUTSIDE the deal's parties.
/// This is the rule track's ONLY time basis (S1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscrowAnchor {
    /// The last event sequence this anchor covers.
    pub upto_seq: u64,
    /// The covered prefix's binding head.
    pub binding: String,
    /// The committed instant.
    pub ts: DateTime<Utc>,
    /// The committer's public key (compressed P-256, hex).
    pub public_key_hex: String,
    /// Base64 P-256 signature over `canon({upto_seq, binding, ts})`.
    pub signature: String,
}

impl EscrowAnchor {
    fn signing_bytes(
        upto_seq: u64,
        binding: &str,
        ts: DateTime<Utc>,
    ) -> Result<Vec<u8>, EscrowError> {
        let body = serde_json::json!({ "upto_seq": upto_seq, "binding": binding, "ts": ts });
        json_canon::to_string(&body)
            .map(String::into_bytes)
            .map_err(|e| EscrowError::Invalid(format!("anchor canon: {e}")))
    }

    /// Sign an anchor over a record prefix with the anchor service's P-256 seed.
    ///
    /// Args:
    /// * `record`: the record whose current head is being committed.
    /// * `ts`: the committed instant (the anchor service's clock, injected).
    /// * `seed`: the anchor service's P-256 seed.
    ///
    /// Usage:
    /// ```ignore
    /// let anchor = EscrowAnchor::commit(&record, now, &seed)?;
    /// ```
    pub fn commit(
        record: &EscrowRecord,
        ts: DateTime<Utc>,
        seed: &TypedSeed,
    ) -> Result<EscrowAnchor, EscrowError> {
        let upto_seq = record
            .events
            .last()
            .map(|e| e.seq)
            .ok_or_else(|| EscrowError::Invalid("empty record".to_string()))?;
        let binding = record.head();
        let message = Self::signing_bytes(upto_seq, &binding, ts)?;
        let signature = auths_crypto::typed_sign(seed, &message)
            .map_err(|e| EscrowError::Signing(e.to_string()))?;
        let public_key = auths_crypto::typed_public_key(seed)
            .map_err(|e| EscrowError::Signing(e.to_string()))?;
        Ok(EscrowAnchor {
            upto_seq,
            binding,
            ts,
            public_key_hex: hex_encode(&public_key),
            signature: BASE64.encode(signature),
        })
    }

    /// Verify this anchor against a pinned committer key and the record it claims
    /// to cover (the binding must match the record's prefix head at `upto_seq`).
    pub fn verify(&self, record: &EscrowRecord, pinned_key_hex: &str) -> Result<(), EscrowError> {
        if self.public_key_hex != pinned_key_hex {
            return Err(EscrowError::Invalid("anchor signer not the pinned key".to_string()));
        }
        let expected = record.binding_at(self.upto_seq)?;
        if expected != self.binding {
            return Err(EscrowError::Invalid(format!(
                "anchor binding does not match the record prefix at seq {}",
                self.upto_seq
            )));
        }
        let message = Self::signing_bytes(self.upto_seq, &self.binding, self.ts)?;
        let signature = BASE64
            .decode(&self.signature)
            .map_err(|e| EscrowError::Invalid(format!("anchor sig b64: {e}")))?;
        let public_key = hex_decode(&self.public_key_hex)?;
        auths_crypto::typed_verify(CurveType::P256, &public_key, &message, &signature)
            .map_err(|_| EscrowError::Invalid("anchor signature did not verify".to_string()))
    }
}

/// The escrow record: the chained events plus the anchors that give them time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowRecord {
    /// Always `"escrow/v1"`.
    pub version: String,
    /// The deal id — the binding of `r₀` (content-addressed, collision-free).
    pub id: String,
    /// The chained events, in order.
    pub events: Vec<EscrowEvent>,
    /// Time anchors over prefixes, in commit order.
    pub anchors: Vec<EscrowAnchor>,
}

/// A party's signing key (seed + did) — held by that party's tooling only.
pub struct PartyKey {
    seed: TypedSeed,
    /// The signer's `did:key:`.
    pub did: String,
}

impl PartyKey {
    /// Generate a fresh party key on the given curve.
    pub fn generate(curve: CurveType) -> Result<Self, EscrowError> {
        let (seed, public_key) =
            auths_crypto::typed_generate(curve).map_err(|e| EscrowError::Signing(e.to_string()))?;
        Ok(PartyKey {
            seed,
            did: crate::escrow::did_key_of(curve, &public_key),
        })
    }

    /// Build a party key from a 32-byte hex seed.
    pub fn from_seed_hex(seed_hex: &str, curve: CurveType) -> Result<Self, EscrowError> {
        let bytes = hex_decode(seed_hex)?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| EscrowError::Signing("seed must be 32 bytes".to_string()))?;
        let seed = TypedSeed::from_curve(curve, seed);
        let public_key =
            auths_crypto::typed_public_key(&seed).map_err(|e| EscrowError::Signing(e.to_string()))?;
        Ok(PartyKey {
            seed,
            did: crate::escrow::did_key_of(curve, &public_key),
        })
    }

    /// Sign an event's canonical body.
    pub fn sign_event(
        &self,
        seq: u64,
        prev: &str,
        at: DateTime<Utc>,
        body: &EscrowEventBody,
    ) -> Result<PartySig, EscrowError> {
        let message = event_signing_bytes(seq, prev, at, body)?;
        let signature = auths_crypto::typed_sign(&self.seed, &message)
            .map_err(|e| EscrowError::Signing(e.to_string()))?;
        Ok(PartySig {
            signer: self.did.clone(),
            sig: BASE64.encode(signature),
        })
    }
}

/// `did:key:` of a raw public key (delegates to the evidence layer's encoder).
pub fn did_key_of(curve: CurveType, public_key: &[u8]) -> String {
    auths_evidence::did_key_encode(curve, public_key)
}

fn event_signing_bytes(
    seq: u64,
    prev: &str,
    at: DateTime<Utc>,
    body: &EscrowEventBody,
) -> Result<Vec<u8>, EscrowError> {
    let value = serde_json::json!({ "seq": seq, "prev": prev, "at": at, "body": body });
    json_canon::to_string(&value)
        .map(String::into_bytes)
        .map_err(|e| EscrowError::Invalid(format!("event canon: {e}")))
}

fn event_binding(prev: &str, event: &EscrowEvent) -> Result<String, EscrowError> {
    let canon = json_canon::to_string(event)
        .map_err(|e| EscrowError::Invalid(format!("event canon: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(canon.as_bytes());
    Ok(hex_encode(&hasher.finalize()))
}

fn verify_party_sig(sig: &PartySig, message: &[u8]) -> Result<(), EscrowError> {
    let decoded = did_key_decode(&sig.signer)
        .map_err(|e| EscrowError::Invalid(format!("signer did: {e}")))?;
    let raw = BASE64
        .decode(&sig.sig)
        .map_err(|e| EscrowError::Invalid(format!("sig b64: {e}")))?;
    let public_key = match &decoded {
        DecodedDidKey::Ed25519(pk) => pk.as_slice(),
        DecodedDidKey::P256(pk) => pk.as_slice(),
    };
    auths_crypto::typed_verify(decoded.curve(), public_key, message, &raw)
        .map_err(|_| EscrowError::Invalid(format!("signature by {} did not verify", sig.signer)))
}

/// Per-milestone derived state, read out of the verified record.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MilestoneState {
    /// The delivery event's seq, when delivered.
    pub delivered_seq: Option<u64>,
    /// The objection event's seq, when objected.
    pub objected_seq: Option<u64>,
    /// The release event's seq, when the buyer released.
    pub released_seq: Option<u64>,
    /// The recorded ruling outcome, when the arbiter ruled.
    pub ruling: Option<RulingOutcome>,
}

impl EscrowRecord {
    /// Open a deal: validate the schedule, require BOTH party signatures over
    /// `r₀`, and seal the record. `anchor_cadence_secs` is the deployment's
    /// measured anchor cadence — every `wᵢ` must exceed it so the window is
    /// decidable from committed heads (design D3).
    ///
    /// Args:
    /// * `body`: the `Open` body.
    /// * `sigs`: both parties' signatures over `r₀`.
    /// * `at`: the open instant (injected clock).
    /// * `anchor_cadence_secs`: the deployment's anchor cadence lower bound.
    ///
    /// Usage:
    /// ```ignore
    /// let record = EscrowRecord::open(body, vec![buyer_sig, seller_sig], now, 5)?;
    /// ```
    pub fn open(
        body: EscrowEventBody,
        sigs: Vec<PartySig>,
        at: DateTime<Utc>,
        anchor_cadence_secs: u64,
    ) -> Result<Self, EscrowError> {
        let EscrowEventBody::Open {
            buyer,
            seller,
            mode,
            milestones,
            t_end,
            ..
        } = &body
        else {
            return Err(EscrowError::Rejected("r₀ must be an Open event".to_string()));
        };
        if *mode == EscrowMode::Locked {
            return Err(EscrowError::Rejected(
                "locked mode is contract-gated and not yet available (reserved mode ships first)"
                    .to_string(),
            ));
        }
        if milestones.is_empty() {
            return Err(EscrowError::Rejected("no milestones".to_string()));
        }
        for (index, milestone) in milestones.iter().enumerate() {
            if milestone.objection_window_secs <= anchor_cadence_secs {
                return Err(EscrowError::Rejected(format!(
                    "milestone {index}: objection window {}s must exceed the anchor cadence {}s",
                    milestone.objection_window_secs, anchor_cadence_secs
                )));
            }
            let window_end = milestone.deliver_by
                + chrono::Duration::seconds(milestone.objection_window_secs as i64);
            if *t_end < window_end {
                return Err(EscrowError::Rejected(format!(
                    "milestone {index}: T_end precedes the deadline + objection window"
                )));
            }
        }
        let message = event_signing_bytes(0, ESCROW_GENESIS, at, &body)?;
        for required in [&buyer.did, &seller.did] {
            let sig = sigs
                .iter()
                .find(|s| &s.signer == required)
                .ok_or_else(|| EscrowError::Rejected(format!("missing signature by {required}")))?;
            verify_party_sig(sig, &message)?;
        }
        let event = EscrowEvent {
            seq: 0,
            prev: ESCROW_GENESIS.to_string(),
            at,
            body,
            sigs,
        };
        let id = event_binding(ESCROW_GENESIS, &event)?;
        Ok(EscrowRecord {
            version: ESCROW_VERSION.to_string(),
            id,
            events: vec![event],
            anchors: Vec::new(),
        })
    }

    /// The `Open` body (validated to exist by construction).
    pub fn open_terms(&self) -> Result<&EscrowEventBody, EscrowError> {
        self.events
            .first()
            .map(|e| &e.body)
            .ok_or_else(|| EscrowError::Invalid("empty record".to_string()))
    }

    fn parties(&self) -> Result<(Party, Party, Option<String>, Vec<Milestone>), EscrowError> {
        match self.open_terms()? {
            EscrowEventBody::Open {
                buyer,
                seller,
                arbiter,
                milestones,
                ..
            } => Ok((
                buyer.clone(),
                seller.clone(),
                arbiter.clone(),
                milestones.clone(),
            )),
            _ => Err(EscrowError::Invalid("r₀ is not an Open event".to_string())),
        }
    }

    /// The record's current binding head.
    pub fn head(&self) -> String {
        self.events
            .iter()
            .try_fold(ESCROW_GENESIS.to_string(), |prev, event| {
                event_binding(&prev, event)
            })
            .unwrap_or_else(|_: EscrowError| ESCROW_GENESIS.to_string())
    }

    /// The binding head of the prefix ending at `seq`.
    pub fn binding_at(&self, seq: u64) -> Result<String, EscrowError> {
        let mut prev = ESCROW_GENESIS.to_string();
        for event in &self.events {
            prev = event_binding(&prev, event)?;
            if event.seq == seq {
                return Ok(prev);
            }
        }
        Err(EscrowError::Invalid(format!("no event at seq {seq}")))
    }

    /// Append one event: validate seq/prev continuity, the signature the kind
    /// requires, and the state machine (no delivery after release, only the named
    /// arbiter rules, etc.).
    pub fn append(&mut self, event: EscrowEvent) -> Result<(), EscrowError> {
        let (buyer, seller, arbiter, milestones) = self.parties()?;
        let expected_seq = self.events.len() as u64;
        if event.seq != expected_seq {
            return Err(EscrowError::Rejected(format!(
                "seq {} out of order (expected {expected_seq})",
                event.seq
            )));
        }
        if event.prev != self.head() {
            return Err(EscrowError::Rejected("prev does not match the head".to_string()));
        }
        let message = event_signing_bytes(event.seq, &event.prev, event.at, &event.body)?;
        let milestone_of = |index: usize| -> Result<&Milestone, EscrowError> {
            milestones
                .get(index)
                .ok_or_else(|| EscrowError::Rejected(format!("no milestone {index}")))
        };
        let require_signer = |required: &str| -> Result<(), EscrowError> {
            let sig = event
                .sigs
                .iter()
                .find(|s| s.signer == required)
                .ok_or_else(|| {
                    EscrowError::Rejected(format!("event requires a signature by {required}"))
                })?;
            verify_party_sig(sig, &message)
        };
        match &event.body {
            EscrowEventBody::Open { .. } => {
                return Err(EscrowError::Rejected("Open only at r₀".to_string()));
            }
            EscrowEventBody::Deliver { milestone, .. } => {
                milestone_of(*milestone)?;
                require_signer(&seller.did)?;
            }
            EscrowEventBody::Object { milestone, .. } => {
                milestone_of(*milestone)?;
                require_signer(&buyer.did)?;
            }
            EscrowEventBody::Release { milestone, .. } => {
                milestone_of(*milestone)?;
                // S2: ONLY the buyer's signature settles a slice.
                require_signer(&buyer.did)?;
            }
            EscrowEventBody::Ruling { milestone, .. } => {
                milestone_of(*milestone)?;
                let arbiter = arbiter.ok_or_else(|| {
                    EscrowError::Rejected("no arbiter was named at open".to_string())
                })?;
                require_signer(&arbiter)?;
            }
        }
        self.events.push(event);
        Ok(())
    }

    /// Attach a verified anchor (the pin stores it; the rule track reads its time).
    pub fn attach_anchor(&mut self, anchor: EscrowAnchor, pinned_key_hex: &str) -> Result<(), EscrowError> {
        anchor.verify(self, pinned_key_hex)?;
        self.anchors.push(anchor);
        Ok(())
    }

    /// Fully re-verify the record by value: chain continuity, every signature,
    /// the state machine, and every anchor — what `verifyEscrowRecord` runs on a
    /// record that arrived from a stranger.
    ///
    /// Args:
    /// * `pinned_anchor_key_hex`: the anchor committer key to pin, when the caller
    ///   has one; anchors failing the pin are rejected.
    ///
    /// Usage:
    /// ```ignore
    /// let verified = EscrowRecord::verify_value(&raw_json, Some(&anchor_key))?;
    /// ```
    pub fn verify_value(
        raw: &serde_json::Value,
        pinned_anchor_key_hex: Option<&str>,
    ) -> Result<EscrowRecord, EscrowError> {
        let record: EscrowRecord = serde_json::from_value(raw.clone())
            .map_err(|e| EscrowError::Invalid(format!("parse: {e}")))?;
        if record.version != ESCROW_VERSION {
            return Err(EscrowError::Invalid(format!(
                "unknown version {}",
                record.version
            )));
        }
        let Some(first) = record.events.first() else {
            return Err(EscrowError::Invalid("empty record".to_string()));
        };
        let expected_id = event_binding(ESCROW_GENESIS, first)?;
        if record.id != expected_id {
            return Err(EscrowError::Invalid("id does not match r₀".to_string()));
        }
        // Rebuild through the append path so every event passes the same checks.
        let mut rebuilt = EscrowRecord {
            version: record.version.clone(),
            id: record.id.clone(),
            events: vec![first.clone()],
            anchors: Vec::new(),
        };
        // r₀'s own signatures.
        let (buyer, seller, _, _) = rebuilt.parties()?;
        let message = event_signing_bytes(first.seq, &first.prev, first.at, &first.body)?;
        for required in [&buyer.did, &seller.did] {
            let sig = first
                .sigs
                .iter()
                .find(|s| &s.signer == required)
                .ok_or_else(|| EscrowError::Invalid(format!("r₀ missing signature by {required}")))?;
            verify_party_sig(sig, &message)?;
        }
        for event in record.events.iter().skip(1) {
            rebuilt.append(event.clone()).map_err(|e| {
                EscrowError::Invalid(format!("event {} does not re-verify: {e}", event.seq))
            })?;
        }
        for anchor in &record.anchors {
            match pinned_anchor_key_hex {
                Some(pinned) => rebuilt.attach_anchor(anchor.clone(), pinned)?,
                None => {
                    // Without a pin the anchor's key is trust-on-first-seen; it must
                    // still self-verify against the record.
                    let key = anchor.public_key_hex.clone();
                    rebuilt.attach_anchor(anchor.clone(), &key)?;
                }
            }
        }
        Ok(rebuilt)
    }

    /// Derive per-milestone state from the verified events.
    pub fn milestone_state(&self, index: usize) -> MilestoneState {
        let mut state = MilestoneState::default();
        for event in &self.events {
            match &event.body {
                EscrowEventBody::Deliver { milestone, .. } if *milestone == index => {
                    state.delivered_seq.get_or_insert(event.seq);
                }
                EscrowEventBody::Object { milestone, .. } if *milestone == index => {
                    state.objected_seq.get_or_insert(event.seq);
                }
                EscrowEventBody::Release { milestone, .. } if *milestone == index => {
                    state.released_seq.get_or_insert(event.seq);
                }
                EscrowEventBody::Ruling {
                    milestone, outcome, ..
                } if *milestone == index => {
                    state.ruling.get_or_insert(outcome.clone());
                }
                _ => {}
            }
        }
        state
    }

    /// The earliest anchor covering `seq` — the event's committed time (S1).
    fn anchored_at(&self, seq: u64) -> Option<DateTime<Utc>> {
        self.anchors
            .iter()
            .filter(|anchor| anchor.upto_seq >= seq)
            .map(|anchor| anchor.ts)
            .min()
    }

    /// The latest anchor instant — the record's decidability horizon.
    fn latest_anchor(&self) -> Option<&EscrowAnchor> {
        self.anchors.iter().max_by_key(|anchor| anchor.ts)
    }
}

/// The rule-track proof: which anchored facts decided the outcome.
#[derive(Debug, Clone, Serialize)]
pub struct RuleProof {
    /// The milestone judged.
    pub milestone: usize,
    /// The delivery's anchored instant, when one exists.
    pub delivered_anchored_at: Option<DateTime<Utc>>,
    /// The objection's anchored instant, when one exists.
    pub objection_anchored_at: Option<DateTime<Utc>>,
    /// The horizon anchor the absence claims are relative to.
    pub horizon: Option<DateTime<Utc>>,
    /// The deadline `dᵢ`.
    pub deliver_by: DateTime<Utc>,
    /// The objection window end, when a delivery is anchored.
    pub window_end: Option<DateTime<Utc>>,
}

/// A rule-track evaluation: the outcome plus the anchored facts that decided it.
#[derive(Debug, Clone, Serialize)]
pub struct RuleEvaluation {
    /// The outcome.
    pub outcome: RulingOutcome,
    /// Why — as anchored facts, offline-checkable.
    pub proof: RuleProof,
}

/// Evaluate milestone `index` on the rule track — a total function of ANCHORED
/// facts only (§RC-E4.0):
///
/// * **releasable-by-rule** — a delivery anchored before `dᵢ`, and a later anchor
///   (≥ delivery + `wᵢ`) whose covered record contains no objection (the
///   anchored-absence proof).
/// * **refundable-by-rule** — an anchor ≥ `dᵢ` whose covered record contains no
///   delivery.
/// * A timely anchored objection → the subjective branch (`NeedsArbiter`).
/// * Anything not yet decidable from committed heads → `Hold`.
///
/// Args:
/// * `record`: the verified record.
/// * `index`: the milestone.
///
/// Usage:
/// ```ignore
/// let eval = evaluate_rule_track(&record, 0)?;
/// ```
pub fn evaluate_rule_track(
    record: &EscrowRecord,
    index: usize,
) -> Result<RuleEvaluation, EscrowError> {
    let (_, _, _, milestones) = record.parties()?;
    let milestone = milestones
        .get(index)
        .ok_or_else(|| EscrowError::Unestablished(format!("no milestone {index}")))?;
    let state = record.milestone_state(index);
    let horizon = record.latest_anchor().map(|anchor| anchor.ts);

    let delivered_anchored_at = state.delivered_seq.and_then(|seq| record.anchored_at(seq));
    let objection_anchored_at = state.objected_seq.and_then(|seq| record.anchored_at(seq));
    let window = chrono::Duration::seconds(milestone.objection_window_secs as i64);

    let proof = RuleProof {
        milestone: index,
        delivered_anchored_at,
        objection_anchored_at,
        horizon,
        deliver_by: milestone.deliver_by,
        window_end: delivered_anchored_at.map(|at| at + window),
    };

    let outcome = match delivered_anchored_at {
        Some(delivered_at) if delivered_at <= milestone.deliver_by => {
            let window_end = delivered_at + window;
            // A timely, ANCHORED objection converts to the subjective branch. A
            // late objection (anchored past the window) is ignored by rule.
            let timely_objection =
                objection_anchored_at.is_some_and(|objected_at| objected_at <= window_end);
            if timely_objection {
                RulingOutcome::NeedsArbiter
            } else if horizon.is_some_and(|h| h >= window_end) {
                // The horizon anchor commits a record with no timely objection —
                // the anchored-absence proof.
                RulingOutcome::Release
            } else {
                RulingOutcome::Hold
            }
        }
        _ => {
            // No anchored delivery. Refundable once an anchor past dᵢ commits a
            // record with no delivery; otherwise the window is still open.
            if horizon.is_some_and(|h| h >= milestone.deliver_by) {
                RulingOutcome::Refund
            } else {
                RulingOutcome::Hold
            }
        }
    };
    Ok(RuleEvaluation { outcome, proof })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, EscrowError> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(EscrowError::Invalid("odd-length hex".to_string()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| EscrowError::Invalid(format!("bad hex: {e}")))
        })
        .collect()
}
