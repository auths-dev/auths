//! The fleet treasury — ONE spending cap across N gateway processes.
//!
//! N delegations for throughput means N split budgets unless something outside every
//! gateway process holds the fleet-wide counter. This module is that counter's domain
//! logic: a monotonic [`FleetLedger`] the coordinator serves, the line-protocol wire
//! types the gateways speak to it, and the signed [`TreasuryCheckpoint`] trail that
//! anchors `{fleet, count, cumulative}` outside any single operator's process so
//! `verify-spend` can cross-check the fleet's re-derived totals against it.
//!
//! Enforcement stance: a reservation COMMITS on grant — the fleet counter rises the
//! moment capacity is granted, so a crashed gateway can never have spent capacity the
//! coordinator did not count. Gateways that cannot reach the coordinator fall back to
//! their local (smaller) budget — fail-closed to the tighter cap, never open.
//!
//! This module is pure domain state + wire shapes: no sockets, no clocks, no files.
//! The gateway binary owns the TCP loop, persistence, and checkpoint cadence.

use crate::Cents;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from fleet-ledger restoration and checkpoint verification.
#[derive(Debug, Error)]
pub enum TreasuryError {
    /// A checkpoint line was not valid JSON or missed required fields.
    #[error("malformed checkpoint line {line}: {reason}")]
    Malformed { line: usize, reason: String },
    /// A checkpoint's signature did not verify under its embedded public key.
    #[error("checkpoint line {line}: signature invalid")]
    BadSignature { line: usize },
    /// A checkpoint's signer differed from the expected (or first-seen) public key.
    #[error("checkpoint line {line}: signer changed mid-trail")]
    SignerChanged { line: usize },
    /// A later checkpoint reported a lower count or cumulative than an earlier one.
    #[error("checkpoint line {line}: {what} regressed ({later} < {earlier})")]
    Rollback {
        line: usize,
        what: &'static str,
        earlier: u64,
        later: u64,
    },
    /// The trail was empty — nothing to cross-check against.
    #[error("checkpoint trail is empty")]
    Empty,
    /// The final cumulative did not equal the total the caller re-derived from logs.
    #[error(
        "cumulative mismatch: checkpoints say {checkpointed} cents, logs re-derive {rederived}"
    )]
    CumulativeMismatch { checkpointed: u64, rederived: u64 },
}

/// The one fleet-wide counter: a cap, the monotonic committed total, and the grant count.
///
/// Args:
/// * `cap_cents`: the fleet cap — the total the whole fleet may spend.
///
/// Usage:
/// ```ignore
/// let mut ledger = FleetLedger::new(Cents::new(500));
/// match ledger.reserve(Cents::new(120)) {
///     FleetReserveOutcome::Granted { headroom_cents } => { /* forward the call */ }
///     FleetReserveOutcome::Refused { .. } => { /* usage-cap-exceeded */ }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetLedger {
    cap_cents: Cents,
    settled_cents: Cents,
    count: u64,
}

/// The outcome of one fleet reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetReserveOutcome {
    /// Capacity granted and committed; `headroom_cents` remains for the fleet.
    Granted { headroom_cents: Cents },
    /// The reservation would cross the fleet cap — refused before any rail is touched.
    Refused {
        cap_cents: Cents,
        would_be_cents: Cents,
    },
}

impl FleetLedger {
    /// Start a fresh ledger at zero spend under `cap_cents`.
    ///
    /// Args:
    /// * `cap_cents`: the fleet-wide cap.
    ///
    /// Usage:
    /// ```ignore
    /// let ledger = FleetLedger::new(Cents::new(500));
    /// ```
    pub fn new(cap_cents: Cents) -> Self {
        FleetLedger {
            cap_cents,
            settled_cents: Cents::ZERO,
            count: 0,
        }
    }

    /// Restore a persisted ledger — the coordinator's restart path. The committed
    /// total only ever rises, so a restart resumes from the durable high-water.
    ///
    /// Args:
    /// * `cap_cents`: the fleet cap in force.
    /// * `settled_cents`: the persisted committed total.
    /// * `count`: the persisted grant count.
    ///
    /// Usage:
    /// ```ignore
    /// let ledger = FleetLedger::restore(cap, persisted.settled_cents(), persisted.count());
    /// ```
    pub fn restore(cap_cents: Cents, settled_cents: Cents, count: u64) -> Self {
        FleetLedger {
            cap_cents,
            settled_cents,
            count,
        }
    }

    /// Reserve `cents` against the fleet cap; a grant COMMITS immediately.
    ///
    /// Args:
    /// * `cents`: the ceiling this call pre-authorizes.
    ///
    /// Usage:
    /// ```ignore
    /// let outcome = ledger.reserve(Cents::new(3));
    /// ```
    pub fn reserve(&mut self, cents: Cents) -> FleetReserveOutcome {
        let would_be = self.settled_cents.saturating_add(cents);
        if would_be > self.cap_cents {
            return FleetReserveOutcome::Refused {
                cap_cents: self.cap_cents,
                would_be_cents: would_be,
            };
        }
        self.settled_cents = would_be;
        self.count += 1;
        FleetReserveOutcome::Granted {
            headroom_cents: Cents::new(self.cap_cents.get() - self.settled_cents.get()),
        }
    }

    /// The committed fleet total.
    pub fn settled_cents(&self) -> Cents {
        self.settled_cents
    }

    /// The number of grants committed.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The cap in force.
    pub fn cap_cents(&self) -> Cents {
        self.cap_cents
    }
}

/// One request line a gateway sends the coordinator (JSON, newline-delimited).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum TreasuryRequest {
    /// Reserve `cents` of fleet capacity for one call by `delegation`.
    Reserve {
        fleet: String,
        delegation: String,
        cents: Cents,
    },
    /// Read the fleet counter without reserving.
    Status { fleet: String },
}

/// One reply line the coordinator sends back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum TreasuryReply {
    /// Capacity granted and committed.
    Granted { headroom_cents: Cents },
    /// The reservation would cross the fleet cap.
    Refused {
        cap_cents: Cents,
        would_be_cents: Cents,
    },
    /// The current counter.
    Status {
        fleet: String,
        count: u64,
        settled_cents: Cents,
        cap_cents: Cents,
    },
    /// The request could not be served (wrong fleet, malformed line).
    Error { reason: String },
}

/// The payload a coordinator signs on a cadence: the fleet's running totals at `at`.
///
/// Signed over its canonical JSON (json-canon), so any holder can re-derive the exact
/// bytes from the fields alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryCheckpoint {
    /// The fleet this trail counts for (the delegator root AID by default).
    pub fleet: String,
    /// Grants committed so far.
    pub count: u64,
    /// The committed fleet total in cents.
    pub cumulative_cents: Cents,
    /// When the coordinator took this snapshot.
    pub at: DateTime<Utc>,
}

impl TreasuryCheckpoint {
    /// The exact bytes the coordinator signs — canonical JSON of the payload.
    ///
    /// Usage:
    /// ```ignore
    /// let sig = RingCryptoProvider::p256_sign(seed.as_bytes(), &checkpoint.signing_bytes()?)?;
    /// ```
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let value = serde_json::to_value(self)?;
        json_canon::to_string(&value).map(String::into_bytes)
    }
}

/// One line of the checkpoint trail: the payload plus its P-256 signature, both keys hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreasuryCheckpoint {
    /// The signed payload.
    #[serde(flatten)]
    pub checkpoint: TreasuryCheckpoint,
    /// The coordinator's compressed P-256 public key, hex.
    pub public_key_hex: String,
    /// The P-256 signature over [`TreasuryCheckpoint::signing_bytes`], hex.
    pub signature_hex: String,
}

/// Decode a hex string into bytes.
///
/// Args:
/// * `hex`: an even-length lowercase/uppercase hex string.
///
/// Usage:
/// ```ignore
/// let bytes = decode_hex(&signed.signature_hex)?;
/// ```
pub fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Encode bytes as lowercase hex.
///
/// Args:
/// * `bytes`: the raw bytes.
///
/// Usage:
/// ```ignore
/// let hex = encode_hex(&public_key);
/// ```
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify a checkpoint trail: every signature valid, one stable signer, counts and
/// cumulative monotonic. Returns the FINAL checkpoint for cross-checking.
///
/// Args:
/// * `lines`: the trail, one signed-checkpoint JSON object per line.
/// * `expect_pubkey_hex`: pin the signer; `None` accepts the first line's key.
/// * `verify`: the signature verifier `(pubkey, message, signature) -> bool`.
///
/// Usage:
/// ```ignore
/// let last = verify_checkpoint_trail(&lines, None, |pk, m, s| {
///     RingCryptoProvider::p256_verify(pk, m, s).is_ok()
/// })?;
/// ```
pub fn verify_checkpoint_trail(
    lines: &[String],
    expect_pubkey_hex: Option<&str>,
    verify: impl Fn(&[u8], &[u8], &[u8]) -> bool,
) -> Result<TreasuryCheckpoint, TreasuryError> {
    let mut pinned: Option<String> = expect_pubkey_hex.map(str::to_string);
    let mut last: Option<TreasuryCheckpoint> = None;
    for (idx, raw) in lines.iter().enumerate() {
        let line = idx + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let signed: SignedTreasuryCheckpoint =
            serde_json::from_str(raw).map_err(|e| TreasuryError::Malformed {
                line,
                reason: e.to_string(),
            })?;
        match &pinned {
            Some(p) if *p != signed.public_key_hex => {
                return Err(TreasuryError::SignerChanged { line });
            }
            Some(_) => {}
            None => pinned = Some(signed.public_key_hex.clone()),
        }
        let pubkey =
            decode_hex(&signed.public_key_hex).map_err(|reason| TreasuryError::Malformed {
                line,
                reason: format!("public_key_hex: {reason}"),
            })?;
        let sig = decode_hex(&signed.signature_hex).map_err(|reason| TreasuryError::Malformed {
            line,
            reason: format!("signature_hex: {reason}"),
        })?;
        let message = signed
            .checkpoint
            .signing_bytes()
            .map_err(|e| TreasuryError::Malformed {
                line,
                reason: format!("canonicalize: {e}"),
            })?;
        if !verify(&pubkey, &message, &sig) {
            return Err(TreasuryError::BadSignature { line });
        }
        if let Some(prev) = &last {
            if signed.checkpoint.count < prev.count {
                return Err(TreasuryError::Rollback {
                    line,
                    what: "count",
                    earlier: prev.count,
                    later: signed.checkpoint.count,
                });
            }
            if signed.checkpoint.cumulative_cents < prev.cumulative_cents {
                return Err(TreasuryError::Rollback {
                    line,
                    what: "cumulative_cents",
                    earlier: prev.cumulative_cents.get(),
                    later: signed.checkpoint.cumulative_cents.get(),
                });
            }
        }
        last = Some(signed.checkpoint);
    }
    last.ok_or(TreasuryError::Empty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_crypto::ring_provider::RingCryptoProvider;
    use chrono::TimeZone;

    fn signed(
        seed: &auths_crypto::SecureSeed,
        pubkey: &[u8],
        fleet: &str,
        count: u64,
        cumulative: u64,
    ) -> String {
        let checkpoint = TreasuryCheckpoint {
            fleet: fleet.to_string(),
            count,
            cumulative_cents: Cents::new(cumulative),
            at: Utc.timestamp_opt(1_700_000_000 + count as i64, 0).unwrap(),
        };
        let sig =
            RingCryptoProvider::p256_sign(seed.as_bytes(), &checkpoint.signing_bytes().unwrap())
                .unwrap();
        serde_json::to_string(&SignedTreasuryCheckpoint {
            checkpoint,
            public_key_hex: encode_hex(pubkey),
            signature_hex: encode_hex(&sig),
        })
        .unwrap()
    }

    #[test]
    fn reserve_commits_on_grant_and_refuses_past_cap() {
        let mut ledger = FleetLedger::new(Cents::new(10));
        assert!(matches!(
            ledger.reserve(Cents::new(6)),
            FleetReserveOutcome::Granted { headroom_cents } if headroom_cents == Cents::new(4)
        ));
        assert!(matches!(
            ledger.reserve(Cents::new(5)),
            FleetReserveOutcome::Refused { cap_cents, would_be_cents }
                if cap_cents == Cents::new(10) && would_be_cents == Cents::new(11)
        ));
        assert_eq!(ledger.settled_cents(), Cents::new(6));
        assert_eq!(ledger.count(), 1);
    }

    #[test]
    fn restore_resumes_the_high_water() {
        let mut ledger = FleetLedger::restore(Cents::new(10), Cents::new(9), 3);
        assert!(matches!(
            ledger.reserve(Cents::new(2)),
            FleetReserveOutcome::Refused { .. }
        ));
    }

    #[test]
    fn checkpoint_trail_verifies_and_catches_tamper() {
        let (seed, pubkey) = RingCryptoProvider::p256_generate().unwrap();
        let lines = vec![
            signed(&seed, &pubkey, "did:keri:Eroot", 1, 3),
            signed(&seed, &pubkey, "did:keri:Eroot", 2, 6),
        ];
        let last = verify_checkpoint_trail(&lines, None, |pk, m, s| {
            RingCryptoProvider::p256_verify(pk, m, s).is_ok()
        })
        .unwrap();
        assert_eq!(last.count, 2);
        assert_eq!(last.cumulative_cents, Cents::new(6));

        let tampered = vec![lines[0].replace("\"cumulative_cents\":3", "\"cumulative_cents\":1")];
        assert!(matches!(
            verify_checkpoint_trail(&tampered, None, |pk, m, s| {
                RingCryptoProvider::p256_verify(pk, m, s).is_ok()
            }),
            Err(TreasuryError::BadSignature { .. })
        ));
    }

    #[test]
    fn checkpoint_trail_refuses_rollback() {
        let (seed, pubkey) = RingCryptoProvider::p256_generate().unwrap();
        let lines = vec![
            signed(&seed, &pubkey, "f", 2, 6),
            signed(&seed, &pubkey, "f", 1, 3),
        ];
        assert!(matches!(
            verify_checkpoint_trail(&lines, None, |pk, m, s| {
                RingCryptoProvider::p256_verify(pk, m, s).is_ok()
            }),
            Err(TreasuryError::Rollback { .. })
        ));
    }
}
