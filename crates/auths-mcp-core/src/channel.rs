//! Payment channels — reserve → stream → settle, with the spend log as the state.
//!
//! The spend log's agent-signed running cumulative already IS a payment-channel
//! state update, and `verify-spend` already IS the closing proof. This module adds
//! only the ends: the OPEN record (a capacity reservation the gateway meters
//! against with zero rail touches per call) and the CLOSE record (the netted
//! settlement evidence a receipts worker re-derives, citing the exact `log_hash`
//! it was computed from).
//!
//! Custody stance (decided): the market is never a treasurer. Rail-touching legs
//! (a Stripe Connect direct-charge capture, an on-chain channel contract) live
//! OUTSIDE these records — this module produces the evidence both sides settle
//! on, never a held balance.

use crate::Cents;
use crate::treasury::encode_hex;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A channel's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChannelState {
    /// Reserved capacity the gateway meters against.
    Open,
    /// Closed with a netted settlement record emitted.
    Settled,
}

/// The OPEN side: a funded (or explicitly unfunded) capacity reservation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRecord {
    /// Deterministic channel id (hash of seller, rail, capacity, opened_at).
    pub channel_id: String,
    /// The seller this channel streams to.
    pub seller: String,
    /// The rail the channel settles on at close.
    pub rail: String,
    /// The reserved capacity the gateway meters against.
    pub capacity_cents: Cents,
    /// Where the hold lives — a rail reference, or a stated `unfunded:` posture.
    pub escrow_ref: String,
    /// When the channel opened.
    pub opened_at: DateTime<Utc>,
    /// Lifecycle state.
    pub state: ChannelState,
}

impl ChannelRecord {
    /// Open a channel: derive the deterministic id and record the reservation.
    ///
    /// Args:
    /// * `seller`: the seller identity the channel streams to.
    /// * `rail`: the settling rail (`x402` / `stripe`).
    /// * `capacity_cents`: the reserved capacity.
    /// * `escrow_ref`: the rail hold reference, or the stated unfunded posture.
    /// * `opened_at`: injected clock.
    ///
    /// Usage:
    /// ```ignore
    /// let channel = ChannelRecord::open("did:keri:Eseller", "x402", Cents::new(5000),
    ///     "unfunded:x402:credentials-absent", now);
    /// ```
    pub fn open(
        seller: &str,
        rail: &str,
        capacity_cents: Cents,
        escrow_ref: &str,
        opened_at: DateTime<Utc>,
    ) -> ChannelRecord {
        let mut hasher = Sha256::new();
        hasher.update(seller.as_bytes());
        hasher.update(rail.as_bytes());
        hasher.update(capacity_cents.get().to_be_bytes());
        hasher.update(opened_at.timestamp_micros().to_be_bytes());
        let digest = hasher.finalize();
        ChannelRecord {
            channel_id: encode_hex(&digest[..16]),
            seller: seller.to_string(),
            rail: rail.to_string(),
            capacity_cents,
            escrow_ref: escrow_ref.to_string(),
            opened_at,
            state: ChannelState::Open,
        }
    }
}

/// The CLOSE side: the netted settlement evidence, citing its exact log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSettlement {
    /// The channel this settles.
    pub channel_id: String,
    /// The settling rail.
    pub rail: String,
    /// The netted total: `min(re-derived cumulative, capacity)` — one rail action.
    pub gross_cents: Cents,
    /// SHA-256 of the exact spend-log bytes the total was re-derived from.
    pub log_hash: String,
    /// Calls in the log at settlement.
    pub calls: u64,
    /// When the settlement evidence was emitted.
    pub settled_at: DateTime<Utc>,
}

/// The netted close amount: the channel settles `min(cumulative, capacity)` in ONE
/// rail action — streamed spend beyond the reserved capacity never settles.
///
/// Args:
/// * `cumulative_cents`: the log's re-derived running total.
/// * `capacity_cents`: the channel's reserved capacity.
///
/// Usage:
/// ```ignore
/// let net = netted_settle_cents(Cents::new(137), Cents::new(100));
/// assert_eq!(net, Cents::new(100));
/// ```
pub fn netted_settle_cents(cumulative_cents: Cents, capacity_cents: Cents) -> Cents {
    cumulative_cents.min(capacity_cents)
}

/// SHA-256 of the spend-log bytes, hex — the citation every fee row carries.
///
/// Args:
/// * `log_bytes`: the raw spend-log file contents.
///
/// Usage:
/// ```ignore
/// let hash = spend_log_hash(&std::fs::read(&log_path)?);
/// ```
pub fn spend_log_hash(log_bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(log_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn open_derives_a_stable_id_and_starts_open() {
        let at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let a = ChannelRecord::open("did:keri:Es", "x402", Cents::new(5000), "ref", at);
        let b = ChannelRecord::open("did:keri:Es", "x402", Cents::new(5000), "ref", at);
        assert_eq!(a.channel_id, b.channel_id);
        assert_eq!(a.state, ChannelState::Open);
        assert_eq!(a.channel_id.len(), 32);
    }

    #[test]
    fn netted_settle_is_bounded_by_capacity() {
        assert_eq!(
            netted_settle_cents(Cents::new(137), Cents::new(100)),
            Cents::new(100)
        );
        assert_eq!(
            netted_settle_cents(Cents::new(40), Cents::new(100)),
            Cents::new(40)
        );
    }
}
