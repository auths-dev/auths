//! The `channel` subcommand — open a metered reservation, close with one netted settle.
//!
//! `channel open` records the funded reservation the gateway meters against with
//! ZERO rail touches per call; `channel close` re-derives the streamed total from
//! the signed spend log and emits the netted settlement record (citing the exact
//! `log_hash`) that the receipts worker re-derives.
//!
//! Rail legs are env-gated and never faked (custody-never): absent credentials
//! record an explicitly `unfunded:` reservation with a stated reason; present
//! credentials still route the actual money movement through the non-custodial
//! leg that owns it (Stripe Connect direct charges on the seller's account, or
//! the x402 channel contract) keyed to the settlement evidence emitted here.

use anyhow::Context;
use auths_mcp_core::channel::{ChannelRecord, ChannelSettlement, ChannelState};
use auths_mcp_core::{Cents, netted_settle_cents, read_spend_log, spend_log_hash};
use chrono::Utc;
use std::path::{Path, PathBuf};

/// Where channel records live under the live dir.
fn channels_dir(live_dir: &Path) -> PathBuf {
    live_dir.join("channels")
}

/// The stated escrow posture for a rail, judged from the environment.
///
/// Args:
/// * `rail`: `x402` or `stripe`.
///
/// Usage:
/// ```ignore
/// let (escrow_ref, notice) = escrow_posture("x402");
/// ```
fn escrow_posture(rail: &str) -> (String, String) {
    let creds_present = match rail {
        "stripe" => std::env::var("STRIPE_SECRET_KEY").is_ok(),
        _ => {
            std::env::var("X402_WALLET_PRIVATE_KEY").is_ok()
                && std::env::var("X402_FACILITATOR_URL").is_ok()
        }
    };
    if !creds_present {
        return (
            format!("unfunded:{rail}:credentials-absent"),
            format!(
                "channel open: {rail} rail not configured (credentials absent) — recording an \
                 UNFUNDED reservation; the gateway still meters against its capacity \
                 (seller-bounded credit posture, settle at close)"
            ),
        );
    }
    (
        format!("unfunded:{rail}:non-custodial-leg"),
        format!(
            "channel open: {rail} credentials detected — the funded hold itself lives in the \
             non-custodial leg (Stripe Connect direct charge / x402 channel contract), keyed to \
             this reservation; the gateway records the capacity and meters against it"
        ),
    )
}

/// `channel open`: record the reservation the gateway meters against.
///
/// Args:
/// * `seller`: the seller identity the channel streams to.
/// * `capacity`: budget syntax, e.g. `$50`.
/// * `rail`: the settling rail.
/// * `live_dir`: the gateway live dir the channel record persists under.
///
/// Usage:
/// ```ignore
/// channel::open("did:keri:Eseller", "$50", "x402", &live_dir)?;
/// ```
pub fn open(seller: &str, capacity: &str, rail: &str, live_dir: &Path) -> anyhow::Result<()> {
    let capacity_cents = auths_mcp_core::Budget::parse(capacity)
        .map_err(|e| anyhow::anyhow!("invalid --capacity `{capacity}`: {e}"))?
        .cap_cents();
    let (escrow_ref, notice) = escrow_posture(rail);
    let record = ChannelRecord::open(seller, rail, capacity_cents, &escrow_ref, Utc::now());
    let dir = channels_dir(live_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(format!("{}.json", record.channel_id));
    std::fs::write(&path, serde_json::to_vec_pretty(&record)?)
        .with_context(|| format!("write {}", path.display()))?;
    println!("{notice}");
    println!(
        "channel open: id={} seller={} rail={} capacity={} cents escrow={} → {}",
        record.channel_id,
        record.seller,
        record.rail,
        record.capacity_cents.get(),
        record.escrow_ref,
        path.display(),
    );
    Ok(())
}

/// `channel close`: re-derive the streamed total from the signed log, emit the
/// netted settlement record, and mark the channel settled.
///
/// Args:
/// * `channel_id`: the channel to close.
/// * `log`: the spend log whose signed cumulative is the closing state.
/// * `live_dir`: the gateway live dir holding the channel record.
///
/// Usage:
/// ```ignore
/// channel::close(&id, &log_path, &live_dir)?;
/// ```
pub fn close(channel_id: &str, log: &Path, live_dir: &Path) -> anyhow::Result<()> {
    let dir = channels_dir(live_dir);
    let path = dir.join(format!("{channel_id}.json"));
    let mut record: ChannelRecord = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .with_context(|| format!("no channel record at {}", path.display()))?,
    )?;
    if record.state == ChannelState::Settled {
        anyhow::bail!("channel {channel_id} is already settled");
    }
    let log_bytes =
        std::fs::read(log).with_context(|| format!("read spend log {}", log.display()))?;
    let records = read_spend_log(log).with_context(|| "parse the spend log")?;
    let cumulative = records
        .last()
        .map(|r| r.receipt.cumulative_cents)
        .unwrap_or(Cents::ZERO);
    let gross = netted_settle_cents(cumulative, record.capacity_cents);
    let settlement = ChannelSettlement {
        channel_id: record.channel_id.clone(),
        rail: record.rail.clone(),
        gross_cents: gross,
        log_hash: spend_log_hash(&log_bytes),
        calls: records.len() as u64,
        settled_at: Utc::now(),
    };
    let settlement_path = dir.join(format!("{channel_id}.settlement.json"));
    std::fs::write(&settlement_path, serde_json::to_vec_pretty(&settlement)?)
        .with_context(|| format!("write {}", settlement_path.display()))?;
    record.state = ChannelState::Settled;
    std::fs::write(&path, serde_json::to_vec_pretty(&record)?)?;
    println!(
        "channel close: id={channel_id} netted={} cents over {} call(s) (cumulative {} bounded \
         by capacity {}) log_hash={} → {}",
        gross.get(),
        settlement.calls,
        cumulative.get(),
        record.capacity_cents.get(),
        settlement.log_hash,
        settlement_path.display(),
    );
    println!(
        "channel close: ONE rail action settles this net on {} through the non-custodial leg \
         (Connect direct charge / channel contract), citing log_hash above — the receipts \
         worker re-derives the same number from the signed log",
        record.rail,
    );
    Ok(())
}
