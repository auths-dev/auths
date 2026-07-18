//! The treasury coordinator wire — the gateway side of `auths_mcp_core::treasury`.
//!
//! One process (`auths-mcp-gateway treasury serve`) holds the fleet's
//! [`FleetLedger`] and answers newline-delimited JSON reserve requests over TCP.
//! Every wrapped gateway in the fleet points `TREASURY_URL=tcp://host:port` at it and
//! pre-authorizes each metered call there BEFORE its own local budget: the fleet cap
//! and the local cap both bind, so the tighter one always governs. A gateway that
//! cannot reach the coordinator proceeds under its local (smaller) budget alone —
//! fail-closed to the tighter cap, never open.
//!
//! The coordinator persists the ledger atomically per grant (restart resumes the
//! high-water, mirroring the per-delegation counter's monotonicity) and appends a
//! P-256-signed `{fleet, count, cumulative}` checkpoint to `checkpoints.jsonl` on a
//! cadence — the running total anchored outside every gateway process, which
//! `verify-spend --treasury-checkpoints` cross-checks offline.

use anyhow::{Context, bail};
use auths_crypto::ring_provider::RingCryptoProvider;
use auths_mcp_core::treasury::{
    FleetLedger, SignedTreasuryCheckpoint, TreasuryCheckpoint, encode_hex,
};
use auths_mcp_core::{Cents, TreasuryReply, TreasuryRequest};
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// How long a gateway waits on the coordinator before falling back to its local cap.
const RESERVE_TIMEOUT: Duration = Duration::from_millis(400);

/// The gateway-held client for one fleet's coordinator.
///
/// Args:
/// * `url`: `tcp://host:port` (the `TREASURY_URL` env value).
/// * `fleet`: the fleet identifier — the delegator root AID unless `TREASURY_FLEET` overrides.
///
/// Usage:
/// ```ignore
/// if let Some(treasury) = TreasuryClient::from_env(&chain.root_did) {
///     let reply = treasury.reserve(&chain.agent_did, ceiling).await;
/// }
/// ```
pub struct TreasuryClient {
    addr: String,
    fleet: String,
    unreachable_reported: AtomicBool,
}

impl TreasuryClient {
    /// Build the client from `TREASURY_URL` (+ optional `TREASURY_FLEET`); `None`
    /// when no coordinator is configured.
    ///
    /// Args:
    /// * `default_fleet`: the fleet id used when `TREASURY_FLEET` is unset.
    ///
    /// Usage:
    /// ```ignore
    /// let treasury = TreasuryClient::from_env(&chain.root_did);
    /// ```
    pub fn from_env(default_fleet: &str) -> Option<Self> {
        let url = std::env::var("TREASURY_URL").ok()?;
        let addr = url.strip_prefix("tcp://")?.to_string();
        let fleet = std::env::var("TREASURY_FLEET").unwrap_or_else(|_| default_fleet.to_string());
        Some(TreasuryClient {
            addr,
            fleet,
            unreachable_reported: AtomicBool::new(false),
        })
    }

    /// Reserve `cents` of fleet capacity for one call; `None` means the coordinator
    /// was unreachable and the caller must enforce its local budget alone.
    ///
    /// Args:
    /// * `delegation`: the calling agent's delegated AID.
    /// * `cents`: the ceiling this call pre-authorizes.
    ///
    /// Usage:
    /// ```ignore
    /// match treasury.reserve(agent_did, ceiling).await {
    ///     Some(TreasuryReply::Refused { .. }) => { /* usage-cap-exceeded */ }
    ///     _ => { /* local budget governs from here */ }
    /// }
    /// ```
    pub async fn reserve(&self, delegation: &str, cents: Cents) -> Option<TreasuryReply> {
        let request = TreasuryRequest::Reserve {
            fleet: self.fleet.clone(),
            delegation: delegation.to_string(),
            cents,
        };
        match tokio::time::timeout(RESERVE_TIMEOUT, self.exchange(&request)).await {
            Ok(Ok(reply)) => Some(reply),
            Ok(Err(_)) | Err(_) => {
                if !self.unreachable_reported.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "auths-mcp-gateway: treasury {} unreachable — enforcing the local \
                         budget alone (the tighter cap still binds; fail-closed, never open)",
                        self.addr
                    );
                }
                None
            }
        }
    }

    async fn exchange(&self, request: &TreasuryRequest) -> anyhow::Result<TreasuryReply> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        let mut line = serde_json::to_string(request)?;
        line.push('\n');
        stream.write_all(line.as_bytes()).await?;
        let mut reply = String::new();
        BufReader::new(&mut stream).read_line(&mut reply).await?;
        Ok(serde_json::from_str(&reply)?)
    }
}

/// The coordinator's serve configuration.
pub struct ServeConfig {
    /// `host:port` to listen on.
    pub listen: String,
    /// The fleet this coordinator counts for.
    pub fleet: String,
    /// The fleet-wide cap.
    pub cap_cents: Cents,
    /// Where the ledger and checkpoint trail persist.
    pub state_dir: PathBuf,
    /// Signing seed (hex) for checkpoints; a fresh keypair is generated when absent.
    pub signing_seed_hex: Option<String>,
    /// Seconds between checkpoint signatures (only written when the counter moved).
    pub checkpoint_secs: u64,
}

struct ServeState {
    ledger: FleetLedger,
    last_checkpointed_count: u64,
}

/// Run the coordinator until the process is killed.
///
/// Args:
/// * `cfg`: the serve configuration.
///
/// Usage:
/// ```ignore
/// treasury::serve(cfg).await?;
/// ```
pub async fn serve(cfg: ServeConfig) -> anyhow::Result<()> {
    std::fs::create_dir_all(&cfg.state_dir)
        .with_context(|| format!("create state dir {}", cfg.state_dir.display()))?;
    let ledger_path = cfg.state_dir.join("fleet-ledger.json");
    let ledger = load_ledger(&ledger_path, cfg.cap_cents)?;

    let (seed, public_key) = match &cfg.signing_seed_hex {
        Some(hex) => {
            let seed = auths_crypto::decode_seed_hex(hex).context("parse --signing-seed")?;
            let public_key = RingCryptoProvider::p256_public_key_from_seed(seed.as_bytes())
                .context("derive the checkpoint public key")?;
            (seed, public_key)
        }
        None => RingCryptoProvider::p256_generate().context("generate the checkpoint key")?,
    };

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    println!(
        "treasury: fleet={} cap=${:.2} listen={} checkpoint-pubkey={} state={}",
        cfg.fleet,
        cfg.cap_cents.get() as f64 / 100.0,
        cfg.listen,
        encode_hex(&public_key),
        cfg.state_dir.display(),
    );

    let state = Arc::new(Mutex::new(ServeState {
        last_checkpointed_count: ledger.count(),
        ledger,
    }));

    let checkpoint_state = Arc::clone(&state);
    let checkpoint_path = cfg.state_dir.join("checkpoints.jsonl");
    let fleet = cfg.fleet.clone();
    let cadence = Duration::from_secs(cfg.checkpoint_secs.max(1));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(cadence);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let snapshot = {
                let mut guard = checkpoint_state.lock().await;
                if guard.ledger.count() == guard.last_checkpointed_count {
                    continue;
                }
                guard.last_checkpointed_count = guard.ledger.count();
                (guard.ledger.count(), guard.ledger.settled_cents())
            };
            if let Err(e) =
                append_checkpoint(&checkpoint_path, &fleet, snapshot, &seed, &public_key)
            {
                eprintln!("treasury: checkpoint append failed: {e}");
            }
        }
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let conn_state = Arc::clone(&state);
        let conn_fleet = cfg.fleet.clone();
        let conn_ledger_path = ledger_path.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, conn_state, &conn_fleet, &conn_ledger_path).await
            {
                eprintln!("treasury: connection error: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    state: Arc<Mutex<ServeState>>,
    fleet: &str,
    ledger_path: &Path,
) -> anyhow::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<TreasuryRequest>(&line) {
            Ok(request) => answer(&state, fleet, ledger_path, request).await,
            Err(e) => TreasuryReply::Error {
                reason: format!("malformed request: {e}"),
            },
        };
        let mut out = serde_json::to_string(&reply)?;
        out.push('\n');
        write_half.write_all(out.as_bytes()).await?;
    }
    Ok(())
}

async fn answer(
    state: &Arc<Mutex<ServeState>>,
    fleet: &str,
    ledger_path: &Path,
    request: TreasuryRequest,
) -> TreasuryReply {
    match request {
        TreasuryRequest::Reserve {
            fleet: requested, ..
        } if requested != fleet => TreasuryReply::Error {
            reason: format!("unknown fleet `{requested}` (serving `{fleet}`)"),
        },
        TreasuryRequest::Reserve { cents, .. } => {
            let mut guard = state.lock().await;
            let outcome = guard.ledger.reserve(cents);
            let snapshot = guard.ledger.clone();
            drop(guard);
            if let Err(e) = persist_ledger(ledger_path, &snapshot) {
                eprintln!("treasury: ledger persist failed: {e}");
            }
            match outcome {
                auths_mcp_core::FleetReserveOutcome::Granted { headroom_cents } => {
                    TreasuryReply::Granted { headroom_cents }
                }
                auths_mcp_core::FleetReserveOutcome::Refused {
                    cap_cents,
                    would_be_cents,
                } => TreasuryReply::Refused {
                    cap_cents,
                    would_be_cents,
                },
            }
        }
        TreasuryRequest::Status { fleet: requested } if requested != fleet => {
            TreasuryReply::Error {
                reason: format!("unknown fleet `{requested}` (serving `{fleet}`)"),
            }
        }
        TreasuryRequest::Status { .. } => {
            let guard = state.lock().await;
            TreasuryReply::Status {
                fleet: fleet.to_string(),
                count: guard.ledger.count(),
                settled_cents: guard.ledger.settled_cents(),
                cap_cents: guard.ledger.cap_cents(),
            }
        }
    }
}

fn load_ledger(path: &Path, cap_cents: Cents) -> anyhow::Result<FleetLedger> {
    if !path.exists() {
        return Ok(FleetLedger::new(cap_cents));
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read persisted ledger {}", path.display()))?;
    let persisted: FleetLedger = serde_json::from_str(&raw)
        .with_context(|| format!("parse persisted ledger {}", path.display()))?;
    if persisted.settled_cents() > cap_cents {
        bail!(
            "persisted fleet spend ({} cents) already exceeds the requested cap ({} cents) — \
             refusing to serve an over-spent fleet",
            persisted.settled_cents().get(),
            cap_cents.get(),
        );
    }
    Ok(FleetLedger::restore(
        cap_cents,
        persisted.settled_cents(),
        persisted.count(),
    ))
}

fn persist_ledger(path: &Path, ledger: &FleetLedger) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(ledger)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn append_checkpoint(
    path: &Path,
    fleet: &str,
    (count, cumulative_cents): (u64, Cents),
    seed: &auths_crypto::SecureSeed,
    public_key: &[u8],
) -> anyhow::Result<()> {
    let checkpoint = TreasuryCheckpoint {
        fleet: fleet.to_string(),
        count,
        cumulative_cents,
        at: Utc::now(),
    };
    let message = checkpoint.signing_bytes()?;
    let signature = RingCryptoProvider::p256_sign(seed.as_bytes(), &message)
        .map_err(|e| anyhow::anyhow!("sign checkpoint: {e}"))?;
    let signed = SignedTreasuryCheckpoint {
        checkpoint,
        public_key_hex: encode_hex(public_key),
        signature_hex: encode_hex(&signature),
    };
    let mut line = serde_json::to_string(&signed)?;
    line.push('\n');
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(line.as_bytes())?;
    Ok(())
}
