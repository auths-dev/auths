//! Black-box durability + correctness tests for the Redis backend.
//!
//! These spawn the REAL `murmur-relay serve-http` binary against a live Redis and drive it
//! over HTTP — so they test the actual deployed path, including the headline guarantee:
//! **a relay process restart with a non-empty backlog loses nothing.**
//!
//! Gated on a live Redis: set `MURMUR_RELAY_TEST_REDIS_URL` (e.g. `redis://127.0.0.1:6390`)
//! or the tests skip. Each test uses a unique key prefix for isolation.
//!
//! Run:
//!   redis-server --port 6390 --save '' --appendonly no &
//!   MURMUR_RELAY_TEST_REDIS_URL=redis://127.0.0.1:6390 \
//!     cargo test -p murmur-relay --test redis_durability -- --nocapture --test-threads=1

// Black-box integration test: it reads an env var to find the test Redis, stamps a unique
// mailbox from the wall clock, spawns the real binary, and unwraps on HTTP — all legitimate
// for a test harness. Allow the restriction lints here, per the project convention.
#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime};

use murmur_core::{MailboxId, OuterEnvelope};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

fn test_redis_url() -> Option<String> {
    std::env::var("MURMUR_RELAY_TEST_REDIS_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// A unique key prefix so tests (and reruns) never collide in a shared Redis.
fn unique_prefix(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("mrtest:{tag}:{nanos}")
}

/// Spawn `murmur-relay serve-http 127.0.0.1:0` against Redis, wait for it to announce its
/// port, and return the child + base URL.
async fn spawn_relay(url: &str, prefix: &str, extra_env: &[(&str, &str)]) -> (Child, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_murmur-relay"));
    cmd.args(["serve-http", "127.0.0.1:0"])
        .env("MURMUR_RELAY_REDIS_URL", url)
        .env("MURMUR_RELAY_KEY_PREFIX", prefix)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn murmur-relay");
    let stdout = child.stdout.take().expect("relay stdout");
    let mut lines = BufReader::new(stdout).lines();

    let mut base = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(10), lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Some(pos) = line.find("http://127.0.0.1:") {
                    base = Some(line[pos..].split_whitespace().next().unwrap().to_string());
                    break;
                }
            }
            _ => break,
        }
    }
    let base = base.expect("relay did not announce a listen address");
    // Keep draining stdout so the child never blocks on a full pipe.
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    (child, base)
}

fn frame(mailbox: &str, ciphertext: Vec<u8>) -> Vec<u8> {
    OuterEnvelope {
        to_mailbox: MailboxId::new(mailbox),
        ciphertext,
    }
    .to_frame()
    .unwrap()
}

async fn deposit(client: &reqwest::Client, base: &str, frame: &[u8]) -> (u16, String) {
    let r = client
        .post(format!("{base}/deposit"))
        .body(frame.to_vec())
        .send()
        .await
        .unwrap();
    let code = r.status().as_u16();
    let body = r.text().await.unwrap();
    (code, body)
}

/// Drain and return each queued envelope's ciphertext (decode the binary list
/// `[count:u32]( [len:u32][frame] )*`).
async fn drain(client: &reqwest::Client, base: &str, mailbox: &str) -> Vec<Vec<u8>> {
    let bytes = client
        .get(format!("{base}/drain/{mailbox}"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let mut out = Vec::new();
    if bytes.len() < 4 {
        return out;
    }
    let count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mut pos = 4usize;
    for _ in 0..count {
        let len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        pos += 4;
        out.push(
            OuterEnvelope::from_frame(&bytes[pos..pos + len])
                .unwrap()
                .ciphertext,
        );
        pos += len;
    }
    out
}

/// THE headline test: deposit a backlog, KILL the relay process, start a fresh one on the
/// same Redis, and confirm the drain returns the whole backlog — nothing lost on restart.
#[tokio::test]
async fn durability_survives_a_relay_restart() {
    let Some(url) = test_redis_url() else {
        eprintln!("skipping durability_survives_a_relay_restart: set MURMUR_RELAY_TEST_REDIS_URL");
        return;
    };
    let prefix = unique_prefix("durability");
    let client = reqwest::Client::new();
    let mailbox = "mbx-durable";

    // Relay #1 accepts a backlog.
    let (mut relay1, base1) = spawn_relay(&url, &prefix, &[]).await;
    for i in 0..25u8 {
        let (code, body) = deposit(&client, &base1, &frame(mailbox, vec![i; 32])).await;
        assert_eq!(code, 200, "deposit {i} not accepted: {body}");
    }

    // Hard kill (simulate a crash / fly deploy mid-backlog).
    relay1.kill().await.expect("kill relay1");

    // Relay #2: a brand-new process on the SAME Redis + prefix.
    let (mut relay2, base2) = spawn_relay(&url, &prefix, &[]).await;

    // The backlog is intact, in order.
    let drained = drain(&client, &base2, mailbox).await;
    assert_eq!(drained.len(), 25, "a restart must lose nothing");
    for (i, ciphertext) in drained.iter().enumerate() {
        assert_eq!(ciphertext[0], i as u8, "order preserved");
    }
    // Drained once.
    assert!(drain(&client, &base2, mailbox).await.is_empty());

    relay2.kill().await.ok();
}

/// Idempotent replay (byte-identical re-deposit is `deduped_replay`, not a double) and a
/// replay AFTER a drain is still dropped within the dedup horizon.
#[tokio::test]
async fn idempotent_replay_and_drain_once() {
    let Some(url) = test_redis_url() else {
        eprintln!("skipping idempotent_replay_and_drain_once");
        return;
    };
    let prefix = unique_prefix("dedup");
    let client = reqwest::Client::new();
    let (mut relay, base) = spawn_relay(&url, &prefix, &[]).await;
    let mbx = "mbx-dedup";
    let env = frame(mbx, vec![1, 2, 3, 4, 5]);

    let (c1, _) = deposit(&client, &base, &env).await;
    assert_eq!(c1, 200);
    let (c2, b2) = deposit(&client, &base, &env).await;
    assert_eq!(c2, 200);
    assert!(
        b2.contains("deduped_replay"),
        "second deposit deduped: {b2}"
    );

    let drained = drain(&client, &base, mbx).await;
    assert_eq!(drained.len(), 1, "exactly one queued despite two deposits");

    // A replay after the drain is still recognized (delivery horizon outlives the queue).
    let (c3, b3) = deposit(&client, &base, &env).await;
    assert_eq!(c3, 200);
    assert!(
        b3.contains("deduped_replay"),
        "post-drain replay still deduped: {b3}"
    );
    assert!(
        drain(&client, &base, mbx).await.is_empty(),
        "no re-delivery of a replay"
    );

    relay.kill().await.ok();
}

/// The per-mailbox message cap returns `quota_exceeded` and records nothing extra.
#[tokio::test]
async fn quota_per_mailbox_message_cap() {
    let Some(url) = test_redis_url() else {
        eprintln!("skipping quota_per_mailbox_message_cap");
        return;
    };
    let prefix = unique_prefix("quota");
    let client = reqwest::Client::new();
    let (mut relay, base) =
        spawn_relay(&url, &prefix, &[("MURMUR_RELAY_MAX_MSGS_PER_MAILBOX", "3")]).await;
    let mbx = "mbx-quota";

    for i in 0..3u8 {
        let (code, _) = deposit(&client, &base, &frame(mbx, vec![i; 16])).await;
        assert_eq!(code, 200);
    }
    // The 4th distinct message exceeds the cap.
    let (code, body) = deposit(&client, &base, &frame(mbx, vec![99; 16])).await;
    assert_eq!(code, 429, "over-cap deposit refused");
    assert!(body.contains("quota_exceeded"), "{body}");

    assert_eq!(
        drain(&client, &base, mbx).await.len(),
        3,
        "only the 3 under-cap queued"
    );
    relay.kill().await.ok();
}

/// Prekey publish/fetch round-trips opaque bytes; an unpublished AID is 404.
#[tokio::test]
async fn prekey_round_trip_and_404() {
    let Some(url) = test_redis_url() else {
        eprintln!("skipping prekey_round_trip_and_404");
        return;
    };
    let prefix = unique_prefix("prekey");
    let client = reqwest::Client::new();
    let (mut relay, base) = spawn_relay(&url, &prefix, &[]).await;
    let aid = "did:keri:Eredis-prekey";
    let bundle = vec![9u8, 8, 7, 6];

    client
        .put(format!("{base}/prekey/{aid}"))
        .body(bundle.clone())
        .send()
        .await
        .unwrap();
    let got = client
        .get(format!("{base}/prekey/{aid}"))
        .send()
        .await
        .unwrap();
    assert_eq!(got.status(), 200);
    assert_eq!(got.bytes().await.unwrap().as_ref(), bundle.as_slice());

    let missing = client
        .get(format!("{base}/prekey/did:keri:Enobody"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    relay.kill().await.ok();
}

/// A short TTL expires an undrained message (the relay is a buffer, not an archive).
#[tokio::test]
async fn ttl_expires_an_undrained_message() {
    let Some(url) = test_redis_url() else {
        eprintln!("skipping ttl_expires_an_undrained_message");
        return;
    };
    let prefix = unique_prefix("ttl");
    let client = reqwest::Client::new();
    let (mut relay, base) = spawn_relay(&url, &prefix, &[("MURMUR_RELAY_MSG_TTL_SECS", "1")]).await;
    let mbx = "mbx-ttl";

    // Deposit and DON'T drain; after the 1 s TTL the undrained message is gone.
    let (code, _) = deposit(&client, &base, &frame(mbx, vec![2; 8])).await;
    assert_eq!(code, 200);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        drain(&client, &base, mbx).await.is_empty(),
        "an undrained message must expire after its TTL"
    );
    relay.kill().await.ok();
}

/// Startup fail-fast: pointed at an unreachable Redis, the relay exits non-zero rather than
/// serving a silently-broken endpoint.
#[tokio::test]
async fn fails_fast_when_redis_is_unreachable() {
    if test_redis_url().is_none() {
        eprintln!("skipping fails_fast_when_redis_is_unreachable");
        return;
    }
    // Port 1 refuses connections.
    let mut child = Command::new(env!("CARGO_BIN_EXE_murmur-relay"))
        .args(["serve-http", "127.0.0.1:0"])
        .env("MURMUR_RELAY_REDIS_URL", "redis://127.0.0.1:1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn");
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("relay should exit fast on an unreachable Redis")
        .expect("wait");
    assert!(
        !status.success(),
        "relay must fail-fast (non-zero) on a dead Redis"
    );
}
