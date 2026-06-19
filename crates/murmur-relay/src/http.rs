//! # The relay's HTTP surface — store-and-forward over a real socket.
//!
//! `serve` (in `main.rs`) proves the end-to-end leg *hermetically*, in one process.
//! This module is the wire that lets two **separate** devices reach the same store: an
//! iPhone deposits an opaque envelope under a mailbox id, a Mac drains it. The relay's
//! nature is unchanged — it only ever touches the outer envelope (a mailbox id and opaque
//! ciphertext), never plaintext, a sender AID, or a telephone number.
//!
//! The backlog lives in a [`RelayStore`] — in-memory (dev/hermetic) or Redis (durable,
//! shared, so a relay restart loses nothing). See `store.rs` + `docs/PRD-durable-relay.md`.
//!
//! ## Surface
//! - `GET  /`                  → version banner; pings the backend (health/readiness).
//! - `POST /deposit`           → JSON [`OuterEnvelope`] → queue it; returns the outcome.
//! - `GET  /drain/{mailbox}`   → JSON `[OuterEnvelope]`, draining the mailbox FIFO.
//! - `PUT  /prekey/{aid}`      → store a recipient's published prekey bundle (opaque bytes).
//! - `GET  /prekey/{aid}`      → fetch it, so a first-contact sender can root a session.
//!
//! ## Failure posture (fail-closed)
//! A backend error never masquerades as success: an unreachable store → `503`, an
//! out-of-memory store → `507`. A deposit is answered `queued` only once it is durably
//! stored, so the sender's outbox keeps and retries anything we could not accept.
//!
//! Idempotency: a retried `POST /deposit` of a byte-identical envelope is recognised by
//! the store's replay dedup and answered `deduped_replay` with **200 OK**.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use murmur_core::{DepositOutcome, OuterEnvelope};
use serde::Serialize;

use crate::store::{MAX_PREKEY_BYTES, RelayConfig, RelayStore, StoreError};

/// The JSON body returned by `POST /deposit`: which of the three store outcomes occurred.
#[derive(Debug, Serialize)]
struct DepositResponse {
    /// `"queued"`, `"deduped_replay"`, or `"quota_exceeded"`.
    outcome: &'static str,
}

/// Build the router over a given store. Split out so a test can mount the same app.
pub fn app(store: RelayStore) -> Router {
    Router::new()
        .route("/", get(health))
        .route("/deposit", post(deposit))
        .route("/drain/{mailbox}", get(drain))
        .route("/prekey/{aid}", put(put_prekey).get(get_prekey))
        // Cap the request body the relay will read into memory. A single deposit cannot exceed one
        // mailbox's byte budget, so a larger body is an abusive request and is rejected before it is
        // buffered.
        .layer(DefaultBodyLimit::max(
            murmur_core::relay::DEFAULT_MAX_BYTES_PER_MAILBOX,
        ))
        .with_state(store)
}

/// Bind `addr`, build the backend from the environment (fail-fast on a bad Redis URL),
/// print the resolved listen address + backend, and serve until the process is killed.
pub async fn serve(addr: &str) -> Result<(), String> {
    let store = RelayStore::from_config(RelayConfig::from_env()).await?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    println!(
        "murmur-relay {} listening on http://{local} · backend: {}",
        murmur_core::VERSION,
        store.label()
    );
    axum::serve(listener, app(store))
        .await
        .map_err(|e| format!("serve: {e}"))
}

/// Map a fail-closed store error to an HTTP response.
fn store_error(e: StoreError) -> Response {
    let code = match e {
        StoreError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE, // 503
        StoreError::OutOfMemory(_) => StatusCode::INSUFFICIENT_STORAGE, // 507
        StoreError::Backend(_) => StatusCode::INTERNAL_SERVER_ERROR,   // 500
    };
    (code, e.to_string()).into_response()
}

/// `GET /` — version banner; also pings the backend so an unhealthy store (e.g. Redis
/// down) marks the machine unhealthy and the platform stops routing to it.
async fn health(State(store): State<RelayStore>) -> Response {
    match store.health().await {
        Ok(()) => (
            StatusCode::OK,
            format!("murmur-relay {}", murmur_core::VERSION),
        )
            .into_response(),
        Err(e) => store_error(e),
    }
}

/// `POST /deposit` — queue an opaque envelope for an offline recipient. The body is one
/// binary [`OuterEnvelope`] frame (`application/octet-stream`).
async fn deposit(State(store): State<RelayStore>, body: Bytes) -> Response {
    let envelope = match OuterEnvelope::from_frame(&body) {
        Ok(envelope) => envelope,
        Err(_) => return (StatusCode::BAD_REQUEST, "malformed envelope frame").into_response(),
    };
    match store.deposit(&envelope).await {
        Ok(DepositOutcome::Queued) => {
            (StatusCode::OK, Json(DepositResponse { outcome: "queued" })).into_response()
        }
        // A byte-identical replay the store already holds — idempotent success.
        Ok(DepositOutcome::DedupedReplay) => (
            StatusCode::OK,
            Json(DepositResponse {
                outcome: "deduped_replay",
            }),
        )
            .into_response(),
        // A quota would be exceeded — fail closed so one mailbox cannot exhaust memory.
        Ok(DepositOutcome::QuotaExceeded) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(DepositResponse {
                outcome: "quota_exceeded",
            }),
        )
            .into_response(),
        Err(e) => store_error(e),
    }
}

/// `GET /drain/{mailbox}` — hand back and remove everything queued under a mailbox, FIFO,
/// as a length-prefixed list of binary frames: `[count:u32]( [len:u32][frame] )*`.
async fn drain(State(store): State<RelayStore>, Path(mailbox): Path<String>) -> Response {
    match store.drain(&mailbox).await {
        Ok(envelopes) => match encode_drain_list(&envelopes) {
            Ok(bytes) => {
                ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
            }
            Err(e) => store_error(e),
        },
        Err(e) => store_error(e),
    }
}

/// Encode a drained list as `[count:u32]( [frame_len:u32][frame] )*` (big-endian) — each
/// element a binary [`OuterEnvelope`] frame, so a client splits by length without parsing.
fn encode_drain_list(envelopes: &[OuterEnvelope]) -> Result<Vec<u8>, StoreError> {
    let mut out = Vec::new();
    out.extend_from_slice(&(envelopes.len() as u32).to_be_bytes());
    for env in envelopes {
        let frame = env
            .to_frame()
            .map_err(|_| StoreError::Backend("encode envelope frame".into()))?;
        out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        out.extend_from_slice(&frame);
    }
    Ok(out)
}

/// `PUT /prekey/{aid}` — publish a recipient's prekey bundle (opaque bytes). The relay
/// stores it verbatim; the *sender* verifies it against the scanned AID digest.
async fn put_prekey(
    State(store): State<RelayStore>,
    Path(aid): Path<String>,
    body: Bytes,
) -> Response {
    if body.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if body.len() > MAX_PREKEY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    match store.put_prekey(&aid, body.to_vec()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => store_error(e),
    }
}

/// `GET /prekey/{aid}` — fetch a published bundle, or 404 if none has been published yet
/// (the app surfaces this as "waiting for {name} to come online").
async fn get_prekey(State(store): State<RelayStore>, Path(aid): Path<String>) -> Response {
    match store.get_prekey(&aid).await {
        Ok(Some(bytes)) => (StatusCode::OK, Bytes::from(bytes)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => store_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use murmur_core::{ContactDirectory, Endpoint, Identity, MailboxId, Session};

    /// Two endpoints sharing a pairwise session secret seal → deposit over real HTTP →
    /// drain over real HTTP → open and authenticate, against the **in-memory** backend
    /// (the hermetic default). The Redis backend's durability is proven separately in
    /// `tests/redis_durability.rs`.
    #[tokio::test]
    async fn http_round_trip_delivers_an_authenticated_message() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app(RelayStore::memory()))
                .await
                .unwrap();
        });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        let sender = Identity::from_seed([1u8; 32]).unwrap();
        let recipient = Identity::from_seed([2u8; 32]).unwrap();
        let secret = [7u8; 32];
        let mailbox = MailboxId::new("mbx-http-round-trip");

        let sender_ep = Endpoint::new(
            sender.clone(),
            recipient.aid().clone(),
            Session::from_secret(secret),
        );
        let recipient_ep = Endpoint::new(
            recipient.clone(),
            sender.aid().clone(),
            Session::from_secret(secret),
        );
        let mut directory = ContactDirectory::new();
        directory.admit(sender.aid().clone(), sender.public_key().to_vec());

        let envelope = sender_ep
            .seal_to(recipient.aid(), &mailbox, "hello over a real socket")
            .unwrap();

        let resp = client
            .post(format!("{base}/deposit"))
            .body(envelope.to_frame().unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let drained = decode_drain_list(
            &client
                .get(format!("{base}/drain/{}", mailbox.as_str()))
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
        );
        assert_eq!(drained.len(), 1, "exactly one envelope queued");
        let message = recipient_ep.open(&drained[0], &directory).unwrap();
        assert_eq!(message.body, "hello over a real socket");
        assert_eq!(message.from, *sender.aid());

        let empty = decode_drain_list(
            &client
                .get(format!("{base}/drain/{}", mailbox.as_str()))
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
        );
        assert!(empty.is_empty(), "mailbox drained");

        let resp2 = client
            .post(format!("{base}/deposit"))
            .body(envelope.to_frame().unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(resp2.status(), 200);
        let body: serde_json::Value = resp2.json().await.unwrap();
        assert_eq!(body["outcome"], "deduped_replay");

        let aid_key = "did:keri:Etest-prekey-aid";
        let bundle_bytes = vec![9u8, 8, 7, 6, 5];
        let put = client
            .put(format!("{base}/prekey/{aid_key}"))
            .body(bundle_bytes.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(put.status(), 204);
        let got = client
            .get(format!("{base}/prekey/{aid_key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(got.status(), 200);
        assert_eq!(got.bytes().await.unwrap().as_ref(), bundle_bytes.as_slice());

        let missing = client
            .get(format!("{base}/prekey/did:keri:Enobody"))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 404);
    }

    /// Split the binary drain response `[count:u32]( [len:u32][frame] )*` into envelopes.
    fn decode_drain_list(bytes: &[u8]) -> Vec<OuterEnvelope> {
        let mut out = Vec::new();
        if bytes.len() < 4 {
            return out;
        }
        let count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut pos = 4usize;
        for _ in 0..count {
            let len =
                u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                    as usize;
            pos += 4;
            out.push(OuterEnvelope::from_frame(&bytes[pos..pos + len]).unwrap());
            pos += len;
        }
        out
    }

    #[tokio::test]
    async fn a_deposit_body_larger_than_a_mailbox_budget_is_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app(RelayStore::memory()))
                .await
                .unwrap();
        });
        let base = format!("http://{addr}");
        let oversized = vec![0u8; murmur_core::relay::DEFAULT_MAX_BYTES_PER_MAILBOX + 1];
        let resp = reqwest::Client::new()
            .post(format!("{base}/deposit"))
            .body(oversized)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    }
}
