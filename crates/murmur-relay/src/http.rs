//! # The relay's HTTP surface — store-and-forward over a real socket.
//!
//! `serve` (in `main.rs`) proves the end-to-end leg *hermetically*, in one process.
//! This module is the wire that lets two **separate** devices reach the same
//! [`MailboxStore`]: an iPhone deposits an opaque envelope under a mailbox id, a Mac
//! drains it. The relay's nature is unchanged — it still only ever touches the outer
//! envelope (a mailbox id and opaque ciphertext), never plaintext, a sender AID, or a
//! telephone number. The HTTP layer is a dumb pipe over the same dumb store.
//!
//! ## Surface
//! - `GET  /`                  → version banner (liveness).
//! - `POST /deposit`           → JSON [`OuterEnvelope`] → queue it; returns the outcome.
//! - `GET  /drain/{mailbox}`   → JSON `[OuterEnvelope]`, draining the mailbox FIFO.
//! - `PUT  /prekey/{aid}`      → store a recipient's published prekey bundle (opaque bytes).
//! - `GET  /prekey/{aid}`      → fetch it, so a first-contact sender can root a session.
//!
//! ## What the relay deliberately does NOT do
//! It does **not** verify a prekey bundle. A bundle is opaque bytes here; the *recipient*
//! verifies it — and the security model turns on the recipient checking the bundle's
//! signing key against the **scanned AID digest** (`Aid = SHA256(pubkey)`), never trusting
//! a key this relay served. So a hostile relay that swaps a bundle is caught downstream,
//! not here. This server therefore only sanity-bounds sizes; it never inspects contents.
//!
//! Idempotency: a retried `POST /deposit` of the byte-identical envelope is recognised by
//! the store's replay dedup and answered `deduped_replay` with **200 OK** — a retry after a
//! lost response is a success, not a failure.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
};
use murmur_core::{DepositOutcome, MailboxId, MailboxStore, OuterEnvelope, RelayRequest};
use serde::Serialize;

/// Largest prekey bundle the directory will store, in bytes. A published bundle is a
/// handful of 32-byte keys plus a signature and an AID; 8 KiB is generous headroom and
/// stops a client filling memory with junk under a directory key.
const MAX_PREKEY_BYTES: usize = 8 * 1024;

/// Shared relay state behind the HTTP handlers: the store-and-forward queue and the
/// prekey directory, each behind a `Mutex` (handlers lock briefly, never across `.await`).
#[derive(Clone)]
pub struct RelayState {
    store: Arc<Mutex<MailboxStore>>,
    /// AID (textual) → that AID's published prekey-bundle bytes. Opaque to the relay.
    prekeys: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl RelayState {
    /// A fresh relay: an empty mailbox store (default quotas) and an empty directory.
    pub fn new() -> Self {
        RelayState {
            store: Arc::new(Mutex::new(MailboxStore::new())),
            prekeys: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for RelayState {
    fn default() -> Self {
        RelayState::new()
    }
}

/// The JSON body returned by `POST /deposit`: which of the three store outcomes occurred.
#[derive(Debug, Serialize)]
struct DepositResponse {
    /// `"queued"`, `"deduped_replay"`, or `"quota_exceeded"`.
    outcome: &'static str,
}

/// Build the router over a given relay state. Split out so the round-trip test can mount
/// the exact same app on an ephemeral port.
pub fn app(state: RelayState) -> Router {
    Router::new()
        .route("/", get(health))
        .route("/deposit", post(deposit))
        .route("/drain/{mailbox}", get(drain))
        .route("/prekey/{aid}", put(put_prekey).get(get_prekey))
        .with_state(state)
}

/// Bind `addr`, print the resolved listen address (so a launcher can read the port when
/// `addr` ends in `:0`), and serve until the process is killed.
pub async fn serve(addr: &str) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    println!(
        "murmur-relay {} listening on http://{local}",
        murmur_core::VERSION
    );
    axum::serve(listener, app(RelayState::new()))
        .await
        .map_err(|e| format!("serve: {e}"))
}

/// `GET /` — liveness banner.
async fn health() -> String {
    format!("murmur-relay {}", murmur_core::VERSION)
}

/// `POST /deposit` — queue an opaque envelope for an offline recipient.
async fn deposit(
    State(state): State<RelayState>,
    Json(envelope): Json<OuterEnvelope>,
) -> (StatusCode, Json<DepositResponse>) {
    let outcome = {
        let mut store = state.store.lock().expect("relay store poisoned");
        store.deposit(&envelope)
    };
    let (code, outcome) = match outcome {
        // Fresh ciphertext queued for the recipient.
        DepositOutcome::Queued => (StatusCode::OK, "queued"),
        // A byte-identical replay the store already holds. Idempotent success (a retry
        // after a lost response), NOT an error.
        DepositOutcome::DedupedReplay => (StatusCode::OK, "deduped_replay"),
        // A quota would be exceeded — fail closed so one mailbox cannot exhaust memory.
        DepositOutcome::QuotaExceeded => (StatusCode::TOO_MANY_REQUESTS, "quota_exceeded"),
    };
    (code, Json(DepositResponse { outcome }))
}

/// `GET /drain/{mailbox}` — hand back and remove everything queued under a mailbox, FIFO.
async fn drain(
    State(state): State<RelayState>,
    Path(mailbox): Path<String>,
) -> Json<Vec<OuterEnvelope>> {
    let drained = {
        let mut store = state.store.lock().expect("relay store poisoned");
        store.handle(&RelayRequest::Drain(MailboxId::new(mailbox)))
    };
    Json(drained)
}

/// `PUT /prekey/{aid}` — publish a recipient's prekey bundle (opaque bytes). The relay
/// stores it verbatim; the *sender* verifies it against the scanned AID digest.
async fn put_prekey(
    State(state): State<RelayState>,
    Path(aid): Path<String>,
    body: Bytes,
) -> StatusCode {
    if body.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    if body.len() > MAX_PREKEY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    state
        .prekeys
        .lock()
        .expect("prekey directory poisoned")
        .insert(aid, body.to_vec());
    StatusCode::NO_CONTENT
}

/// `GET /prekey/{aid}` — fetch a published bundle, or 404 if the recipient has not
/// published one yet (the app surfaces this as "waiting for {name} to come online").
async fn get_prekey(
    State(state): State<RelayState>,
    Path(aid): Path<String>,
) -> Result<Bytes, StatusCode> {
    let found = state
        .prekeys
        .lock()
        .expect("prekey directory poisoned")
        .get(&aid)
        .cloned();
    match found {
        Some(bytes) => Ok(Bytes::from(bytes)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use murmur_core::{ContactDirectory, Endpoint, Identity, Session};

    /// Two endpoints sharing a pairwise session secret seal → deposit over real HTTP →
    /// drain over real HTTP → open and authenticate. This is the whole store-and-forward
    /// leg, but across a socket rather than in-process: the proof that the network surface
    /// carries the engine's guarantee end to end.
    #[tokio::test]
    async fn http_round_trip_delivers_an_authenticated_message() {
        // A real listener on an ephemeral port, serving the same router `serve` mounts.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app(RelayState::new())).await.unwrap();
        });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // Sender and recipient identities; a shared session secret stands in for the X3DH
        // output (key agreement is exercised elsewhere — here we test the transport).
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
        // The recipient resolves the sender's AID to its key through the directory — built
        // from the sender's real public key, the binding the AID digest commits to.
        let mut directory = ContactDirectory::new();
        directory.admit(sender.aid().clone(), sender.public_key().to_vec());

        let envelope = sender_ep
            .seal_to(recipient.aid(), &mailbox, "hello over a real socket")
            .unwrap();

        // Deposit.
        let resp = client
            .post(format!("{base}/deposit"))
            .json(&envelope)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Drain and open.
        let drained: Vec<OuterEnvelope> = client
            .get(format!("{base}/drain/{}", mailbox.as_str()))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(drained.len(), 1, "exactly one envelope queued");
        let message = recipient_ep.open(&drained[0], &directory).unwrap();
        assert_eq!(message.body, "hello over a real socket");
        assert_eq!(message.from, *sender.aid());

        // A second drain of the same mailbox is empty (FIFO drain removed it).
        let empty: Vec<OuterEnvelope> = client
            .get(format!("{base}/drain/{}", mailbox.as_str()))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(empty.is_empty(), "mailbox drained");

        // Idempotent re-deposit of the identical envelope → deduped_replay, still 200.
        let resp2 = client
            .post(format!("{base}/deposit"))
            .json(&envelope)
            .send()
            .await
            .unwrap();
        assert_eq!(resp2.status(), 200);
        let body: serde_json::Value = resp2.json().await.unwrap();
        assert_eq!(body["outcome"], "deduped_replay");

        // Prekey directory put/get round-trips opaque bytes verbatim.
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

        // An unpublished AID is a clean 404 (the "not online yet" signal).
        let missing = client
            .get(format!("{base}/prekey/did:keri:Enobody"))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 404);
    }
}
