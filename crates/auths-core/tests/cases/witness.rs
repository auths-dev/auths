use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use auths_core::witness::{
    AsyncWitnessProvider, HttpWitnessClient, ReceiptCollectorBuilder, WitnessError,
    WitnessServerState,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Start a witness server on a random port and return the address.
async fn start_test_server() -> (SocketAddr, WitnessServerState) {
    let state = WitnessServerState::in_memory_generated().unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_state = state.clone();
    tokio::spawn(async move {
        let app = auths_core::witness::witness_router(server_state);
        axum::serve(listener, app).await.unwrap();
    });

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, state)
}

/// Build a valid KERI inception event with proper SAID and self-signature.
/// Returns (event_json_bytes, computed_said).
fn make_test_event(prefix: &str, seq: u64) -> (Vec<u8>, String) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pk_hex = hex::encode(kp.public_key().as_ref());

    // Build event with empty d and x for signing
    let mut event = serde_json::json!({
        "v": "KERI10JSON000000_",
        "t": "icp",
        "d": "",
        "i": prefix,
        "s": seq,
        "k": [pk_hex],
        "x": ""
    });

    // Sign the payload (with empty d and x)
    let payload = serde_json::to_vec(&event).unwrap();
    let sig = kp.sign(&payload);
    event["x"] = serde_json::Value::String(hex::encode(sig.as_ref()));

    // Compute SAID (with empty d, but final x)
    let mut for_said = event.clone();
    for_said["d"] = serde_json::Value::String(String::new());
    let said_payload = serde_json::to_vec(&for_said).unwrap();
    let said = auths_core::crypto::said::compute_said(&said_payload);
    event["d"] = serde_json::Value::String(said.clone());

    (serde_json::to_vec(&event).unwrap(), said)
}

#[tokio::test]
async fn http_witness_submit_and_retrieve_receipt() {
    let (addr, _state) = start_test_server().await;
    let client = HttpWitnessClient::new(format!("http://{}", addr), 1);

    let (event_json, said) = make_test_event("ETestPrefix", 0);

    // Submit event
    let receipt = client
        .submit_event("ETestPrefix", &event_json)
        .await
        .unwrap();

    assert_eq!(receipt.a, said);
    assert_eq!(receipt.s, 0);
    assert_eq!(receipt.t, "rct");

    // Retrieve receipt
    let retrieved = client.get_receipt("ETestPrefix", &said).await.unwrap();

    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.a, said);
}

#[tokio::test]
async fn http_witness_detects_duplicity() {
    let (addr, _state) = start_test_server().await;
    let client = HttpWitnessClient::new(format!("http://{}", addr), 1);

    // Submit first event
    let (event1, _said1) = make_test_event("ETestPrefix", 0);
    client.submit_event("ETestPrefix", &event1).await.unwrap();

    // Submit different event with same prefix and sequence (duplicity)
    let (event2, _said2) = make_test_event("ETestPrefix", 0);
    let result = client.submit_event("ETestPrefix", &event2).await;

    assert!(
        matches!(result, Err(WitnessError::Duplicity(_))),
        "Expected duplicity error, got: {:?}",
        result
    );
}

#[tokio::test]
async fn receipt_collector_reaches_quorum() {
    // Start 3 witness servers
    let (addr1, _s1) = start_test_server().await;
    let (addr2, _s2) = start_test_server().await;
    let (addr3, _s3) = start_test_server().await;

    let w1: Arc<dyn AsyncWitnessProvider> =
        Arc::new(HttpWitnessClient::new(format!("http://{}", addr1), 1));
    let w2: Arc<dyn AsyncWitnessProvider> =
        Arc::new(HttpWitnessClient::new(format!("http://{}", addr2), 1));
    let w3: Arc<dyn AsyncWitnessProvider> =
        Arc::new(HttpWitnessClient::new(format!("http://{}", addr3), 1));

    let collector = ReceiptCollectorBuilder::new()
        .witnesses(vec![w1, w2, w3])
        .threshold(2) // Need at least 2 of 3
        .timeout_ms(5000)
        .build();

    let (event_json, _said) = make_test_event("ETestPrefix", 0);

    let receipts = collector.collect("ETestPrefix", &event_json).await.unwrap();

    assert!(
        receipts.len() >= 2,
        "Expected >= 2 receipts, got {}",
        receipts.len()
    );
}

#[tokio::test]
async fn http_witness_health_check() {
    let (addr, _state) = start_test_server().await;
    let client = HttpWitnessClient::new(format!("http://{}", addr), 1);

    let available = client.is_available().await.unwrap();
    assert!(available);
}

#[tokio::test]
async fn http_witness_unavailable_server() {
    // Point at a port that isn't listening
    let client =
        HttpWitnessClient::new("http://127.0.0.1:1", 1).with_timeout(Duration::from_millis(500));

    let result = client.submit_event("ETest", b"{}").await;
    assert!(
        matches!(
            result,
            Err(WitnessError::Network(_)) | Err(WitnessError::Timeout(_))
        ),
        "Expected network or timeout error, got: {:?}",
        result
    );
}

#[tokio::test]
async fn http_witness_observe_head() {
    let (addr, _state) = start_test_server().await;
    let client = HttpWitnessClient::new(format!("http://{}", addr), 1);

    // Before any events, head should be None
    let head = client
        .observe_identity_head("EUnknownPrefix")
        .await
        .unwrap();
    assert!(head.is_none());

    // Submit an event
    let (event_json, _said) = make_test_event("EHeadPrefix", 0);
    client
        .submit_event("EHeadPrefix", &event_json)
        .await
        .unwrap();

    // Now head should exist
    let head = client.observe_identity_head("EHeadPrefix").await.unwrap();
    assert!(head.is_some());
}

#[tokio::test]
async fn http_witness_get_nonexistent_receipt() {
    let (addr, _state) = start_test_server().await;
    let client = HttpWitnessClient::new(format!("http://{}", addr), 1);

    let receipt = client
        .get_receipt("ETestPrefix", "ENonexistentSaid")
        .await
        .unwrap();
    assert!(receipt.is_none());
}
