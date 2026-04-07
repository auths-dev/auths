use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use auths_core::witness::{
    AsyncWitnessProvider, ReceiptCollectorBuilder, WitnessError, WitnessServerState,
};
use auths_infra_http::HttpAsyncWitnessClient;
use auths_keri::{Prefix, Said};
use ring::signature::{Ed25519KeyPair, KeyPair};

async fn start_test_server() -> (SocketAddr, WitnessServerState) {
    let state = WitnessServerState::in_memory_generated().unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_state = state.clone();
    tokio::spawn(async move {
        let app = auths_core::witness::witness_router(server_state);
        axum::serve(listener, app).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, state)
}

fn make_test_event(prefix: &str, seq: u64) -> (Vec<u8>, Said) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pk_hex = hex::encode(kp.public_key().as_ref());

    let mut event = serde_json::json!({
        "v": "KERI10JSON000000_",
        "t": "icp",
        "d": "",
        "i": prefix,
        "s": seq,
        "k": [pk_hex],
        "x": ""
    });

    let payload = serde_json::to_vec(&event).unwrap();
    let sig = kp.sign(&payload);
    event["x"] = serde_json::Value::String(hex::encode(sig.as_ref()));

    let mut for_said = event.clone();
    for_said["d"] = serde_json::Value::String(String::new());
    let said_payload = serde_json::to_vec(&for_said).unwrap();
    let said = auths_core::crypto::said::compute_said(&said_payload);
    event["d"] = serde_json::Value::String(said.to_string());

    (serde_json::to_vec(&event).unwrap(), said)
}

#[tokio::test(flavor = "multi_thread")]
async fn http_witness_submit_and_retrieve_receipt() {
    let (addr, _state) = start_test_server().await;
    let client = HttpAsyncWitnessClient::new(format!("http://{}", addr), 1);

    let prefix = Prefix::new_unchecked("ETestPrefix".to_string());
    let (event_json, said) = make_test_event("ETestPrefix", 0);

    let receipt = client.submit_event(&prefix, &event_json).await.unwrap();

    assert_eq!(receipt.a, said);
    assert_eq!(receipt.s, 0);
    assert_eq!(receipt.t, "rct");

    let retrieved = client.get_receipt(&prefix, &said).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().a, said);
}

#[tokio::test(flavor = "multi_thread")]
async fn http_witness_detects_duplicity() {
    let (addr, _state) = start_test_server().await;
    let client = HttpAsyncWitnessClient::new(format!("http://{}", addr), 1);

    let prefix = Prefix::new_unchecked("ETestPrefix".to_string());
    let (event1, _said1) = make_test_event("ETestPrefix", 0);
    client.submit_event(&prefix, &event1).await.unwrap();

    let (event2, _said2) = make_test_event("ETestPrefix", 0);
    let result = client.submit_event(&prefix, &event2).await;

    assert!(
        matches!(result, Err(WitnessError::Duplicity(_))),
        "Expected duplicity error, got: {:?}",
        result
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn receipt_collector_reaches_quorum() {
    let (addr1, _s1) = start_test_server().await;
    let (addr2, _s2) = start_test_server().await;
    let (addr3, _s3) = start_test_server().await;

    let w1: Arc<dyn AsyncWitnessProvider> =
        Arc::new(HttpAsyncWitnessClient::new(format!("http://{}", addr1), 1));
    let w2: Arc<dyn AsyncWitnessProvider> =
        Arc::new(HttpAsyncWitnessClient::new(format!("http://{}", addr2), 1));
    let w3: Arc<dyn AsyncWitnessProvider> =
        Arc::new(HttpAsyncWitnessClient::new(format!("http://{}", addr3), 1));

    let collector = ReceiptCollectorBuilder::new()
        .witnesses(vec![w1, w2, w3])
        .threshold(2)
        .timeout_ms(5000)
        .build();

    let prefix = Prefix::new_unchecked("ETestPrefix".to_string());
    let (event_json, _said) = make_test_event("ETestPrefix", 0);
    let receipts = collector.collect(&prefix, &event_json).await.unwrap();

    assert!(
        receipts.len() >= 2,
        "Expected >= 2 receipts, got {}",
        receipts.len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http_witness_health_check() {
    let (addr, _state) = start_test_server().await;
    let client = HttpAsyncWitnessClient::new(format!("http://{}", addr), 1);
    assert!(client.is_available().await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn http_witness_unavailable_server() {
    let client = HttpAsyncWitnessClient::new("http://127.0.0.1:1", 1)
        .with_timeout(Duration::from_millis(500));

    let prefix = Prefix::new_unchecked("ETest".to_string());
    let result = client.submit_event(&prefix, b"{}").await;
    assert!(
        matches!(
            result,
            Err(WitnessError::Network(_)) | Err(WitnessError::Timeout(_))
        ),
        "Expected network or timeout error, got: {:?}",
        result
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http_witness_observe_head() {
    let (addr, _state) = start_test_server().await;
    let client = HttpAsyncWitnessClient::new(format!("http://{}", addr), 1);

    let unknown_prefix = Prefix::new_unchecked("EUnknownPrefix".to_string());
    let head = client.observe_identity_head(&unknown_prefix).await.unwrap();
    assert!(head.is_none());

    let head_prefix = Prefix::new_unchecked("EHeadPrefix".to_string());
    let (event_json, _said) = make_test_event("EHeadPrefix", 0);
    client
        .submit_event(&head_prefix, &event_json)
        .await
        .unwrap();

    let head = client.observe_identity_head(&head_prefix).await.unwrap();
    assert!(head.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn http_witness_get_nonexistent_receipt() {
    let (addr, _state) = start_test_server().await;
    let client = HttpAsyncWitnessClient::new(format!("http://{}", addr), 1);

    let prefix = Prefix::new_unchecked("ETestPrefix".to_string());
    let said = Said::new_unchecked("ENonexistentSaid".to_string());
    let receipt = client.get_receipt(&prefix, &said).await.unwrap();
    assert!(receipt.is_none());
}
