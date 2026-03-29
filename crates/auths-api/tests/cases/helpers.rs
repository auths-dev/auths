use auths_api::{build_router, AgentPersistence, AppState};
use auths_sdk::domains::agents::AgentRegistry;
use std::sync::Arc;

/// Start a test server and return its URL and HTTP client
#[allow(clippy::expect_used)] // INVARIANT: test setup must panic on failure
pub async fn start_test_server() -> (String, reqwest::Client) {
    // Create in-memory registry and test-mode persistence
    let registry = Arc::new(AgentRegistry::new());
    let persistence = Arc::new(AgentPersistence::new_test());

    let state = AppState {
        registry,
        persistence,
    };

    // Build router
    let app = build_router(state);

    // Start server on random available port (0 = OS assigns free port)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind test server");

    let addr = listener.local_addr().expect("Failed to get local addr");
    let url = format!("http://{}", addr);

    // Spawn server in background
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Server failed to start");
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    (url, client)
}
