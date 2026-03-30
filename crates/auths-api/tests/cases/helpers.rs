use auths_api::{AgentPersistence, AppState, build_router};
use auths_core::storage::keychain::KeyStorage;
use auths_id::storage::registry::RegistryBackend;
use auths_sdk::domains::agents::AgentRegistry;
use auths_storage::git::{GitRegistryBackend, RegistryConfig};
use std::sync::Arc;

/// Start a test server and return its URL and HTTP client
#[allow(clippy::expect_used)] // INVARIANT: test setup must panic on failure
pub async fn start_test_server() -> (String, reqwest::Client) {
    // Create in-memory registry and test-mode persistence
    let registry = Arc::new(AgentRegistry::new());
    let persistence = Arc::new(AgentPersistence::new_test());

    // Create a temporary Git registry backend for tests
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let registry_config = RegistryConfig::single_tenant(temp_dir.path());
    let git_backend = GitRegistryBackend::from_config_unchecked(registry_config);
    git_backend
        .init_if_needed()
        .expect("Failed to initialize registry");
    let registry_backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(git_backend);

    // Use in-memory keychain for tests
    let keychain: Arc<dyn KeyStorage + Send + Sync> =
        Arc::new(auths_core::storage::memory::MemoryKeychainHandle);

    let state = AppState {
        registry,
        persistence,
        registry_backend,
        keychain,
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
