use auths_api::app::{AppState, build_router};
use auths_api::{AgentPersistence, AgentRegistry};
use auths_core::storage::keychain::get_platform_keychain;
use auths_storage::git::GitRegistryBackend;
use auths_storage::git::RegistryConfig;
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Initialize persistence (Redis connection)
    let persistence = match AgentPersistence::new() {
        Ok(p) => {
            tracing::info!("Connected to Redis");
            Arc::new(p)
        }
        Err(e) => {
            tracing::error!("Failed to connect to Redis: {}", e);
            return;
        }
    };

    // Initialize registry (in-memory cache)
    let registry = Arc::new(AgentRegistry::new());

    // Warm cache from Redis on startup
    if let Ok(sessions) = persistence.load_all().await {
        for session in sessions {
            registry.insert(session);
        }
        let now = {
            #[allow(clippy::disallowed_methods)]
            chrono::Utc::now()
        };
        tracing::info!("Loaded {} sessions from Redis", registry.len(now));
    }

    // Initialize Git-backed registry for KERI identity storage
    let agent_registry_path = PathBuf::from(".auths-agents");
    let registry_config = RegistryConfig::single_tenant(&agent_registry_path);
    let git_backend = GitRegistryBackend::from_config_unchecked(registry_config);

    // Initialize registry if needed (creates .git structure)
    if let Err(e) = git_backend.init_if_needed() {
        tracing::error!("Failed to initialize agent registry: {:?}", e);
        return;
    }

    let registry_backend: Arc<dyn auths_id::storage::registry::RegistryBackend + Send + Sync> =
        Arc::new(git_backend);

    // Initialize platform-specific keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
    let keychain: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> = {
        match get_platform_keychain() {
            Ok(keychain) => Arc::from(keychain),
            Err(e) => {
                tracing::error!("Failed to initialize platform keychain: {}", e);
                return;
            }
        }
    };

    // Create application state
    let state = AppState {
        registry: registry.clone(),
        persistence: persistence.clone(),
        registry_backend,
        keychain,
    };

    // Build router
    let app = build_router(state);

    // Start server
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:8080").await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind server: {}", e);
            return;
        }
    };

    tracing::info!("Server listening on 127.0.0.1:8080");

    // Start background cleanup task (reap expired sessions)
    let registry_clone = registry.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = {
                #[allow(clippy::disallowed_methods)]
                chrono::Utc::now()
            };
            let reaped = registry_clone.reap_expired(now);
            if reaped > 0 {
                tracing::info!("Reaped {} expired sessions", reaped);
            }
        }
    });

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("Server error: {}", e);
    }
}
