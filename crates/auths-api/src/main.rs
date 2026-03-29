use auths_api::app::{build_router, AppState};
use auths_api::{AgentPersistence, AgentRegistry};
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

    // Create application state
    let state = AppState {
        registry: registry.clone(),
        persistence: persistence.clone(),
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
