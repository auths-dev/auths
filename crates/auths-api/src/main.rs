use auths_api::app::{build_router, AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = build_router(AppState::default());

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:8080").await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind server: {}", e);
            return;
        }
    };

    tracing::info!("Server listening on 127.0.0.1:8080");

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("Server error: {}", e);
    }
}
