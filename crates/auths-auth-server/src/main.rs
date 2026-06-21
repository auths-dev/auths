//! Auths Auth Server binary.
//!
//! "Login with Auths" demo server. Serves the mock bank UI and handles
//! challenge/response authentication via KERI identities.
//!
//! # Environment Variables
//!
//! - `AUTH_SERVER_BIND` - Address to bind (default: 0.0.0.0:3001)
//! - `AUTH_SERVER_REGISTRY_URL` - Registry server URL (default: http://localhost:3000)
//! - `AUTH_SERVER_LOCAL_GIT_REPO` - Path to local git registry (overrides HTTP resolver)
//! - `AUTH_SERVER_CHALLENGE_TTL` - Challenge TTL in seconds (default: 300)
//! - `AUTH_SERVER_STATIC_DIR` - Path to static files directory (default: ./static)
//! - `AUTH_SERVER_LOG_LEVEL` - Log level (default: info)

// Server binary — `env::var` is expected at the process boundary for configuration.
#![allow(clippy::disallowed_methods)]

use std::env;

use auths_auth_server::{
    AuthServerConfig, AuthServerState,
    adapters::{
        InMemoryClientStore, InMemorySessionStore, LocalGitResolver, RegistryIdentityResolver,
    },
    config::ResolverMode,
    ports::IdentityResolver,
    run_server,
};
use std::sync::Arc;

use auths_telemetry::{init_telemetry_with_sink, init_tracing, sinks::stdout::new_stdout_sink};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AuthServerConfig::default();

    // Apply environment variables
    if let Ok(addr) = env::var("AUTH_SERVER_BIND")
        && let Ok(parsed) = addr.parse()
    {
        config = config.with_addr(parsed);
    }

    if let Ok(url) = env::var("AUTH_SERVER_REGISTRY_URL") {
        config = config.with_registry_url(url);
    }

    // LOCAL_GIT_REPO overrides the HTTP resolver when set
    if let Ok(path) = env::var("AUTH_SERVER_LOCAL_GIT_REPO") {
        config = config.with_local_git_resolver(path);
    }

    if let Ok(ttl) = env::var("AUTH_SERVER_CHALLENGE_TTL")
        && let Ok(secs) = ttl.parse()
    {
        config = config.with_challenge_ttl(secs);
    }

    if let Ok(dir) = env::var("AUTH_SERVER_STATIC_DIR") {
        config = config.with_static_dir(dir);
    }

    if let Ok(level) = env::var("AUTH_SERVER_LOG_LEVEL") {
        config = config.with_log_level(level);
    }

    // Initialize tracing (plain-text: auth-server also runs an async SIEM pipeline)
    init_tracing(&config.log_level, false);

    tracing::info!("Auths Auth Server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Bind address: {}", config.bind_addr);
    tracing::info!("Challenge TTL: {}s", config.challenge_ttl_secs);
    tracing::info!("Static dir: {:?}", config.static_dir);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            // Initialise the telemetry pipeline with the synchronous stdout sink.
            let telemetry = init_telemetry_with_sink(Arc::new(new_stdout_sink()));

            let resolver = build_resolver(&config.resolver_mode)?;

            // Session/client stores are in-memory in the open-source build. (Durable
            // persistence is a planned follow-up — see the crate README.)
            tracing::info!("Session store: in-memory");
            let state: AuthServerState = AuthServerState::new(
                resolver,
                InMemorySessionStore::new(),
                InMemoryClientStore::new(),
                config,
            );

            // Spawn background cleanup task.
            let cleanup_state = state.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    match cleanup_state
                        .app_service()
                        .sessions()
                        .cleanup_expired()
                        .await
                    {
                        Ok(0) => {}
                        Ok(n) => tracing::info!("Cleaned up {n} expired auth sessions"),
                        Err(e) => tracing::warn!("auth sessions cleanup error: {e}"),
                    }
                }
            });

            let result = run_server(state).await;

            // Flush all buffered telemetry events before the runtime exits.
            telemetry.shutdown();

            result
        })
}

fn build_resolver(
    mode: &ResolverMode,
) -> Result<Box<dyn IdentityResolver>, Box<dyn std::error::Error>> {
    match mode {
        ResolverMode::RegistryHttp { url } => {
            tracing::info!("Resolver: HTTP registry at {url}");
            Ok(Box::new(RegistryIdentityResolver::new(url)))
        }
        ResolverMode::LocalGit { repo_path } => {
            tracing::info!("Resolver: local git at {}", repo_path.display());
            let resolver = LocalGitResolver::open(repo_path).map_err(|e| {
                format!("cannot open local registry at {}: {e}", repo_path.display())
            })?;
            Ok(Box::new(resolver))
        }
    }
}
