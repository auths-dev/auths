//! The `registry` role's git smart-HTTP surface. The fetch path is driven
//! end-to-end with the real `git` binary — the same `+refs/auths/*:refs/auths/*`
//! fetch the witness sync (`crate::sync`) performs — since a subprocess- and
//! protocol-sensitive path can't be covered by unit assertions alone.

use std::path::Path;
use std::process::Command;

use auths_witness_node::serve_registry::registry_router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

/// Run a git command in `dir`, isolated from any host/global git config (so the
/// auths repo's own commit-signing never touches these throwaway repos), and
/// return stdout. Panics with stderr on failure.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .unwrap_or_else(|e| panic!("spawn git {args:?}: {e}"));
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_refs_auths_over_git_smart_http() {
    // A source repo holding a party KEL under refs/auths/* — the shape the
    // anchor role resolves keys from and the registry role serves.
    let src = TempDir::new().unwrap();
    git(src.path(), &["init", "-q"]);
    std::fs::write(src.path().join("kel.cesr"), b"party-a kel\n").unwrap();
    git(src.path(), &["add", "."]);
    git(
        src.path(),
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "kel"],
    );
    let head = git(src.path(), &["rev-parse", "HEAD"]).trim().to_string();
    git(
        src.path(),
        &["update-ref", "refs/auths/registry/party-a", &head],
    );

    // Serve it read-only on an ephemeral port.
    let app = registry_router(src.path());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Fetch the custom namespace exactly as `witness-node sync-registry` does.
    let dst = TempDir::new().unwrap();
    git(dst.path(), &["init", "-q"]);
    let url = format!("http://{addr}");
    git(
        dst.path(),
        &["fetch", "-q", &url, "+refs/auths/*:refs/auths/*"],
    );

    // The party ref arrived and points at the same object we served.
    let fetched = git(dst.path(), &["rev-parse", "refs/auths/registry/party-a"])
        .trim()
        .to_string();
    assert_eq!(fetched, head, "fetched ref must match the served ref");

    server.abort();
}

#[tokio::test]
async fn refuses_receive_pack_advertisement() {
    // Read-only by construction: asking for the push service is refused before
    // git is ever invoked, so no client can even begin to negotiate a write.
    let dir = TempDir::new().unwrap();
    let response = registry_router(dir.path())
        .oneshot(
            Request::builder()
                .uri("/info/refs?service=git-receive-pack")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
