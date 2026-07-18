//! End-to-end test for the agent socket on the live wired path.
//!
//! Drives the real listener over a real Unix socket through the connecting
//! client, and asserts that locking the agent stops it from signing — the
//! property a single-component unit test cannot cover, since it spans the
//! client transport, the listener, peer authorization, and the lock check.

#![cfg(unix)]

use auths_core::AgentHandle;
use auths_core::agent::{AgentStatus, add_identity, agent_sign, check_agent_status};
use auths_core::api::start_agent_listener_with_handle;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

fn generate_ed25519_pkcs8() -> Vec<u8> {
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;
    let rng = SystemRandom::new();
    Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("generate pkcs8")
        .as_ref()
        .to_vec()
}

fn unique_socket_dir() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("auths-agent-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp socket dir");
    // The listener accepts a pre-existing socket directory only when it is owner-only.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .expect("restrict temp socket dir");
    dir
}

async fn wait_until_running(socket_path: &Path) {
    for _ in 0..150 {
        if let AgentStatus::Running { .. } = check_agent_status(socket_path) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("agent listener did not become ready");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locked_agent_refuses_signing_over_the_socket() {
    let dir = unique_socket_dir();
    let socket_path = dir.join("agent.sock");

    let handle = Arc::new(AgentHandle::new(socket_path.clone()));
    let server = tokio::spawn(start_agent_listener_with_handle(
        handle.clone(),
        Arc::new(auths_core::agent::AllowAllSigning),
    ));
    wait_until_running(&socket_path).await;

    let pkcs8 = generate_ed25519_pkcs8();
    let add_path = socket_path.clone();
    let pubkey = tokio::task::spawn_blocking(move || add_identity(&add_path, &pkcs8))
        .await
        .expect("add task")
        .expect("add_identity over the socket should succeed");

    let sign_path = socket_path.clone();
    let unlocked_pubkey = pubkey.clone();
    let unlocked =
        tokio::task::spawn_blocking(move || agent_sign(&sign_path, &unlocked_pubkey, b"payload"))
            .await
            .expect("sign task");
    assert!(
        unlocked.is_ok(),
        "an unlocked agent should sign over the socket"
    );

    handle.lock_agent().expect("lock the agent");

    let denied_path = socket_path.clone();
    let denied = tokio::task::spawn_blocking(move || agent_sign(&denied_path, &pubkey, b"payload"))
        .await
        .expect("sign task");
    assert!(
        denied.is_err(),
        "a locked agent must refuse to sign over the socket"
    );

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
