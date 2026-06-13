//! Bringing one witness node up, for real.
//!
//! [`StandupRequest`](crate::StandupRequest) is the parsed operator *intent*;
//! this module is the *runtime* that acts on it: it materializes the embedded
//! manifest, asks a container engine to bring the node (and its monitor
//! sidecar) up, waits until the node answers its health endpoint, and hands the
//! operator back the URL — or fails with one actionable line and leaves nothing
//! half-standing.
//!
//! Ports and adapters: the orchestration here never shells out directly. It
//! drives a [`ContainerEngine`] port; the shipped adapter ([`DockerEngine`])
//! is the only thing that knows about the `docker` binary. The health wait
//! talks to a [`HealthCheck`] port the same way. Swapping either (a different
//! engine, an in-process probe) never touches the bring-up logic.
//!
//! No source builds: the manifest declares the node's *released* image
//! (`image:`, never `build:`), so an operator runs what the platform shipped.
//! When that image cannot be obtained, bring-up fails honestly rather than
//! falling back to compiling one.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::StandupRequest;

/// Why a standup could not complete. Each variant carries the single,
/// actionable sentence an operator should see — no stack traces, no partial
/// state left behind.
#[derive(Debug)]
pub enum StandupError {
    /// No container engine is available on this host.
    NoEngine {
        /// The one-line, actionable remedy.
        hint: String,
    },
    /// The engine ran but could not bring the node up (image unavailable,
    /// port already taken, …). Carries the engine's own first error line.
    BringUpFailed {
        /// The single actionable line distilled from the engine's output.
        reason: String,
    },
    /// The node was asked to come up but never answered its health endpoint
    /// within the allotted window.
    Unhealthy {
        /// The health URL that stayed dark.
        url: String,
        /// How long we waited before giving up.
        waited: Duration,
    },
    /// The host filesystem could not be prepared for the node's data volume.
    DataDir {
        /// The path that could not be prepared.
        path: PathBuf,
        /// The underlying os error rendered to one line.
        reason: String,
    },
}

impl std::fmt::Display for StandupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StandupError::NoEngine { hint } => write!(f, "{hint}"),
            StandupError::BringUpFailed { reason } => write!(f, "{reason}"),
            StandupError::Unhealthy { url, waited } => write!(
                f,
                "node did not become healthy at {url} within {}s — nothing left running",
                waited.as_secs()
            ),
            StandupError::DataDir { path, reason } => {
                write!(
                    f,
                    "could not prepare data directory {}: {reason}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for StandupError {}

/// A container engine that can bring a compose project up and tear it down.
///
/// The port is intentionally narrow: the orchestrator only needs to start a
/// project from a manifest, stop it, and know whether the engine is usable at
/// all. Everything engine-specific lives behind the adapter.
pub trait ContainerEngine {
    /// Is this engine usable right now (binary present AND daemon reachable)?
    /// A `None` return means yes; `Some(hint)` is the one-line reason it is not,
    /// phrased as a remedy.
    fn unavailable_reason(&self) -> Option<String>;

    /// Bring the project named `project` up from `manifest_path`, publishing on
    /// the host as the manifest declares. Returns the first actionable error
    /// line on failure.
    fn compose_up(&self, project: &str, manifest_path: &Path) -> Result<(), String>;

    /// Tear the project down (idempotent — tearing down an absent project
    /// succeeds), removing its containers so no partial state survives a failed
    /// bring-up.
    fn compose_down(&self, project: &str, manifest_path: &Path) -> Result<(), String>;
}

/// A health endpoint poller.
pub trait HealthCheck {
    /// Does `url` answer successfully right now?
    fn is_healthy(&self, url: &str) -> bool;
}

/// The result of a successful standup: the operator-facing health URL of a node
/// that is already answering there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandupOutcome {
    /// The health URL the operator can open — proven live before this returns.
    pub health_url: String,
}

/// The stable compose project name for a node published on `port`.
///
/// One node per host port; the project name is derived from the port so a
/// second node on a second port is a second project, and `down` targets exactly
/// the node `up` created.
fn project_name(port: u16) -> String {
    format!("auths-witness-{port}")
}

/// Bring one witness node up and return its proven-live health URL.
///
/// The full bring-up, in order: prepare the data dir, refuse early if the
/// engine is unusable, write the manifest, bring the project up, then wait for
/// the node to answer its health endpoint. Any failure tears down whatever
/// started so the host is left clean, and returns the single actionable line.
///
/// Args:
/// * `req`: the parsed standup intent.
/// * `engine`: the container engine adapter to drive.
/// * `health`: the health poller.
/// * `wait`: how long to wait for the node to answer before failing.
pub fn stand_up(
    req: &StandupRequest,
    engine: &dyn ContainerEngine,
    health: &dyn HealthCheck,
    wait: Duration,
) -> Result<StandupOutcome, StandupError> {
    // Fail before touching anything if the engine is unusable.
    if let Some(hint) = engine.unavailable_reason() {
        return Err(StandupError::NoEngine { hint });
    }

    std::fs::create_dir_all(&req.data_dir).map_err(|e| StandupError::DataDir {
        path: req.data_dir.clone(),
        reason: e.to_string(),
    })?;

    let project = project_name(req.host_port);
    let manifest_path = req.data_dir.join("standup.compose.yml");
    std::fs::write(&manifest_path, req.compose_manifest()).map_err(|e| StandupError::DataDir {
        path: manifest_path.clone(),
        reason: e.to_string(),
    })?;

    if let Err(reason) = engine.compose_up(&project, &manifest_path) {
        // Leave nothing half-standing.
        let _ = engine.compose_down(&project, &manifest_path);
        return Err(StandupError::BringUpFailed { reason });
    }

    let url = req.health_url();
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if health.is_healthy(&url) {
            return Ok(StandupOutcome { health_url: url });
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    // Came up but never answered — tear it down and report honestly.
    let _ = engine.compose_down(&project, &manifest_path);
    Err(StandupError::Unhealthy { url, waited: wait })
}

/// Tear down the node published on `port`, if any. Idempotent.
pub fn tear_down(
    data_dir: &Path,
    port: u16,
    engine: &dyn ContainerEngine,
) -> Result<(), StandupError> {
    if let Some(hint) = engine.unavailable_reason() {
        return Err(StandupError::NoEngine { hint });
    }
    let project = project_name(port);
    let manifest_path = data_dir.join("standup.compose.yml");
    engine
        .compose_down(&project, &manifest_path)
        .map_err(|reason| StandupError::BringUpFailed { reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A scripted engine: records calls, returns canned results.
    struct FakeEngine {
        unavailable: Option<String>,
        up_result: Result<(), String>,
        calls: RefCell<Vec<String>>,
    }

    impl FakeEngine {
        fn ok() -> Self {
            Self {
                unavailable: None,
                up_result: Ok(()),
                calls: RefCell::new(vec![]),
            }
        }
    }

    impl ContainerEngine for FakeEngine {
        fn unavailable_reason(&self) -> Option<String> {
            self.unavailable.clone()
        }
        fn compose_up(&self, project: &str, _m: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("up:{project}"));
            self.up_result.clone()
        }
        fn compose_down(&self, project: &str, _m: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("down:{project}"));
            Ok(())
        }
    }

    struct AlwaysHealthy;
    impl HealthCheck for AlwaysHealthy {
        fn is_healthy(&self, _url: &str) -> bool {
            true
        }
    }
    struct NeverHealthy;
    impl HealthCheck for NeverHealthy {
        fn is_healthy(&self, _url: &str) -> bool {
            false
        }
    }

    fn req() -> StandupRequest {
        let dir = tempfile::tempdir().unwrap().keep();
        let mut r = StandupRequest::local(dir);
        r.host_port = 3399;
        r
    }

    #[test]
    fn healthy_node_yields_its_health_url() {
        let r = req();
        let out = stand_up(
            &r,
            &FakeEngine::ok(),
            &AlwaysHealthy,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(out.health_url, r.health_url());
    }

    #[test]
    fn missing_engine_fails_before_touching_the_host() {
        let r = req();
        let engine = FakeEngine {
            unavailable: Some("install a container engine".to_string()),
            up_result: Ok(()),
            calls: RefCell::new(vec![]),
        };
        let err = stand_up(&r, &engine, &AlwaysHealthy, Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, StandupError::NoEngine { .. }));
        // Never attempted to bring anything up.
        assert!(engine.calls.borrow().is_empty());
    }

    #[test]
    fn bring_up_failure_tears_down_so_nothing_is_left() {
        let r = req();
        let engine = FakeEngine {
            unavailable: None,
            up_result: Err("port already taken".to_string()),
            calls: RefCell::new(vec![]),
        };
        let err = stand_up(&r, &engine, &AlwaysHealthy, Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, StandupError::BringUpFailed { .. }));
        // A teardown followed the failed bring-up.
        assert!(engine.calls.borrow().iter().any(|c| c.starts_with("down:")));
    }

    #[test]
    fn came_up_but_never_healthy_is_a_distinct_failure_and_tears_down() {
        let r = req();
        let engine = FakeEngine::ok();
        let err = stand_up(&r, &engine, &NeverHealthy, Duration::from_millis(50)).unwrap_err();
        assert!(matches!(err, StandupError::Unhealthy { .. }));
        assert!(engine.calls.borrow().iter().any(|c| c.starts_with("down:")));
    }

    #[test]
    fn project_name_is_per_port() {
        assert_ne!(project_name(3333), project_name(3334));
        assert_eq!(project_name(3333), "auths-witness-3333");
    }

    #[test]
    fn standup_error_renders_one_line() {
        let e = StandupError::NoEngine {
            hint: "one actionable line".to_string(),
        };
        assert_eq!(e.to_string(), "one actionable line");
        assert!(!e.to_string().contains('\n'));
    }
}
