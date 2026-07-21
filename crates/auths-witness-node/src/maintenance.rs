//! Registry housekeeping: periodic repack of the served KEL store.
//!
//! Every append writes loose git objects (~45 KB/identity measured by the
//! bulk-onboarding bench, `tests/scale/REPORT.md`), and nothing packs them —
//! disk grows unbounded and cold reads touch ever more files. `git gc --auto`
//! is the reference remedy: cheap when under threshold, packs when over. The
//! node runs it on a cadence rather than per-write so the write path never
//! stalls behind a repack.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

/// How often the node offers the registry to `git gc --auto`. The gc is a
/// no-op below git's loose-object threshold, so a short cadence costs one
/// subprocess spawn.
pub const REPACK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Run `git gc --auto` over the registry once.
///
/// Args:
/// * `registry`: Path to the served registry repository.
///
/// Usage:
/// ```ignore
/// maintenance::repack_registry(&args.registry).await?;
/// ```
pub async fn repack_registry(registry: &Path) -> Result<(), String> {
    let status = Command::new("git")
        .arg("-C")
        .arg(registry)
        .args(["gc", "--auto", "--quiet"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| format!("could not run git gc: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("git gc exited with {status}"))
    }
}

/// Spawn the periodic repack task for the served registry.
///
/// Failures are reported through `on_error` and the loop continues —
/// housekeeping must never take the node down.
///
/// Args:
/// * `registry`: Path to the served registry repository.
/// * `on_error`: Operator-facing reporter for failed repack attempts.
///
/// Usage:
/// ```ignore
/// maintenance::spawn_repack_task(args.registry.clone(), |e| eprintln!("{e}"));
/// ```
pub fn spawn_repack_task(
    registry: PathBuf,
    on_error: impl Fn(String) + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REPACK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(e) = repack_registry(&registry).await {
                on_error(format!("registry repack: {e}"));
            }
        }
    })
}
