//! Shared gate for the keripy-subprocess differentials.

/// Decide whether a keripy subprocess cross-check should run.
///
/// Returns `true` to run, `false` to skip. Panics if `KERIPY_REQUIRED=1` but keripy
/// is not reachable (the CI conformance job sets it), so a venv/PATH break fails the
/// build instead of silently reverting the cross-check to a self-oracle.
///
/// Args:
/// * `import_probe`: a python import statement that succeeds iff the keripy modules
///   this differential needs are importable (e.g. `"import keri.core.parsing"`).
///
/// Usage:
/// ```ignore
/// if !super::keripy_oracle::should_run_keripy("import keri.core.parsing") {
///     return;
/// }
/// ```
pub fn should_run_keripy(import_probe: &str) -> bool {
    let required = std::env::var("KERIPY_REQUIRED").ok().as_deref() == Some("1");
    if std::env::var("KERIPY_INTEROP").ok().as_deref() != Some("1") {
        assert!(!required, "KERIPY_REQUIRED=1 but KERIPY_INTEROP is not set");
        eprintln!("[SKIP] KERIPY_INTEROP != 1; not invoking keripy");
        return false;
    }
    let importable = std::process::Command::new("python3")
        .args(["-c", import_probe])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !importable {
        assert!(!required, "KERIPY_REQUIRED=1 but keripy is not importable");
        eprintln!("[SKIP] keripy not importable");
    }
    importable
}
