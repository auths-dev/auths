use std::path::Path;
use std::sync::OnceLock;

use tempfile::TempDir;

/// Initializes a temporary Git repository with basic user configuration.
///
/// Creates a new `TempDir`, calls `git2::Repository::init`, and sets
/// `user.name` / `user.email` so that commits work out of the box.
///
/// Usage:
/// ```ignore
/// let (temp_dir, repo) = init_test_repo();
/// ```
pub fn init_test_repo() -> (TempDir, git2::Repository) {
    let dir = TempDir::new().unwrap();
    let repo = git2::Repository::init(dir.path()).unwrap();

    let mut config = repo.config().unwrap();
    config.set_str("user.name", "Test User").unwrap();
    config.set_str("user.email", "test@example.com").unwrap();

    (dir, repo)
}

/// Returns a cloned copy of a lazily-initialized template Git repository.
///
/// The template is created once (via `OnceLock`) and reused across all calls
/// within the same test binary. Each call gets its own independent `TempDir`
/// containing a full copy of the template, so tests remain isolated.
///
/// Usage:
/// ```ignore
/// let temp_dir = get_cloned_test_repo();
/// let repo = git2::Repository::open(temp_dir.path()).unwrap();
/// ```
pub fn get_cloned_test_repo() -> TempDir {
    static TEMPLATE_DIR: OnceLock<TempDir> = OnceLock::new();

    let template = TEMPLATE_DIR.get_or_init(|| {
        let (dir, _repo) = init_test_repo();
        dir
    });

    let new_dir = TempDir::new().unwrap();
    copy_directory(template.path(), new_dir.path());
    new_dir
}

/// Recursively copies all files and directories from `src` to `dst`.
///
/// Handles nested directory structures. Does not follow symlinks — they are
/// skipped to avoid cycles or references outside the source tree.
///
/// Args:
/// * `src`: The source directory to copy from.
/// * `dst`: The destination directory to copy into (must already exist).
///
/// Usage:
/// ```ignore
/// copy_directory(Path::new("/tmp/source"), Path::new("/tmp/dest"));
/// ```
pub fn copy_directory(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let target = dst.join(entry.file_name());

        if path.is_symlink() {
            continue;
        }

        if path.is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy_directory(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap();
        }
    }
}
