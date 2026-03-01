use std::path::Path;

use auths_core::ports::storage::StorageError;
use auths_infra_git::GitRepo;

/// Opens an existing Git repository at the given path.
///
/// Args:
/// * `path`: Filesystem path to the repository root.
///
/// Usage:
/// ```ignore
/// use auths_cli::factories::storage::open_git_repo;
///
/// let repo = open_git_repo(Path::new("/home/user/.auths"))?;
/// ```
pub fn open_git_repo(path: &Path) -> Result<GitRepo, StorageError> {
    GitRepo::open(path)
}

/// Initializes a new Git repository at the given path.
///
/// Args:
/// * `path`: Filesystem path where the repository will be created.
///
/// Usage:
/// ```ignore
/// let repo = init_git_repo(Path::new("/tmp/new-repo"))?;
/// ```
pub fn init_git_repo(path: &Path) -> Result<GitRepo, StorageError> {
    GitRepo::init(path)
}

/// Opens an existing Git repository or initializes a new one.
///
/// If the path exists and contains a Git repository, opens it.
/// If the path exists but is not a Git repository, initializes one.
/// If the path does not exist, creates directories and initializes.
///
/// Args:
/// * `path`: Filesystem path to open or create a repository at.
///
/// Usage:
/// ```ignore
/// let repo = ensure_git_repo(Path::new("/data/auths"))?;
/// ```
pub fn ensure_git_repo(path: &Path) -> Result<GitRepo, StorageError> {
    if path.exists() {
        match GitRepo::open(path) {
            Ok(repo) => Ok(repo),
            Err(_) => GitRepo::init(path),
        }
    } else {
        std::fs::create_dir_all(path)
            .map_err(|e| StorageError::Io(format!("failed to create directory: {}", e)))?;
        GitRepo::init(path)
    }
}

/// Discovers a Git repository starting from the given path, walking up parent directories.
///
/// Returns the working directory of the discovered repository.
///
/// Args:
/// * `start_path`: Directory to begin searching from.
///
/// Usage:
/// ```ignore
/// let repo_root = discover_git_repo(Path::new("."))?;
/// ```
pub fn discover_git_repo(start_path: &Path) -> Result<std::path::PathBuf, StorageError> {
    let repo = git2::Repository::discover(start_path)
        .map_err(|e| StorageError::not_found(format!("no Git repository found: {}", e)))?;
    let path: &Path = repo
        .workdir()
        .or_else(|| repo.path().parent())
        .ok_or_else(|| StorageError::Io("could not determine repository path".into()))?;
    Ok(path.to_path_buf())
}

/// Reads a Git configuration value from the default config.
///
/// Args:
/// * `key`: The Git configuration key (e.g. "gpg.ssh.allowedSignersFile").
///
/// Usage:
/// ```ignore
/// let value = read_git_config("user.email")?;
/// ```
pub fn read_git_config(key: &str) -> Result<Option<String>, StorageError> {
    let config = git2::Config::open_default()
        .map_err(|e| StorageError::Io(format!("failed to open git config: {}", e)))?;
    match config.get_string(key) {
        Ok(value) => Ok(Some(value)),
        Err(_) => Ok(None),
    }
}
