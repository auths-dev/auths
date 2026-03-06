use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use auths_core::config::EnvironmentConfig;
use auths_core::ports::clock::SystemClock;
use auths_core::ports::storage::StorageError;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::get_platform_keychain_with_config;
use auths_id::attestation::export::AttestationSink;
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_infra_git::GitRepo;
use auths_sdk::context::AuthsContext;
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};

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

/// Builds a canonical `AuthsContext` for CLI commands.
///
/// This is the single composition root for all storage and keychain wiring.
/// All commands that need an `AuthsContext` must use this function instead
/// of assembling the context inline.
///
/// Args:
/// * `repo_path`: Path to the auths registry Git repository.
/// * `env_config`: Environment configuration used to select the keychain backend.
/// * `passphrase_provider`: Optional passphrase provider; `None` uses the keychain default.
///
/// Usage:
/// ```ignore
/// let ctx = build_auths_context(&repo_path, &env_config, Some(passphrase_provider))?;
/// ```
pub fn build_auths_context(
    repo_path: &Path,
    env_config: &EnvironmentConfig,
    passphrase_provider: Option<Arc<dyn PassphraseProvider + Send + Sync>>,
) -> Result<AuthsContext> {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(repo_path)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(repo_path.to_path_buf()));
    let attestation_store = Arc::new(RegistryAttestationStorage::new(repo_path));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&attestation_store) as Arc<dyn AttestationSink + Send + Sync>;
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        attestation_store as Arc<dyn AttestationSource + Send + Sync>;
    let key_storage = get_platform_keychain_with_config(env_config)
        .map_err(|e| anyhow::anyhow!("Failed to initialize keychain: {}", e))?;
    let mut builder = AuthsContext::builder()
        .registry(backend)
        .key_storage(Arc::from(key_storage))
        .clock(Arc::new(SystemClock))
        .identity_storage(identity_storage)
        .attestation_sink(attestation_sink)
        .attestation_source(attestation_source);
    if let Some(pp) = passphrase_provider {
        builder = builder.passphrase_provider(pp);
    }
    Ok(builder.build()?)
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
