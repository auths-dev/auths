use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

pub struct TestEnv {
    pub home: TempDir,
    pub repo_path: PathBuf,
    pub auths_home: PathBuf,
    bin_dir: PathBuf,
}

impl TestEnv {
    pub fn new() -> Self {
        let home = TempDir::new().unwrap();
        let home_path = home.path();

        let auths_home = home_path.join(".auths");
        std::fs::create_dir_all(&auths_home).unwrap();

        let repo_path = home_path.join("test-repo");
        git2::Repository::init(&repo_path).unwrap();

        let gitconfig = home_path.join(".gitconfig");
        std::fs::write(
            &gitconfig,
            "[user]\n\tname = Test User\n\temail = test@example.com\n",
        )
        .unwrap();

        let ssh_dir = home_path.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();

        let target_dir = Command::cargo_bin("auths-sign")
            .unwrap()
            .get_program()
            .to_owned();
        let bin_dir = PathBuf::from(target_dir).parent().unwrap().to_path_buf();

        Self {
            home,
            repo_path,
            auths_home,
            bin_dir,
        }
    }

    fn env_path(&self) -> String {
        let path = std::env::var("PATH").unwrap_or_default();
        format!("{}:{}", self.bin_dir.display(), path)
    }

    pub fn cmd(&self, bin: &str) -> Command {
        let mut cmd = Command::cargo_bin(bin).unwrap();
        self.apply_env_cmd(&mut cmd);
        cmd
    }

    pub fn git_cmd(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("git");
        self.apply_env_std(&mut cmd);
        cmd
    }

    fn apply_env_cmd(&self, cmd: &mut Command) {
        let home_path = self.home.path();
        cmd.env("HOME", home_path)
            .env("AUTHS_HOME", &self.auths_home)
            .env("AUTHS_KEYCHAIN_BACKEND", "file")
            .env("AUTHS_KEYCHAIN_FILE", home_path.join("keys.enc"))
            .env("AUTHS_PASSPHRASE", "Test-Passphrase-1!")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", home_path.join(".gitconfig"))
            .env("PATH", self.env_path())
            .current_dir(&self.repo_path);
    }

    fn apply_env_std(&self, cmd: &mut std::process::Command) {
        let home_path = self.home.path();
        cmd.env("HOME", home_path)
            .env("AUTHS_HOME", &self.auths_home)
            .env("AUTHS_KEYCHAIN_BACKEND", "file")
            .env("AUTHS_KEYCHAIN_FILE", home_path.join("keys.enc"))
            .env("AUTHS_PASSPHRASE", "Test-Passphrase-1!")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", home_path.join(".gitconfig"))
            .env("PATH", self.env_path())
            .current_dir(&self.repo_path);
    }

    pub fn allowed_signers_path(&self) -> PathBuf {
        self.home.path().join(".ssh").join("allowed_signers")
    }

    pub fn init_identity(&self) {
        let output = self
            .cmd("auths")
            .args(["init", "--non-interactive", "--profile", "developer"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
