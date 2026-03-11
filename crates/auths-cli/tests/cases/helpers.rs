use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

pub struct TestEnv {
    pub home: TempDir,
    pub repo_path: PathBuf,
    pub auths_home: PathBuf,
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

        Self {
            home,
            repo_path,
            auths_home,
        }
    }

    pub fn cmd(&self, bin: &str) -> Command {
        let mut cmd = Command::cargo_bin(bin).unwrap();
        let home_path = self.home.path();

        let target_dir = Command::cargo_bin("auths-sign")
            .unwrap()
            .get_program()
            .to_owned();
        let bin_dir = PathBuf::from(target_dir).parent().unwrap().to_path_buf();

        let path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.display(), path);

        cmd.env("HOME", home_path)
            .env("AUTHS_HOME", &self.auths_home)
            .env("AUTHS_KEYCHAIN_BACKEND", "file")
            .env("AUTHS_KEYCHAIN_FILE", home_path.join("keys.enc"))
            .env("AUTHS_PASSPHRASE", "test-passphrase-for-cli-integration")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", home_path.join(".gitconfig"))
            .env("PATH", new_path)
            .current_dir(&self.repo_path);

        cmd
    }
}
