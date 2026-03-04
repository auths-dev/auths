use auths_infra_git::audit::Git2LogProvider;
use auths_sdk::ports::git::{CommitRecord, SignatureStatus};
use auths_sdk::testing::fakes::FakeGitLogProvider;

fn make_test_commit(hash: &str) -> CommitRecord {
    CommitRecord {
        hash: hash.to_string(),
        author_name: "Test Author".to_string(),
        author_email: "test@example.com".to_string(),
        timestamp: "2024-01-15T10:00:00+00:00".to_string(),
        message: "test commit".to_string(),
        signature_status: SignatureStatus::Unsigned,
    }
}

fn create_commit(repo: &git2::Repository, message: &str) {
    let sig = repo.signature().unwrap();
    let tree_builder = repo.treebuilder(None).unwrap();
    let tree_oid = tree_builder.write().unwrap();
    let tree = repo.find_tree(tree_oid).unwrap();

    let parents: Vec<git2::Commit<'_>> = match repo.head() {
        Ok(head) => {
            let oid = head.target().unwrap();
            vec![repo.find_commit(oid).unwrap()]
        }
        Err(_) => vec![],
    };
    let parent_refs: Vec<&git2::Commit<'_>> = parents.iter().collect();
    repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
        .unwrap();
}

auths_sdk::git_log_provider_contract_tests!(
    fake,
    {
        let commits = vec![
            make_test_commit("abc1"),
            make_test_commit("def2"),
            make_test_commit("ghi3"),
        ];
        (FakeGitLogProvider::with_commits(commits), ())
    },
    3,
);

auths_sdk::git_log_provider_contract_tests!(
    git2_provider,
    {
        let (dir, repo) = auths_test_utils::git::init_test_repo();
        create_commit(&repo, "first");
        create_commit(&repo, "second");
        create_commit(&repo, "third");
        let provider = Git2LogProvider::open(dir.path()).unwrap();
        (provider, dir)
    },
    3,
);
