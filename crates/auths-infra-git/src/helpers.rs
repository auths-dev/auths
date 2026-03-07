use git2::{Oid, Repository, Signature};

pub(crate) fn resolve_git_ref(repo: &Repository, refname: &str) -> Result<Oid, git2::Error> {
    let reference = repo.find_reference(refname)?;
    let commit = reference.peel_to_commit()?;
    Ok(commit.id())
}

pub(crate) fn extract_blob_payload(
    repo: &Repository,
    tree_oid: Oid,
    blob_name: &str,
) -> Result<Vec<u8>, git2::Error> {
    let tree = repo.find_tree(tree_oid)?;
    let entry = tree
        .get_name(blob_name)
        .ok_or_else(|| git2::Error::from_str(&format!("blob '{}' not found in tree", blob_name)))?;
    let blob = repo.find_blob(entry.id())?;
    Ok(blob.content().to_vec())
}

pub(crate) fn create_ref_commit(
    repo: &Repository,
    refname: &str,
    data: &[u8],
    blob_name: &str,
    message: &str,
) -> Result<Oid, git2::Error> {
    let sig = default_signature(repo)?;
    let blob_oid = repo.blob(data)?;

    let mut tree_builder = repo.treebuilder(None)?;
    tree_builder.insert(blob_name, blob_oid, 0o100644)?;
    let tree_oid = tree_builder.write()?;
    let tree = repo.find_tree(tree_oid)?;

    let parent = match repo.find_reference(refname) {
        Ok(r) => Some(r.peel_to_commit()?),
        Err(e) if e.code() == git2::ErrorCode::NotFound => None,
        Err(e) => return Err(e),
    };

    let parents: Vec<&git2::Commit> = parent.iter().collect();
    let commit_oid = repo.commit(Some(refname), &sig, &sig, message, &tree, &parents)?;
    Ok(commit_oid)
}

pub(crate) fn list_refs_matching(
    repo: &Repository,
    glob: &str,
) -> Result<Vec<String>, git2::Error> {
    let mut result = Vec::new();
    for reference in repo.references_glob(glob)? {
        let reference = reference?;
        if let Some(name) = reference.name() {
            result.push(name.to_string());
        }
    }
    Ok(result)
}

#[allow(clippy::disallowed_methods)] // Infrastructure boundary: Utc::now() acceptable here
fn default_signature(repo: &Repository) -> Result<Signature<'_>, git2::Error> {
    repo.signature().or_else(|_| {
        let now = chrono::Utc::now();
        Signature::new(
            "auths",
            "auths@localhost",
            &git2::Time::new(now.timestamp(), 0),
        )
    })
}
