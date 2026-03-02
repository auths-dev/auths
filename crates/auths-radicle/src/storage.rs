//! Git-backed storage for the Auths bridge.
//!
//! Implements `AuthsStorage` by reading KERI Key Event Logs and RIP-X
//! 2-blob attestations from a bare Git repository.

use auths_id::keri::event::Event;
use auths_id::keri::state::KeyState;
use auths_id::keri::validate::replay_kel;
use auths_verifier::core::Attestation;
use git2::{ErrorCode, Repository};

use crate::attestation::{RadAttestation, RadCanonicalPayload};
use crate::bridge::BridgeError;
use crate::identity::resolve_did_key_bytes;
use crate::refs;
use crate::verify::AuthsStorage;

const EVENT_BLOB_NAME: &str = "event.json";

/// Git-backed implementation of `AuthsStorage`.
///
/// Reads KERI KEL events and RIP-X 2-blob attestations from a bare Git
/// repository. All operations are read-only.
///
/// Usage:
/// ```ignore
/// let storage = GitRadicleStorage::open("/path/to/bare/repo.git")?;
/// let key_state = storage.load_key_state("did:keri:EXq5abc")?;
/// ```
pub struct GitRadicleStorage {
    repo: Repository,
}

impl GitRadicleStorage {
    /// Opens a bare Git repository for reading.
    ///
    /// Args:
    /// * `path`: Path to the bare Git repository.
    ///
    /// Usage:
    /// ```ignore
    /// let storage = GitRadicleStorage::open("/path/to/repo.git")?;
    /// ```
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, BridgeError> {
        let repo = Repository::open_bare(path.as_ref()).map_err(|e| {
            BridgeError::Repository(format!(
                "failed to open bare repo at {}: {e}",
                path.as_ref().display()
            ))
        })?;
        Ok(Self { repo })
    }

    fn read_kel_events(&self) -> Result<Vec<Event>, BridgeError> {
        let reference = match self.repo.find_reference(refs::KERI_KEL_REF) {
            Ok(r) => r,
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(vec![]),
            Err(e) => return Err(BridgeError::Repository(format!("KEL ref error: {e}"))),
        };

        let mut commit = reference
            .peel_to_commit()
            .map_err(|e| BridgeError::IdentityCorrupt(format!("KEL ref not a commit: {e}")))?;

        let mut events = Vec::new();
        loop {
            if commit.parent_count() > 1 {
                return Err(BridgeError::IdentityCorrupt(
                    "merge commit in KEL chain".into(),
                ));
            }

            let tree = commit
                .tree()
                .map_err(|e| BridgeError::IdentityCorrupt(format!("missing tree: {e}")))?;
            let entry = tree.get_name(EVENT_BLOB_NAME).ok_or_else(|| {
                BridgeError::IdentityCorrupt("missing event.json in KEL commit".into())
            })?;
            let blob = self
                .repo
                .find_blob(entry.id())
                .map_err(|e| BridgeError::IdentityCorrupt(format!("blob read error: {e}")))?;
            let event: Event = serde_json::from_slice(blob.content()).map_err(|e| {
                BridgeError::IdentityCorrupt(format!("invalid event JSON: {e}"))
            })?;
            events.push(event);

            if commit.parent_count() == 0 {
                break;
            }
            commit = commit
                .parent(0)
                .map_err(|e| BridgeError::IdentityCorrupt(format!("parent walk error: {e}")))?;
        }

        events.reverse();
        Ok(events)
    }

    fn read_blob_at_ref(&self, ref_path: &str) -> Result<Option<Vec<u8>>, BridgeError> {
        let reference = match self.repo.find_reference(ref_path) {
            Ok(r) => r,
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(None),
            Err(e) => {
                return Err(BridgeError::Repository(format!(
                    "ref lookup error for {ref_path}: {e}"
                )))
            }
        };

        let commit = reference.peel_to_commit().map_err(|e| {
            BridgeError::Repository(format!("{ref_path} is not a commit: {e}"))
        })?;
        let tree = commit.tree().map_err(|e| {
            BridgeError::Repository(format!("missing tree at {ref_path}: {e}"))
        })?;

        // The blob name is the last path component of the ref
        let blob_name = ref_path
            .rsplit('/')
            .next()
            .unwrap_or(ref_path);

        match tree.get_name(blob_name) {
            Some(entry) => {
                let blob = self.repo.find_blob(entry.id()).map_err(|e| {
                    BridgeError::Repository(format!("blob read error at {ref_path}: {e}"))
                })?;
                Ok(Some(blob.content().to_vec()))
            }
            None => Ok(None),
        }
    }
}

fn device_did_to_nid(device_did: &str) -> Result<&str, BridgeError> {
    device_did
        .strip_prefix("did:key:")
        .ok_or_else(|| BridgeError::InvalidDeviceKey(format!("expected did:key: prefix: {device_did}")))
}

impl AuthsStorage for GitRadicleStorage {
    fn load_key_state(&self, _identity_did: &str) -> Result<KeyState, BridgeError> {
        let events = self.read_kel_events()?;
        if events.is_empty() {
            return Err(BridgeError::IdentityLoad("no KEL events found".into()));
        }
        replay_kel(&events)
            .map_err(|e| BridgeError::IdentityCorrupt(format!("KEL validation failed: {e}")))
    }

    fn load_attestation(
        &self,
        device_did: &str,
        identity_did: &str,
    ) -> Result<Attestation, BridgeError> {
        let nid = device_did_to_nid(device_did)?;
        let did_key_ref = refs::device_did_key_ref(nid);
        let did_keri_ref = refs::device_did_keri_ref(nid);

        let dk_blob = self
            .read_blob_at_ref(&did_key_ref)?
            .ok_or_else(|| BridgeError::AttestationLoad(format!("did-key blob missing for {nid}")))?;
        let dkeri_blob = self
            .read_blob_at_ref(&did_keri_ref)?
            .ok_or_else(|| BridgeError::AttestationLoad(format!("did-keri blob missing for {nid}")))?;

        let device_pk_bytes = resolve_did_key_bytes(device_did).map_err(|e| {
            BridgeError::InvalidDeviceKey(format!("failed to resolve device public key: {e}"))
        })?;
        let device_pk: [u8; 32] = device_pk_bytes.try_into().map_err(|_| {
            BridgeError::InvalidDeviceKey("device public key is not 32 bytes".into())
        })?;

        let payload = RadCanonicalPayload {
            did: identity_did.to_string(),
            rid: String::new(),
        };

        let rad_att =
            RadAttestation::from_blobs(&dk_blob, &dkeri_blob, payload, device_did.to_string(), device_pk)
                .map_err(|e| BridgeError::AttestationLoad(format!("malformed attestation blobs: {e}")))?;

        Attestation::try_from(rad_att)
            .map_err(|e| BridgeError::AttestationLoad(format!("attestation conversion failed: {e}")))
    }

    fn find_identity_for_device(
        &self,
        device_did: &str,
        _repo_id: &str,
    ) -> Result<Option<String>, BridgeError> {
        let nid = device_did_to_nid(device_did)?;
        let sig_ref = refs::device_signatures_ref(nid);

        match self.repo.find_reference(&format!("{sig_ref}/{}", refs::DID_KEY_BLOB)) {
            Ok(_) => {}
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(None),
            Err(e) => {
                return Err(BridgeError::Repository(format!(
                    "ref lookup error: {e}"
                )))
            }
        }

        let events = self.read_kel_events()?;
        if events.is_empty() {
            return Ok(None);
        }

        let key_state = replay_kel(&events)
            .map_err(|e| BridgeError::IdentityCorrupt(format!("KEL replay failed: {e}")))?;

        Ok(Some(format!("did:keri:{}", key_state.prefix.as_str())))
    }

    fn local_identity_tip(&self, _identity_did: &str) -> Result<Option<[u8; 20]>, BridgeError> {
        match self.repo.find_reference(refs::KERI_KEL_REF) {
            Ok(reference) => {
                let commit = reference.peel_to_commit().map_err(|e| {
                    BridgeError::Repository(format!("KEL ref not a commit: {e}"))
                })?;
                let oid = commit.id();
                let raw = oid.as_bytes();
                let mut tip = [0u8; 20];
                tip.copy_from_slice(raw);
                Ok(Some(tip))
            }
            Err(e) if e.code() == ErrorCode::NotFound => Ok(None),
            Err(e) => Err(BridgeError::Repository(format!("KEL ref error: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_id::keri::event::{Event, IcpEvent};
    use auths_id::keri::types::{Prefix, Said};
    use git2::Signature;
    use tempfile::TempDir;

    fn create_bare_repo() -> (TempDir, Repository) {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init_bare(dir.path()).unwrap();
        (dir, repo)
    }

    fn create_icp_event(prefix: &str) -> IcpEvent {
        IcpEvent {
            v: "KERI10JSON".into(),
            d: Said::new_unchecked(prefix.to_string()),
            i: Prefix::new_unchecked(prefix.to_string()),
            s: "0".into(),
            kt: "1".into(),
            k: vec!["DTestKey123".into()],
            nt: "1".into(),
            n: vec!["ENextCommitment".into()],
            bt: "0".into(),
            b: vec![],
            a: vec![],
            x: String::new(),
        }
    }

    fn write_kel_commit(repo: &Repository, event: &Event, parent: Option<git2::Oid>) -> git2::Oid {
        let json = serde_json::to_vec(event).unwrap();
        let blob_oid = repo.blob(&json).unwrap();

        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert(EVENT_BLOB_NAME, blob_oid, 0o100644).unwrap();
        let tree_oid = tb.write().unwrap();
        drop(tb);

        let tree = repo.find_tree(tree_oid).unwrap();
        let sig = Signature::now("test", "test@test.com").unwrap();

        let parents: Vec<git2::Commit<'_>> = parent
            .into_iter()
            .map(|oid| repo.find_commit(oid).unwrap())
            .collect();
        let parent_refs: Vec<&git2::Commit<'_>> = parents.iter().collect();

        repo.commit(None, &sig, &sig, "KEL event", &tree, &parent_refs)
            .unwrap()
    }

    fn point_ref(repo: &Repository, ref_name: &str, oid: git2::Oid) {
        repo.reference(ref_name, oid, true, "test").unwrap();
    }

    fn write_attestation_blobs(
        repo: &Repository,
        nid: &str,
        did_key_bytes: &[u8],
        did_keri_bytes: &[u8],
    ) {
        let dk_blob = repo.blob(did_key_bytes).unwrap();
        let dkeri_blob = repo.blob(did_keri_bytes).unwrap();

        let dk_ref = refs::device_did_key_ref(nid);
        let dkeri_ref = refs::device_did_keri_ref(nid);

        let sig = Signature::now("test", "test@test.com").unwrap();

        // Write did-key commit
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert(refs::DID_KEY_BLOB, dk_blob, 0o100644).unwrap();
        let tree_oid = tb.write().unwrap();
        drop(tb);
        let tree = repo.find_tree(tree_oid).unwrap();
        let commit_oid = repo.commit(None, &sig, &sig, "did-key", &tree, &[]).unwrap();
        point_ref(repo, &dk_ref, commit_oid);

        // Write did-keri commit
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert(refs::DID_KERI_BLOB, dkeri_blob, 0o100644).unwrap();
        let tree_oid = tb.write().unwrap();
        drop(tb);
        let tree = repo.find_tree(tree_oid).unwrap();
        let commit_oid = repo.commit(None, &sig, &sig, "did-keri", &tree, &[]).unwrap();
        point_ref(repo, &dkeri_ref, commit_oid);
    }

    #[test]
    fn load_key_state_from_kel() {
        let (_dir, repo) = create_bare_repo();
        let icp = create_icp_event("ETestPrefix");
        let event = Event::Icp(icp);
        let commit_oid = write_kel_commit(&repo, &event, None);
        point_ref(&repo, refs::KERI_KEL_REF, commit_oid);

        let storage = GitRadicleStorage { repo };
        let ks = storage.load_key_state("did:keri:ETestPrefix").unwrap();
        assert_eq!(ks.prefix.as_str(), "ETestPrefix");
        assert_eq!(ks.sequence, 0);
    }

    #[test]
    fn load_key_state_missing_kel_returns_error() {
        let (_dir, repo) = create_bare_repo();
        let storage = GitRadicleStorage { repo };
        let result = storage.load_key_state("did:keri:ETestPrefix");
        assert!(result.is_err());
    }

    #[test]
    fn local_identity_tip_returns_oid() {
        let (_dir, repo) = create_bare_repo();
        let icp = create_icp_event("ETestPrefix");
        let event = Event::Icp(icp);
        let commit_oid = write_kel_commit(&repo, &event, None);
        point_ref(&repo, refs::KERI_KEL_REF, commit_oid);

        let storage = GitRadicleStorage { repo };
        let tip = storage.local_identity_tip("did:keri:ETestPrefix").unwrap();
        assert!(tip.is_some());
        let tip_bytes = tip.unwrap();
        assert_eq!(tip_bytes, commit_oid.as_bytes()[..20]);
    }

    #[test]
    fn local_identity_tip_missing_returns_none() {
        let (_dir, repo) = create_bare_repo();
        let storage = GitRadicleStorage { repo };
        let tip = storage.local_identity_tip("did:keri:ETestPrefix").unwrap();
        assert!(tip.is_none());
    }

    #[test]
    fn find_identity_with_attestation() {
        let (_dir, repo) = create_bare_repo();

        let icp = create_icp_event("ETestPrefix");
        let event = Event::Icp(icp);
        let commit_oid = write_kel_commit(&repo, &event, None);
        point_ref(&repo, refs::KERI_KEL_REF, commit_oid);

        let nid = "z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi";
        write_attestation_blobs(&repo, nid, &[1; 64], &[2; 64]);

        let storage = GitRadicleStorage { repo };
        let identity = storage
            .find_identity_for_device(&format!("did:key:{nid}"), "rad:test")
            .unwrap();
        assert_eq!(identity, Some("did:keri:ETestPrefix".to_string()));
    }

    #[test]
    fn find_identity_no_attestation_returns_none() {
        let (_dir, repo) = create_bare_repo();

        let icp = create_icp_event("ETestPrefix");
        let event = Event::Icp(icp);
        let commit_oid = write_kel_commit(&repo, &event, None);
        point_ref(&repo, refs::KERI_KEL_REF, commit_oid);

        let storage = GitRadicleStorage { repo };
        let identity = storage
            .find_identity_for_device("did:key:z6MkUnknownDevice", "rad:test")
            .unwrap();
        assert!(identity.is_none());
    }

    #[test]
    fn merge_commit_in_kel_rejected() {
        let (_dir, repo) = create_bare_repo();

        let icp = create_icp_event("ETestPrefix");
        let event = Event::Icp(icp);
        let c1 = write_kel_commit(&repo, &event, None);
        let c2 = write_kel_commit(&repo, &event, None);

        // Create a merge commit
        let sig = Signature::now("test", "test@test.com").unwrap();
        let p1 = repo.find_commit(c1).unwrap();
        let p2 = repo.find_commit(c2).unwrap();
        let blob = repo.blob(b"{}").unwrap();
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert(EVENT_BLOB_NAME, blob, 0o100644).unwrap();
        let tree_oid = tb.write().unwrap();
        drop(tb);
        let tree = repo.find_tree(tree_oid).unwrap();
        let merge_oid = repo
            .commit(None, &sig, &sig, "merge", &tree, &[&p1, &p2])
            .unwrap();
        point_ref(&repo, refs::KERI_KEL_REF, merge_oid);

        let storage = GitRadicleStorage { repo };
        let result = storage.load_key_state("did:keri:ETestPrefix");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("merge commit"));
    }

    #[test]
    fn open_non_bare_repo_fails() {
        let dir = TempDir::new().unwrap();
        Repository::init(dir.path()).unwrap(); // non-bare
        let result = GitRadicleStorage::open(dir.path());
        assert!(result.is_err());
    }
}
