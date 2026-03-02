//! Git-backed storage for the Auths bridge.
//!
//! Implements `AuthsStorage` by reading KERI Key Event Logs and RIP-X
//! 2-blob attestations from a bare Git repository.

use std::sync::Mutex;

use auths_id::keri::event::Event;
use auths_id::keri::state::KeyState;
use auths_id::keri::validate::replay_kel;
use auths_verifier::core::Attestation;
use git2::{ErrorCode, Repository};
use radicle_core::{Did, RepoId};

use crate::attestation::{RadAttestation, RadCanonicalPayload};
use crate::bridge::BridgeError;
use crate::refs::Layout;
use crate::verify::AuthsStorage;

const EVENT_BLOB_NAME: &str = "event.json";

/// Git-backed implementation of `AuthsStorage`.
///
/// Reads KERI KEL events and RIP-X 2-blob attestations from a bare Git
/// repository. All operations are read-only. Wraps `git2::Repository` in
/// a `Mutex` because `Repository` is `Send` but not `Sync`.
///
/// Usage:
/// ```ignore
/// let storage = GitRadicleStorage::open("/path/to/bare/repo.git", Layout::radicle())?;
/// let key_state = storage.load_key_state(&"did:keri:EXq5abc".parse()?)?;
/// ```
pub struct GitRadicleStorage {
    repo: Mutex<Repository>,
    layout: Layout,
}

impl GitRadicleStorage {
    /// Opens a bare Git repository for reading.
    ///
    /// Args:
    /// * `path`: Path to the bare Git repository.
    /// * `layout`: Ref path configuration.
    ///
    /// Usage:
    /// ```ignore
    /// let storage = GitRadicleStorage::open("/path/to/repo.git", Layout::radicle())?;
    /// ```
    pub fn open(path: impl AsRef<std::path::Path>, layout: Layout) -> Result<Self, BridgeError> {
        let repo = Repository::open_bare(path.as_ref()).map_err(|e| {
            BridgeError::Repository(format!(
                "failed to open bare repo at {}: {e}",
                path.as_ref().display()
            ))
        })?;
        Ok(Self {
            repo: Mutex::new(repo),
            layout,
        })
    }

    fn lock_repo(&self) -> std::sync::MutexGuard<'_, Repository> {
        self.repo.lock().expect("repository mutex poisoned")
    }

    fn read_kel_events(&self, repo: &Repository) -> Result<Vec<Event>, BridgeError> {
        let reference = match repo.find_reference(&self.layout.keri_kel_ref) {
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
            let blob = repo
                .find_blob(entry.id())
                .map_err(|e| BridgeError::IdentityCorrupt(format!("blob read error: {e}")))?;
            let event: Event = serde_json::from_slice(blob.content())
                .map_err(|e| BridgeError::IdentityCorrupt(format!("invalid event JSON: {e}")))?;
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

    fn read_blob_at_ref(repo: &Repository, ref_path: &str) -> Result<Option<Vec<u8>>, BridgeError> {
        let reference = match repo.find_reference(ref_path) {
            Ok(r) => r,
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(None),
            Err(e) => {
                return Err(BridgeError::Repository(format!(
                    "ref lookup error for {ref_path}: {e}"
                )));
            }
        };

        let commit = reference
            .peel_to_commit()
            .map_err(|e| BridgeError::Repository(format!("{ref_path} is not a commit: {e}")))?;
        let tree = commit
            .tree()
            .map_err(|e| BridgeError::Repository(format!("missing tree at {ref_path}: {e}")))?;

        let blob_name = ref_path.rsplit('/').next().unwrap_or(ref_path);

        match tree.get_name(blob_name) {
            Some(entry) => {
                let blob = repo.find_blob(entry.id()).map_err(|e| {
                    BridgeError::Repository(format!("blob read error at {ref_path}: {e}"))
                })?;
                Ok(Some(blob.content().to_vec()))
            }
            None => Ok(None),
        }
    }
}

fn device_did_to_nid(did: &Did) -> Result<String, BridgeError> {
    match did {
        Did::Key(pk) => Ok(pk.to_human()),
        Did::Keri(_) => Err(BridgeError::InvalidDeviceKey(format!(
            "expected did:key, got {did}"
        ))),
    }
}

impl AuthsStorage for GitRadicleStorage {
    fn layout(&self) -> &Layout {
        &self.layout
    }

    fn load_key_state(&self, _identity_did: &Did) -> Result<KeyState, BridgeError> {
        let repo = self.lock_repo();
        let events = self.read_kel_events(&repo)?;
        if events.is_empty() {
            return Err(BridgeError::IdentityLoad("no KEL events found".into()));
        }
        replay_kel(&events)
            .map_err(|e| BridgeError::IdentityCorrupt(format!("KEL validation failed: {e}")))
    }

    fn load_attestation(
        &self,
        device_did: &Did,
        identity_did: &Did,
    ) -> Result<Attestation, BridgeError> {
        let nid = device_did_to_nid(device_did)?;
        let did_key_ref = self.layout.device_did_key_ref(&nid);
        let did_keri_ref = self.layout.device_did_keri_ref(&nid);

        let repo = self.lock_repo();
        let dk_blob = Self::read_blob_at_ref(&repo, &did_key_ref)?.ok_or_else(|| {
            BridgeError::AttestationLoad(format!("did-key blob missing for {nid}"))
        })?;
        let dkeri_blob = Self::read_blob_at_ref(&repo, &did_keri_ref)?.ok_or_else(|| {
            BridgeError::AttestationLoad(format!("did-keri blob missing for {nid}"))
        })?;
        drop(repo);

        let device_pk = match device_did {
            Did::Key(pk) => *pk,
            Did::Keri(_) => {
                return Err(BridgeError::InvalidDeviceKey(format!(
                    "expected did:key, got {device_did}"
                )));
            }
        };

        let payload = RadCanonicalPayload {
            did: identity_did.clone(),
            rid: RepoId::from_urn("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").expect("invalid dummy RID"),
        };

        let rad_att = RadAttestation::from_blobs(
            &dk_blob,
            &dkeri_blob,
            payload,
            device_did.clone(),
            device_pk,
        )
        .map_err(|e| BridgeError::AttestationLoad(format!("malformed attestation blobs: {e}")))?;

        Attestation::try_from(rad_att).map_err(|e| {
            BridgeError::AttestationLoad(format!("attestation conversion failed: {e}"))
        })
    }

    fn find_identity_for_device(
        &self,
        device_did: &Did,
        _repo_id: &RepoId,
    ) -> Result<Option<Did>, BridgeError> {
        let nid = device_did_to_nid(device_did)?;
        let sig_ref = self.layout.device_signatures_ref(&nid);

        let repo = self.lock_repo();
        match repo.find_reference(&format!("{sig_ref}/{}", self.layout.did_key_blob)) {
            Ok(_) => {}
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(None),
            Err(e) => return Err(BridgeError::Repository(format!("ref lookup error: {e}"))),
        }

        let events = self.read_kel_events(&repo)?;
        drop(repo);

        if events.is_empty() {
            return Ok(None);
        }

        let key_state = replay_kel(&events)
            .map_err(|e| BridgeError::IdentityCorrupt(format!("KEL replay failed: {e}")))?;

        Ok(Some(Did::Keri(key_state.prefix.to_string())))
    }

    fn list_devices(&self, _identity_did: &Did) -> Result<Vec<Did>, BridgeError> {
        let repo = self.lock_repo();
        let mut devices = Vec::new();
        let prefix = &self.layout.keys_prefix;
        let blob_name = &self.layout.did_keri_blob;

        let glob_pattern = format!("{prefix}/*/signatures/{blob_name}");
        let references = repo
            .references_glob(&glob_pattern)
            .map_err(|e| BridgeError::Repository(format!("failed to list device refs: {e}")))?;

        for reference in references {
            let reference = reference
                .map_err(|e| BridgeError::Repository(format!("reference error: {e}")))?;
            let name = reference
                .name()
                .ok_or_else(|| BridgeError::Repository("invalid ref name".into()))?;

            // Ref format: refs/keys/<nid>/signatures/did-keri
            let components: Vec<&str> = name.split('/').collect();
            if components.len() >= 3 {
                let nid = components[2];
                if let Ok(did) = format!("did:key:{nid}").parse::<Did>() {
                    devices.push(did);
                }
            }
        }

        Ok(devices)
    }

    fn local_identity_tip(&self, _identity_did: &Did) -> Result<Option<[u8; 20]>, BridgeError> {
        let repo = self.lock_repo();
        match repo.find_reference(&self.layout.keri_kel_ref) {
            Ok(reference) => {
                let commit = reference
                    .peel_to_commit()
                    .map_err(|e| BridgeError::Repository(format!("KEL ref not a commit: {e}")))?;
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
    use std::str::FromStr;
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

        let layout = Layout::radicle();
        let dk_ref = layout.device_did_key_ref(nid);
        let dkeri_ref = layout.device_did_keri_ref(nid);

        let sig = Signature::now("test", "test@test.com").unwrap();

        // Write did-key commit
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert(&layout.did_key_blob, dk_blob, 0o100644).unwrap();
        let tree_oid = tb.write().unwrap();
        drop(tb);
        let tree = repo.find_tree(tree_oid).unwrap();
        let commit_oid = repo
            .commit(None, &sig, &sig, "did-key", &tree, &[])
            .unwrap();
        point_ref(repo, &dk_ref, commit_oid);

        // Write did-keri commit
        let mut tb = repo.treebuilder(None).unwrap();
        tb.insert(&layout.did_keri_blob, dkeri_blob, 0o100644)
            .unwrap();
        let tree_oid = tb.write().unwrap();
        drop(tb);
        let tree = repo.find_tree(tree_oid).unwrap();
        let commit_oid = repo
            .commit(None, &sig, &sig, "did-keri", &tree, &[])
            .unwrap();
        point_ref(repo, &dkeri_ref, commit_oid);
    }

    #[test]
    fn load_key_state_from_kel() {
        let (_dir, repo) = create_bare_repo();
        let init = auths_id::keri::create_keri_identity(&repo, None).unwrap();
        let layout = Layout::radicle();

        let src_ref = format!("refs/did/keri/{}/kel", init.prefix.as_str());
        let reference = repo.find_reference(&src_ref).unwrap();
        let oid = reference.target().unwrap();
        drop(reference);
        point_ref(&repo, &layout.keri_kel_ref, oid);

        let storage = GitRadicleStorage {
            repo: Mutex::new(repo),
            layout,
        };
        let ks = storage.load_key_state(&init.did().parse().unwrap()).unwrap();
        assert_eq!(ks.prefix, init.prefix);
        assert_eq!(ks.sequence, 0);
    }

    #[test]
    fn local_identity_tip_returns_oid() {
        let (_dir, repo) = create_bare_repo();
        let icp = create_icp_event("ETestPrefix");
        let event = Event::Icp(icp);
        let commit_oid = write_kel_commit(&repo, &event, None);
        let layout = Layout::radicle();
        point_ref(&repo, &layout.keri_kel_ref, commit_oid);

        let storage = GitRadicleStorage {
            repo: Mutex::new(repo),
            layout,
        };
        let tip = storage.local_identity_tip(&"did:keri:ETestPrefix".parse().unwrap()).unwrap();
        assert!(tip.is_some());
        let tip_bytes = tip.unwrap();
        assert_eq!(tip_bytes, commit_oid.as_bytes()[..20]);
    }

    #[test]
    fn find_identity_with_attestation() {
        let (_dir, repo) = create_bare_repo();
        let init = auths_id::keri::create_keri_identity(&repo, None).unwrap();
        let layout = Layout::radicle();

        let src_ref = format!("refs/did/keri/{}/kel", init.prefix.as_str());
        let reference = repo.find_reference(&src_ref).unwrap();
        let oid = reference.target().unwrap();
        drop(reference);
        point_ref(&repo, &layout.keri_kel_ref, oid);

        let nid = "z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi";
        write_attestation_blobs(&repo, nid, &[1; 64], &[2; 64]);

        let storage = GitRadicleStorage {
            repo: Mutex::new(repo),
            layout,
        };
        let identity = storage
            .find_identity_for_device(&format!("did:key:{nid}").parse().unwrap(), &RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap())
            .unwrap();
        assert_eq!(identity.map(|d| d.to_string()), Some(init.did()));
    }
}
