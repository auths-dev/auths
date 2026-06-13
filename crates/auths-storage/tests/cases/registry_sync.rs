//! Registry push/pull over a git remote: fast-forward-only publish, and the
//! validated merge on pull (authenticated import/advance, unsigned refusal,
//! fork refusal, idempotence).

use auths_id::keri::sync::{MergeOutcome, RegistryMergeError};
use auths_id::ports::registry::RegistryBackend;
use auths_keri::{
    Event, IndexedSignature, IxnEvent, KeriSequence, Prefix, Said, Seal, VersionString,
    finalize_ixn_event, serialize_attachment, serialize_for_signing,
};
use auths_storage::git::sync::{PushOutcome, RegistrySyncError, pull_registry, push_registry};
use auths_storage::git::{GitRegistryBackend, RegistryConfig};
use ring::signature::Ed25519KeyPair;
use tempfile::TempDir;

use super::mock_ed25519_keypairs::{mock_inception_event, mock_keypair};

/// Sign `event` with `signer`; return the CESR attachment bytes.
fn attachment_for(signer: &Ed25519KeyPair, event: &Event) -> Vec<u8> {
    let sig = signer
        .sign(&serialize_for_signing(event).unwrap())
        .as_ref()
        .to_vec();
    serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig,
    }])
    .unwrap()
}

fn fresh_registry() -> (GitRegistryBackend, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let backend =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path()));
    backend.init_if_needed().unwrap();
    (backend, dir)
}

/// A registry holding identity `index`'s fully-signed inception.
fn signed_registry(index: usize) -> (GitRegistryBackend, TempDir, Ed25519KeyPair, Event, Prefix) {
    let (backend, dir) = fresh_registry();
    let signer = mock_keypair(index * 2);
    let event = mock_inception_event(index);
    let prefix = event.prefix().clone();
    let attachment = attachment_for(&signer, &event);
    backend
        .append_signed_event(&prefix, &event, &attachment)
        .unwrap();
    (backend, dir, signer, event, prefix)
}

/// A signed interaction event extending `prior` at sequence `seq`.
fn signed_ixn(
    signer: &Ed25519KeyPair,
    prefix: &Prefix,
    prior: &Said,
    seq: u128,
    anchors: Vec<Seal>,
) -> (Event, Vec<u8>) {
    let ixn = IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(seq),
        p: prior.clone(),
        a: anchors,
    };
    let event = Event::Ixn(finalize_ixn_event(ixn).unwrap());
    let attachment = attachment_for(signer, &event);
    (event, attachment)
}

fn bare_remote() -> (TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    git2::Repository::init_bare(dir.path()).unwrap();
    let url = format!("file://{}", dir.path().display());
    (dir, url)
}

#[test]
fn push_then_pull_imports_authenticated_kel() {
    let (_src, src_dir, _signer, event, prefix) = signed_registry(0);
    let (_remote_dir, url) = bare_remote();

    assert_eq!(
        push_registry(src_dir.path(), &url).unwrap(),
        PushOutcome::Updated
    );
    // Re-pushing the same tip is a no-op, not an error.
    assert_eq!(
        push_registry(src_dir.path(), &url).unwrap(),
        PushOutcome::AlreadyCurrent
    );

    let dest_dir = tempfile::tempdir().unwrap();
    let merged = pull_registry(dest_dir.path(), &url).unwrap();
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].prefix, prefix);
    assert!(matches!(
        merged[0].outcome,
        MergeOutcome::Imported { events: 1 }
    ));

    // The destination's copy is the same event WITH its signature attachment —
    // still authenticatable, not merely structurally replayable.
    let dest =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dest_dir.path()));
    assert_eq!(dest.get_event(&prefix, 0).unwrap(), event);
    assert!(dest.get_attachment(&prefix, 0).unwrap().is_some());
}

#[test]
fn pull_advances_then_reports_already_current() {
    let (src, src_dir, signer, event, prefix) = signed_registry(1);
    let (_remote_dir, url) = bare_remote();
    push_registry(src_dir.path(), &url).unwrap();

    let dest_dir = tempfile::tempdir().unwrap();
    pull_registry(dest_dir.path(), &url).unwrap();

    // The source advances (a signed interaction) and re-publishes (fast-forward).
    let (ixn, ixn_att) = signed_ixn(&signer, &prefix, event.said(), 1, vec![]);
    src.append_signed_event(&prefix, &ixn, &ixn_att).unwrap();
    assert_eq!(
        push_registry(src_dir.path(), &url).unwrap(),
        PushOutcome::Updated
    );

    let merged = pull_registry(dest_dir.path(), &url).unwrap();
    assert!(matches!(
        merged[0].outcome,
        MergeOutcome::Advanced { events: 1 }
    ));

    // Pulling again changes nothing — the merge is idempotent.
    let merged = pull_registry(dest_dir.path(), &url).unwrap();
    assert!(matches!(merged[0].outcome, MergeOutcome::AlreadyCurrent));
}

#[test]
fn push_refuses_diverged_remote() {
    let (_a, a_dir, _sa, _ea, _pa) = signed_registry(2);
    let (_b, b_dir, _sb, _eb, _pb) = signed_registry(3);
    let (_remote_dir, url) = bare_remote();

    push_registry(a_dir.path(), &url).unwrap();
    // B's registry shares no history with A's — pushing it would discard A.
    let err = push_registry(b_dir.path(), &url).unwrap_err();
    assert!(matches!(err, RegistrySyncError::Diverged));
}

#[test]
fn push_without_local_registry_fails_actionably() {
    let empty = tempfile::tempdir().unwrap();
    let (_remote_dir, url) = bare_remote();
    let err = push_registry(empty.path(), &url).unwrap_err();
    assert!(matches!(err, RegistrySyncError::OpenLocal { .. }));
}

#[test]
fn pull_refuses_unsigned_kel() {
    // An event persisted WITHOUT its signature attachment cannot be
    // authenticated — the pull refuses the whole registry (fail closed).
    let (backend, src_dir) = fresh_registry();
    let event = mock_inception_event(4);
    let prefix = event.prefix().clone();
    backend.append_event(&prefix, &event).unwrap();
    let (_remote_dir, url) = bare_remote();
    push_registry(src_dir.path(), &url).unwrap();

    let dest_dir = tempfile::tempdir().unwrap();
    let err = pull_registry(dest_dir.path(), &url).unwrap_err();
    assert!(matches!(
        err,
        RegistrySyncError::Merge(RegistryMergeError::MissingSignature { .. })
    ));
}

#[test]
fn pull_refuses_forked_kel() {
    // Source and destination share an inception but diverge at sequence 1 —
    // the merge must refuse, never silently pick a side.
    let (src, src_dir, signer, event, prefix) = signed_registry(5);
    let (ixn_src, att_src) = signed_ixn(&signer, &prefix, event.said(), 1, vec![]);
    src.append_signed_event(&prefix, &ixn_src, &att_src)
        .unwrap();
    let (_remote_dir, url) = bare_remote();
    push_registry(src_dir.path(), &url).unwrap();

    let dest_dir = tempfile::tempdir().unwrap();
    let dest =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dest_dir.path()));
    dest.init_if_needed().unwrap();
    dest.append_signed_event(&prefix, &event, &attachment_for(&signer, &event))
        .unwrap();
    let (ixn_dest, att_dest) = signed_ixn(
        &signer,
        &prefix,
        event.said(),
        1,
        vec![Seal::Digest {
            d: event.said().clone(),
        }],
    );
    dest.append_signed_event(&prefix, &ixn_dest, &att_dest)
        .unwrap();

    let err = pull_registry(dest_dir.path(), &url).unwrap_err();
    assert!(matches!(
        err,
        RegistrySyncError::Merge(RegistryMergeError::Forked { sequence: 1, .. })
    ));
}

#[test]
fn pull_into_unprovisioned_root_provisions_it() {
    // A fresh machine (no ~/.auths at all) can pull before `auths init`.
    let (_src, src_dir, _signer, _event, prefix) = signed_registry(6);
    let (_remote_dir, url) = bare_remote();
    push_registry(src_dir.path(), &url).unwrap();

    let dest_root = tempfile::tempdir().unwrap();
    let dest_path = dest_root.path().join("never-initialized");
    let merged = pull_registry(&dest_path, &url).unwrap();
    assert_eq!(merged.len(), 1);

    let dest = GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&dest_path));
    assert!(matches!(
        dest.get_tip(&prefix),
        Ok(tip) if tip.sequence == 0
    ));
}

#[test]
fn pull_from_remote_without_registry_fails_actionably() {
    let (_remote_dir, url) = bare_remote();
    let dest_dir = tempfile::tempdir().unwrap();
    let err = pull_registry(dest_dir.path(), &url).unwrap_err();
    assert!(matches!(err, RegistrySyncError::Fetch(_)));
}
