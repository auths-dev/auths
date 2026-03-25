//! Capsec test helpers for creating capability tokens in tests.

use capsec::SendCap;

/// All capability tokens needed by adapter tests.
pub struct TestCaps {
    pub fs_read: SendCap<capsec::FsRead>,
    pub fs_write: SendCap<capsec::FsWrite>,
    pub net_connect: SendCap<capsec::NetConnect>,
    pub spawn: SendCap<capsec::Spawn>,
}

/// Creates a full set of test capability tokens via `capsec::test_root()`.
///
/// Usage:
/// ```ignore
/// let caps = auths_test_utils::caps::test_caps();
/// let repo = GitRepo::open(path, caps.fs_read.clone(), caps.fs_write.clone())?;
/// ```
pub fn test_caps() -> TestCaps {
    let root = capsec::test_root();
    TestCaps {
        fs_read: root.fs_read().make_send(),
        fs_write: root.fs_write().make_send(),
        net_connect: root.net_connect().make_send(),
        spawn: root.spawn().make_send(),
    }
}
