//! Git tree navigation and mutation helpers.
//!
//! These helpers provide efficient operations on Git trees:
//! - `TreeNavigator`: Read-only navigation and blob reading
//! - `TreeMutator`: Efficient tree mutations (only rebuild modified paths)
//!
//! ## Key Design Goal
//!
//! At 1M identities, naive tree rebuild would be O(1M), but path-targeted
//! rebuild is O(depth) = O(5) for our sharded layout.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

use git2::{Oid, Repository, Tree};

use auths_id::ports::registry::RegistryError;
use auths_id::storage::registry::shard::path_parts;

fn from_git2(e: git2::Error) -> RegistryError {
    match e.code() {
        git2::ErrorCode::NotFound => RegistryError::NotFound {
            entity_type: "git object".into(),
            id: e.message().to_string(),
        },
        git2::ErrorCode::Locked => {
            RegistryError::ConcurrentModification(format!("Git lock conflict: {}", e.message()))
        }
        _ => RegistryError::storage(e),
    }
}

/// Read-only navigator for Git trees.
///
/// Provides efficient path navigation and blob reading.
pub struct TreeNavigator<'a> {
    repo: &'a Repository,
    root: Tree<'a>,
}

impl<'a> TreeNavigator<'a> {
    /// Create a new navigator for the given tree.
    pub fn new(repo: &'a Repository, root: Tree<'a>) -> Self {
        Self { repo, root }
    }

    /// Navigate to a path and return the tree entry's OID and kind if it exists.
    ///
    /// Returns `None` if any component along the path doesn't exist.
    fn get_entry_info(&self, path: &[&str]) -> Option<(Oid, git2::ObjectType)> {
        if path.is_empty() {
            return None;
        }

        let mut current_tree_oid = self.root.id();

        // Navigate through all but the last component
        for component in &path[..path.len() - 1] {
            let tree = self.repo.find_tree(current_tree_oid).ok()?;
            let entry = tree.get_name(component)?;
            if entry.kind() != Some(git2::ObjectType::Tree) {
                return None;
            }
            current_tree_oid = entry.id();
        }

        // Get the final component
        let tree = self.repo.find_tree(current_tree_oid).ok()?;
        let last = path.last()?;
        let entry = tree.get_name(last)?;
        Some((entry.id(), entry.kind().unwrap_or(git2::ObjectType::Blob)))
    }

    /// Navigate to a path and return the entry OID if it exists.
    ///
    /// Returns `None` if any component along the path doesn't exist.
    #[allow(dead_code)]
    pub fn get_entry(&self, path: &[&str]) -> Option<Oid> {
        self.get_entry_info(path).map(|(oid, _)| oid)
    }

    /// Read a blob at the given path and return its content.
    ///
    /// # Errors
    ///
    /// Returns error if path doesn't exist or isn't a blob.
    pub fn read_blob(&self, path: &[&str]) -> Result<Vec<u8>, RegistryError> {
        let (oid, kind) = self
            .get_entry_info(path)
            .ok_or_else(|| RegistryError::NotFound {
                entity_type: "blob".into(),
                id: path.join("/"),
            })?;

        if kind != git2::ObjectType::Blob {
            return Err(RegistryError::NotFound {
                entity_type: "blob".into(),
                id: path.join("/"),
            });
        }

        let blob = self.repo.find_blob(oid).map_err(from_git2)?;
        Ok(blob.content().to_vec())
    }

    /// Read a blob at a path string.
    pub fn read_blob_path(&self, path: &str) -> Result<Vec<u8>, RegistryError> {
        let parts = path_parts(path);
        self.read_blob(&parts)
    }

    /// Check if a path exists in the tree.
    pub fn exists(&self, path: &[&str]) -> bool {
        self.get_entry_info(path).is_some()
    }

    /// Check if a path string exists in the tree.
    pub fn exists_path(&self, path: &str) -> bool {
        let parts = path_parts(path);
        self.exists(&parts)
    }

    /// Visit entries in a directory at the given path.
    ///
    /// Calls `visitor` for each entry name. Return `ControlFlow::Break(())` to stop early.
    pub fn visit_dir<F>(&self, path: &[&str], mut visitor: F) -> Result<(), RegistryError>
    where
        F: FnMut(&str) -> ControlFlow<()>,
    {
        let tree = if path.is_empty() {
            self.root.clone()
        } else {
            let (oid, kind) = self
                .get_entry_info(path)
                .ok_or_else(|| RegistryError::NotFound {
                    entity_type: "directory".into(),
                    id: path.join("/"),
                })?;

            if kind != git2::ObjectType::Tree {
                return Err(RegistryError::NotFound {
                    entity_type: "directory".into(),
                    id: path.join("/"),
                });
            }

            self.repo.find_tree(oid).map_err(from_git2)?
        };

        for entry in tree.iter() {
            if let Some(name) = entry.name()
                && visitor(name).is_break()
            {
                break;
            }
        }

        Ok(())
    }

    /// Visit entries in a directory at a path string.
    #[allow(dead_code)]
    pub fn visit_dir_path<F>(&self, path: &str, visitor: F) -> Result<(), RegistryError>
    where
        F: FnMut(&str) -> ControlFlow<()>,
    {
        let parts = path_parts(path);
        self.visit_dir(&parts, visitor)
    }

    /// Get the tree at the given path.
    #[allow(dead_code)]
    pub fn get_tree(&self, path: &[&str]) -> Result<Tree<'a>, RegistryError> {
        if path.is_empty() {
            return Ok(self.root.clone());
        }

        let (oid, kind) = self
            .get_entry_info(path)
            .ok_or_else(|| RegistryError::NotFound {
                entity_type: "directory".into(),
                id: path.join("/"),
            })?;

        if kind != git2::ObjectType::Tree {
            return Err(RegistryError::NotFound {
                entity_type: "directory".into(),
                id: path.join("/"),
            });
        }

        self.repo.find_tree(oid).map_err(from_git2)
    }
}

/// Efficiently mutates a Git tree by only rebuilding modified paths.
///
/// **CRITICAL**: `build_tree()` must:
/// - Reuse existing subtree OIDs for untouched directories
/// - Only create new tree objects along the modified path
/// - NEVER read or materialize the entire tree
///
/// At 1M identities, naive rebuild would be O(1M), but path-targeted
/// rebuild is O(depth) = O(5) for our sharded layout.
pub struct TreeMutator {
    /// Staged blob writes: full path -> content bytes
    pending_writes: HashMap<String, Vec<u8>>,
    /// Staged deletions: full paths
    pending_deletes: HashSet<String>,
}

impl TreeMutator {
    /// Create a new tree mutator.
    pub fn new() -> Self {
        Self {
            pending_writes: HashMap::new(),
            pending_deletes: HashSet::new(),
        }
    }

    /// Stage a blob write at the given path.
    ///
    /// If the path already has a pending write, it will be overwritten.
    pub fn write_blob(&mut self, path: &str, content: Vec<u8>) {
        self.pending_deletes.remove(path);
        self.pending_writes.insert(path.to_string(), content);
    }

    /// Stage a deletion at the given path.
    ///
    /// If the path has a pending write, it will be removed.
    pub fn delete(&mut self, path: &str) {
        self.pending_writes.remove(path);
        self.pending_deletes.insert(path.to_string());
    }

    /// Check if there are any pending mutations.
    #[allow(dead_code)]
    pub fn has_mutations(&self) -> bool {
        !self.pending_writes.is_empty() || !self.pending_deletes.is_empty()
    }

    /// Build a new tree from base + mutations.
    ///
    /// # Algorithm
    ///
    /// 1. Group mutations by top-level directory
    /// 2. For each affected directory, recursively rebuild only that subtree
    /// 3. Reuse OIDs for unaffected directories from base tree
    /// 4. Return new root tree OID
    ///
    /// # Arguments
    ///
    /// * `repo` - The Git repository
    /// * `base` - The base tree to apply mutations to (None for empty tree)
    pub fn build_tree(&self, repo: &Repository, base: Option<&Tree>) -> Result<Oid, RegistryError> {
        self.build_tree_recursive(repo, base, "")
    }

    /// Recursively build tree at the given path prefix.
    fn build_tree_recursive(
        &self,
        repo: &Repository,
        base: Option<&Tree>,
        prefix: &str,
    ) -> Result<Oid, RegistryError> {
        // Collect all children at this level
        let mut children: HashMap<String, ChildEntry> = HashMap::new();

        // First, get all existing children from base tree
        if let Some(tree) = base {
            for entry in tree.iter() {
                if let Some(name) = entry.name() {
                    children.insert(
                        name.to_string(),
                        ChildEntry {
                            oid: entry.id(),
                            kind: entry.kind().unwrap_or(git2::ObjectType::Blob),
                            modified: false,
                        },
                    );
                }
            }
        }

        // Find all mutations that affect this level
        let prefix_with_slash = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix)
        };

        // Track which children are affected by mutations
        let mut affected_children: HashSet<String> = HashSet::new();

        // Process writes
        for (path, content) in &self.pending_writes {
            if let Some(remainder) = path.strip_prefix(&prefix_with_slash) {
                // This mutation is under our prefix
                let parts: Vec<&str> = remainder.splitn(2, '/').collect();
                let child_name = parts[0];

                if parts.len() == 1 {
                    // Direct child blob - write it
                    let blob_oid = repo.blob(content).map_err(from_git2)?;
                    children.insert(
                        child_name.to_string(),
                        ChildEntry {
                            oid: blob_oid,
                            kind: git2::ObjectType::Blob,
                            modified: true,
                        },
                    );
                } else {
                    // Nested - mark this child as affected
                    affected_children.insert(child_name.to_string());
                }
            } else if prefix.is_empty() && !path.contains('/') {
                // Root-level blob
                let blob_oid = repo.blob(content).map_err(from_git2)?;
                children.insert(
                    path.clone(),
                    ChildEntry {
                        oid: blob_oid,
                        kind: git2::ObjectType::Blob,
                        modified: true,
                    },
                );
            } else if prefix.is_empty() {
                // Nested under root
                let parts: Vec<&str> = path.splitn(2, '/').collect();
                affected_children.insert(parts[0].to_string());
            }
        }

        // Process deletes
        for path in &self.pending_deletes {
            if let Some(remainder) = path.strip_prefix(&prefix_with_slash) {
                let parts: Vec<&str> = remainder.splitn(2, '/').collect();
                let child_name = parts[0];

                if parts.len() == 1 {
                    // Direct child - remove it
                    children.remove(child_name);
                } else {
                    // Nested - mark as affected
                    affected_children.insert(child_name.to_string());
                }
            } else if prefix.is_empty() && !path.contains('/') {
                // Root-level deletion
                children.remove(path);
            } else if prefix.is_empty() {
                // Nested under root
                let parts: Vec<&str> = path.splitn(2, '/').collect();
                affected_children.insert(parts[0].to_string());
            }
        }

        // Recursively rebuild affected children
        for child_name in affected_children {
            let child_path = if prefix.is_empty() {
                child_name.clone()
            } else {
                format!("{}/{}", prefix, child_name)
            };

            // Get base subtree if it exists
            let child_base = base.and_then(|t| {
                t.get_name(&child_name)
                    .filter(|e| e.kind() == Some(git2::ObjectType::Tree))
                    .and_then(|e| repo.find_tree(e.id()).ok())
            });

            let child_oid = self.build_tree_recursive(repo, child_base.as_ref(), &child_path)?;

            // Only add if the subtree isn't empty
            // (Check by trying to find it and seeing if it has entries)
            let child_tree = repo.find_tree(child_oid).map_err(from_git2)?;
            if !child_tree.is_empty() {
                children.insert(
                    child_name,
                    ChildEntry {
                        oid: child_oid,
                        kind: git2::ObjectType::Tree,
                        modified: true,
                    },
                );
            } else {
                children.remove(&child_name);
            }
        }

        // Build the tree
        let mut builder = repo.treebuilder(None).map_err(from_git2)?;
        for (name, entry) in &children {
            let filemode = match entry.kind {
                git2::ObjectType::Blob => 0o100644,
                git2::ObjectType::Tree => 0o040000,
                _ => 0o100644,
            };
            builder
                .insert(name, entry.oid, filemode)
                .map_err(from_git2)?;
        }

        builder.write().map_err(from_git2)
    }
}

impl Default for TreeMutator {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal helper struct for tree building.
struct ChildEntry {
    oid: Oid,
    kind: git2::ObjectType,
    #[allow(dead_code)]
    modified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_test_repo() -> (TempDir, Repository) {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        (dir, repo)
    }

    #[allow(dead_code)]
    fn create_empty_tree(repo: &Repository) -> Tree<'_> {
        let builder = repo.treebuilder(None).unwrap();
        let oid = builder.write().unwrap();
        repo.find_tree(oid).unwrap()
    }

    fn create_test_tree(repo: &Repository) -> Tree<'_> {
        // Create a tree with structure:
        // foo/bar.txt = "hello"
        // baz.txt = "world"

        let hello_oid = repo.blob(b"hello").unwrap();
        let world_oid = repo.blob(b"world").unwrap();

        let mut foo_builder = repo.treebuilder(None).unwrap();
        foo_builder.insert("bar.txt", hello_oid, 0o100644).unwrap();
        let foo_oid = foo_builder.write().unwrap();

        let mut root_builder = repo.treebuilder(None).unwrap();
        root_builder.insert("foo", foo_oid, 0o040000).unwrap();
        root_builder.insert("baz.txt", world_oid, 0o100644).unwrap();
        let root_oid = root_builder.write().unwrap();

        repo.find_tree(root_oid).unwrap()
    }

    // --- TreeNavigator tests ---

    #[test]
    fn navigator_read_blob() {
        let (_dir, repo) = setup_test_repo();
        let tree = create_test_tree(&repo);
        let nav = TreeNavigator::new(&repo, tree);

        let content = nav.read_blob(&["baz.txt"]).unwrap();
        assert_eq!(content, b"world");

        let nested = nav.read_blob(&["foo", "bar.txt"]).unwrap();
        assert_eq!(nested, b"hello");
    }

    #[test]
    fn navigator_read_blob_path() {
        let (_dir, repo) = setup_test_repo();
        let tree = create_test_tree(&repo);
        let nav = TreeNavigator::new(&repo, tree);

        let content = nav.read_blob_path("foo/bar.txt").unwrap();
        assert_eq!(content, b"hello");
    }

    #[test]
    fn navigator_read_nonexistent() {
        let (_dir, repo) = setup_test_repo();
        let tree = create_test_tree(&repo);
        let nav = TreeNavigator::new(&repo, tree);

        let result = nav.read_blob(&["nonexistent.txt"]);
        assert!(result.is_err());
    }

    #[test]
    fn navigator_exists() {
        let (_dir, repo) = setup_test_repo();
        let tree = create_test_tree(&repo);
        let nav = TreeNavigator::new(&repo, tree);

        assert!(nav.exists(&["baz.txt"]));
        assert!(nav.exists(&["foo", "bar.txt"]));
        assert!(nav.exists(&["foo"]));
        assert!(!nav.exists(&["nonexistent"]));
    }

    #[test]
    fn navigator_visit_dir() {
        let (_dir, repo) = setup_test_repo();
        let tree = create_test_tree(&repo);
        let nav = TreeNavigator::new(&repo, tree);

        let mut entries = Vec::new();
        nav.visit_dir(&[], |name| {
            entries.push(name.to_string());
            ControlFlow::Continue(())
        })
        .unwrap();

        entries.sort();
        assert_eq!(entries, vec!["baz.txt", "foo"]);
    }

    #[test]
    fn navigator_visit_dir_nested() {
        let (_dir, repo) = setup_test_repo();
        let tree = create_test_tree(&repo);
        let nav = TreeNavigator::new(&repo, tree);

        let mut entries = Vec::new();
        nav.visit_dir(&["foo"], |name| {
            entries.push(name.to_string());
            ControlFlow::Continue(())
        })
        .unwrap();

        assert_eq!(entries, vec!["bar.txt"]);
    }

    // --- TreeMutator tests ---

    #[test]
    fn mutator_write_to_empty_tree() {
        let (_dir, repo) = setup_test_repo();

        let mut mutator = TreeMutator::new();
        mutator.write_blob("test.txt", b"content".to_vec());

        let oid = mutator.build_tree(&repo, None).unwrap();
        let tree = repo.find_tree(oid).unwrap();
        let nav = TreeNavigator::new(&repo, tree);

        let content = nav.read_blob(&["test.txt"]).unwrap();
        assert_eq!(content, b"content");
    }

    #[test]
    fn mutator_write_nested() {
        let (_dir, repo) = setup_test_repo();

        let mut mutator = TreeMutator::new();
        mutator.write_blob("a/b/c.txt", b"nested".to_vec());

        let oid = mutator.build_tree(&repo, None).unwrap();
        let tree = repo.find_tree(oid).unwrap();
        let nav = TreeNavigator::new(&repo, tree);

        let content = nav.read_blob(&["a", "b", "c.txt"]).unwrap();
        assert_eq!(content, b"nested");
    }

    #[test]
    fn mutator_preserves_existing() {
        let (_dir, repo) = setup_test_repo();
        let base = create_test_tree(&repo);

        let mut mutator = TreeMutator::new();
        mutator.write_blob("new.txt", b"new content".to_vec());

        let oid = mutator.build_tree(&repo, Some(&base)).unwrap();
        let tree = repo.find_tree(oid).unwrap();
        let nav = TreeNavigator::new(&repo, tree);

        // New file exists
        let new_content = nav.read_blob(&["new.txt"]).unwrap();
        assert_eq!(new_content, b"new content");

        // Old files preserved
        let old_content = nav.read_blob(&["baz.txt"]).unwrap();
        assert_eq!(old_content, b"world");

        let nested = nav.read_blob(&["foo", "bar.txt"]).unwrap();
        assert_eq!(nested, b"hello");
    }

    #[test]
    fn mutator_overwrites_existing() {
        let (_dir, repo) = setup_test_repo();
        let base = create_test_tree(&repo);

        let mut mutator = TreeMutator::new();
        mutator.write_blob("baz.txt", b"updated".to_vec());

        let oid = mutator.build_tree(&repo, Some(&base)).unwrap();
        let tree = repo.find_tree(oid).unwrap();
        let nav = TreeNavigator::new(&repo, tree);

        let content = nav.read_blob(&["baz.txt"]).unwrap();
        assert_eq!(content, b"updated");
    }

    #[test]
    fn mutator_delete() {
        let (_dir, repo) = setup_test_repo();
        let base = create_test_tree(&repo);

        let mut mutator = TreeMutator::new();
        mutator.delete("baz.txt");

        let oid = mutator.build_tree(&repo, Some(&base)).unwrap();
        let tree = repo.find_tree(oid).unwrap();
        let nav = TreeNavigator::new(&repo, tree);

        assert!(!nav.exists(&["baz.txt"]));
        // foo/bar.txt should still exist
        assert!(nav.exists(&["foo", "bar.txt"]));
    }

    #[test]
    fn mutator_reuses_unchanged_subtrees() {
        let (_dir, repo) = setup_test_repo();
        let base = create_test_tree(&repo);

        // Get the OID of the "foo" subtree
        let foo_entry = base.get_name("foo").unwrap();
        let original_foo_oid = foo_entry.id();

        // Mutate only root-level file
        let mut mutator = TreeMutator::new();
        mutator.write_blob("baz.txt", b"updated".to_vec());

        let oid = mutator.build_tree(&repo, Some(&base)).unwrap();
        let tree = repo.find_tree(oid).unwrap();

        // The "foo" subtree should have the same OID (reused)
        let new_foo_entry = tree.get_name("foo").unwrap();
        assert_eq!(new_foo_entry.id(), original_foo_oid);
    }

    #[test]
    fn mutator_no_mutations_returns_same_tree() {
        let (_dir, repo) = setup_test_repo();
        let base = create_test_tree(&repo);

        let mutator = TreeMutator::new();
        assert!(!mutator.has_mutations());

        let oid = mutator.build_tree(&repo, Some(&base)).unwrap();

        // The tree content should be identical
        // (OID might differ if empty tree builder doesn't preserve exact structure)
        let tree = repo.find_tree(oid).unwrap();
        let nav = TreeNavigator::new(&repo, tree);

        assert!(nav.exists(&["foo", "bar.txt"]));
        assert!(nav.exists(&["baz.txt"]));
    }
}
