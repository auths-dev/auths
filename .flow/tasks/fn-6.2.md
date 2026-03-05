# fn-6.2 Swap Did import in radicle-httpd delegates.rs

## Description

Replace `use radicle::identity::Did` with `use auths_radicle::Did` in `radicle-httpd/src/api/v1/delegates.rs`. Change `delegates_repos_handler` to use `HashSet<String>` for string-based comparison with published radicle's `repo.doc.delegates()`.

### What changed
1. Import swap: `radicle::identity::Did` → `auths_radicle::Did`
2. `delegate_handler`: `Did::Keri(_)` / `Did::Key(_)` match arms now compile
3. `delegates_repos_handler`: `match_dids: HashSet<Did>` → `match_strings: HashSet<String>`, filter uses `.to_string()` comparison

### Key files
- `radicle-httpd/src/api/v1/delegates.rs`

## Acceptance
- [x] `use auths_radicle::Did` replaces `use radicle::identity::Did`
- [x] `Did::Keri(_)` / `Did::Key(_)` pattern matching compiles
- [x] `delegates_repos_handler` uses string comparison for `repo.doc.delegates()`
