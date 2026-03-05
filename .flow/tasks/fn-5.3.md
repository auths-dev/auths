# fn-5.3 Fix Axum route parameter syntax in delegates.rs and identity.rs

## Description
## Fix Axum route parameter syntax

**Repos**:
- `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1/delegates.rs`
- `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1/identity.rs`

### Problem
`delegates.rs` and `identity.rs` use Axum 0.7 colon syntax (`:did`) for route parameters, but the project uses Axum 0.8.4 which requires curly brace syntax (`{did}`). Routes using `:did` will create literal path segments and never match.

`node.rs` already uses the correct `{nid}` syntax (line 31), confirming the project targets Axum 0.8.

### What to do
1. In `delegates.rs`, change all `:did` to `{did}` in route definitions
2. In `identity.rs`, change all `:did` to `{did}` in route definitions
3. Verify `Path(did)` extractors still work with `{did}` syntax (they do in Axum 0.8)

### Key files
- `delegates.rs:27-28` — route definitions with `:did`
- `identity.rs:13-14` — route definitions with `:did`
- `node.rs:31` — reference for correct `{nid}` syntax
## Acceptance
- [ ] All route parameters in `delegates.rs` use `{did}` syntax
- [ ] All route parameters in `identity.rs` use `{did}` syntax
- [ ] No colon-style `:param` routes remain in v1 handlers
## Done summary
- Changed `:did` to `{did}` in delegates.rs routes (3 routes)
- Changed `:did` to `{did}` in identity.rs routes (2 routes)

Why:
- Project uses Axum 0.8.4 which requires `{param}` syntax; `:param` creates literal path segments that never match

Verification:
- Grep confirms no colon-style routes remain in v1 handlers
## Evidence
- Commits: 7c8522a09eaca99aeea5543dc9bb886fb10deadf
- Tests: grep for colon-style routes
- PRs:
