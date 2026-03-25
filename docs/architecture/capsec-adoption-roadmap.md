# capsec Adoption Roadmap

Generated from `cargo capsec audit` on 2026-03-21.

## Principle

The CLI is the presentation layer — it is *supposed* to do I/O.
The same way `Utc::now()` is banned in domain crates but called freely
at the CLI boundary, `std::fs::read` and `std::process::Command` are
expected in CLI command handlers. The architecture goal is not to
eliminate I/O from the CLI, but to ensure domain crates never do it directly.

## Summary

| Category | Count | Action |
|----------|-------|--------|
| Test code | 20 | None — tests do I/O by design |
| CLI env reads | 23 | None — presentation layer reads env vars by design |
| Build tooling (xtask, test-utils) | 51 | None — not shipped, not a security surface |
| Standalone binaries (sign/verify) | 13 | None — separate entry points with their own capsec::root() |
| Server entry points (mcp, pairing) | 13 | None — main() reads env and binds ports by design |
| CLI command handlers | 140 | None — the CLI is the I/O boundary, this is expected |
| Ungated CLI adapters | 13 | **Do** — add SendCap tokens, same pattern as fn-82.4 |
| Domain crate I/O (core, id) | 49 | **Do** — extract behind port traits or add INVARIANT comments |
| Infrastructure crate I/O | 23 | **Do** — add capsec dependency and gate with tokens |

**260 of 347 findings need no action** (CLI doing its job).
**85 findings are real work**, in 3 buckets.

---

## No Action Needed

These findings are the system working as designed.

### Test code (20 findings)

- `crates/auths-cli/src/bin/verify.rs` (1 FS): `test_find_signer_nonexistent_file()`
- `crates/auths-cli/src/commands/policy.rs` (2 FS): `handle_test()`
- `crates/auths-cli/src/commands/sign.rs` (1 FS): `test_parse_sign_target_file()`
- `crates/auths-cli/src/commands/unified_verify.rs` (1 FS): `test_parse_verify_target_file()`
- `crates/auths-core/src/agent/handle.rs` (1 FS): `test_agent_handle_shutdown()`
- `crates/auths-core/src/trust/pinned.rs` (1 FS): `test_concurrent_access_no_corruption()`
- `crates/auths-id/src/storage/registry/hooks.rs` (13 FS): `test_install_appends_to_existing()`, `test_install_idempotent()`, `test_install_linearity_hook_appends_to_existing()`, `test_install_linearity_hook_idempotent()`, `test_install_linearity_hook_new()`, `test_install_new_hooks()`, `test_uninstall_linearity_hook_preserves_other_content()`

### CLI env reads (23 findings)

- `crates/auths-cli/src/commands/device/pair/common.rs` (2 ENV): `hostname()`
- `crates/auths-cli/src/commands/device/verify_attestation.rs` (1 ENV): `resolve_issuer_key()`
- `crates/auths-cli/src/commands/git.rs` (1 ENV): `find_git_dir()`
- `crates/auths-cli/src/commands/id/claim.rs` (1 ENV): `github_client_id()`
- `crates/auths-cli/src/commands/id/migrate.rs` (1 ENV): `handle_migrate_status()`
- `crates/auths-cli/src/commands/init/gather.rs` (3 ENV): `gather_ci_config()`
- `crates/auths-cli/src/commands/init/helpers.rs` (8 ENV): `detect_ci_environment()`, `detect_shell()`
- `crates/auths-cli/src/commands/init/prompts.rs` (2 ENV): `prompt_for_git_scope()`, `run_github_verification()`
- `crates/auths-cli/src/commands/key.rs` (2 ENV): `key_copy_backend()`, `key_import()`
- `crates/auths-cli/src/factories/mod.rs` (1 ENV): `init_audit_sinks()`
- `crates/auths-cli/src/ux/format.rs` (1 ENV): `should_use_colors()`

### Build tooling (xtask, test-utils) (51 findings)

- `crates/auths-test-utils/src/git.rs` (3 FS): `copy_directory()`
- `crates/xtask/src/check_clippy_sync.rs` (3 FS): `extract_disallowed_paths()`, `find_crate_clippy_files()`
- `crates/xtask/src/ci_setup.rs` (2 ENV, 9 FS): `add_dir_to_tar()`, `dirs_or_env()`, `run()`, `tar_excludes_sock_files()`
- `crates/xtask/src/gen_docs.rs` (2 FS, 4 PROC): `generate_table()`, `run()`
- `crates/xtask/src/gen_error_docs.rs` (10 FS): `check_or_write()`, `parse_file()`, `run()`, `update_mkdocs_nav()`
- `crates/xtask/src/gen_schema.rs` (3 FS): `run()`
- `crates/xtask/src/schemas.rs` (5 FS): `generate()`, `validate()`
- `crates/xtask/src/shell.rs` (6 PROC): `run_capture()`, `run_capture_env()`, `run_with_stdin()`
- `crates/xtask/src/test_integration.rs` (4 PROC): `run()`

### Standalone binaries (sign/verify) (13 findings)

- `crates/auths-cli/src/bin/sign.rs` (2 FS, 4 PROC): `run_delegate_to_ssh_keygen()`, `run_sign()`, `run_verify()`
- `crates/auths-cli/src/bin/verify.rs` (1 FS, 6 PROC): `check_ssh_keygen()`, `find_signer()`, `verify_file()`, `verify_with_ssh_keygen()`

### Server entry points (mcp, pairing) (13 findings)

- `crates/auths-mcp-server/src/main.rs` (8 ENV, 1 NET): `main()`
- `crates/auths-mcp-server/src/tools.rs` (2 FS): `execute_read_file()`, `execute_write_file()`
- `crates/auths-pairing-daemon/src/discovery.rs` (2 ENV): `advertise()`

### CLI command handlers (140 findings)

- `crates/auths-cli/src/commands/agent/mod.rs` (2 FS): `start_agent()`
- `crates/auths-cli/src/commands/agent/process.rs` (6 FS, 2 PROC): `cleanup_stale_files()`, `cleanup_stale_files_removes_existing()`, `read_pid_file()`, `read_pid_file_invalid_content_errors()`, `spawn_detached()`
- `crates/auths-cli/src/commands/agent/service.rs` (6 FS, 6 PROC): `install_launchd_service()`, `install_systemd_service()`, `uninstall_launchd_service()`, `uninstall_systemd_service()`
- `crates/auths-cli/src/commands/artifact/publish.rs` (1 FS): `handle_publish_async()`
- `crates/auths-cli/src/commands/artifact/sign.rs` (1 FS): `handle_sign()`
- `crates/auths-cli/src/commands/artifact/verify.rs` (3 FS): `handle_verify()`, `resolve_identity_key()`, `verify_witnesses()`
- `crates/auths-cli/src/commands/audit.rs` (1 FS): `handle_audit()`
- `crates/auths-cli/src/commands/device/authorization.rs` (2 FS): `read_payload_file()`, `validate_payload_schema()`
- `crates/auths-cli/src/commands/device/pair/lan_server.rs` (1 NET): `start()`
- `crates/auths-cli/src/commands/device/verify_attestation.rs` (3 FS): `handle_verify_attestation()`, `run_verify()`
- `crates/auths-cli/src/commands/doctor.rs` (1 FS): `check_allowed_signers_file()`
- `crates/auths-cli/src/commands/emergency.rs` (2 FS): `handle_report()`
- `crates/auths-cli/src/commands/git.rs` (6 FS): `find_git_dir()`, `handle_install_hooks()`
- `crates/auths-cli/src/commands/id/bind_idp.rs` (2 PROC): `handle_bind_idp()`
- `crates/auths-cli/src/commands/id/identity.rs` (2 FS): `handle_id()`
- `crates/auths-cli/src/commands/id/migrate.rs` (8 FS, 12 PROC): `analyze_commit_signatures()`, `get_ssh_key_bits()`, `is_gpg_available()`, `list_gpg_secret_keys()`, `list_ssh_keys()`, `parse_ssh_public_key()`, `perform_gpg_migration()`, `perform_ssh_migration()`, `update_allowed_signers()`
- `crates/auths-cli/src/commands/init/gather.rs` (1 FS): `ensure_registry_dir()`
- `crates/auths-cli/src/commands/init/helpers.rs` (3 FS, 6 PROC): `check_git_version()`, `install_shell_completions()`, `set_git_config()`, `write_allowed_signers()`
- `crates/auths-cli/src/commands/key.rs` (1 FS): `key_import()`
- `crates/auths-cli/src/commands/learn.rs` (7 FS, 12 PROC): `cleanup_sandbox()`, `load_progress()`, `reset_progress()`, `save_progress()`, `section_creating_identity()`, `section_signing_commit()`, `setup_sandbox()`
- `crates/auths-cli/src/commands/log.rs` (1 FS): `handle_verify()`
- `crates/auths-cli/src/commands/org.rs` (2 FS, 1 NET): `handle_join()`, `handle_org()`
- `crates/auths-cli/src/commands/policy.rs` (6 FS): `handle_compile()`, `handle_diff()`, `handle_explain()`, `handle_lint()`
- `crates/auths-cli/src/commands/scim.rs` (2 PROC): `handle_serve()`
- `crates/auths-cli/src/commands/sign.rs` (4 PROC): `execute_git_rebase()`, `sign_commit_range()`
- `crates/auths-cli/src/commands/signers.rs` (2 PROC): `resolve_signers_path()`
- `crates/auths-cli/src/commands/status.rs` (1 FS): `get_agent_status()`
- `crates/auths-cli/src/commands/verify_commit.rs` (3 FS, 14 PROC): `check_ssh_keygen()`, `get_commit_signature()`, `resolve_commit_sha()`, `resolve_commits()`, `resolve_signers_source()`, `verify_ssh_signature()`, `verify_witnesses()`
- `crates/auths-cli/src/core/fs.rs` (3 FS): `create_restricted_dir()`, `write_sensitive_file()`
- `crates/auths-cli/src/core/pubkey_cache.rs` (4 FS): `clear_all_cached_pubkeys()`, `clear_cached_pubkey()`, `get_cached_pubkey()`

---

## Priority 1: Ungated CLI Adapters (13 findings)

Same pattern as fn-82.4. Add `SendCap<P>` fields to adapter structs,
update constructors to accept tokens, replace `std` calls with `capsec` wrappers.

### `allowed_signers_store.rs` → needs FsRead, FsWrite
- [ ] `std::fs::read_to_string` in `read()` (line 14, FS)
- [ ] `std::fs::create_dir_all` in `write()` (line 27, FS)

### `doctor_fixes.rs` → needs FsWrite, Spawn
- [ ] `std::fs::create_dir_all` in `apply()` (line 41, FS)
- [ ] `std::process::Command::new` in `set_git_config_value()` (line 124, PROC **[critical]**)
- [ ] `status` in `set_git_config_value()` (line 126, PROC **[critical]**)

### `ssh_agent.rs` → needs Spawn
- [ ] `std::process::Command::new` in `register_key()` (line 18, PROC **[critical]**)
- [ ] `output` in `register_key()` (line 20, PROC **[critical]**)

### `system_diagnostic.rs` → needs Spawn
- [ ] `std::process::Command::new` in `check_git_version()` (line 13, PROC **[critical]**)
- [ ] `output` in `check_git_version()` (line 13, PROC **[critical]**)
- [ ] `std::process::Command::new` in `get_git_config()` (line 30, PROC **[critical]**)
- [ ] `output` in `get_git_config()` (line 32, PROC **[critical]**)
- [ ] `std::process::Command::new` in `check_ssh_keygen_available()` (line 47, PROC **[critical]**)
- [ ] `output` in `check_ssh_keygen_available()` (line 47, PROC **[critical]**)

---

## Priority 2: Domain Crate I/O (49 findings)

These are `std::fs` and `std::process` calls in auths-core and auths-id —
crates that should ideally be I/O-free. Some are platform-specific storage
with INVARIANT comments (acceptable as-is). Others should be extracted
behind port traits with adapters in the infrastructure layer.

### `crates/auths-core/src/agent/handle.rs` (FS:2)
**`shutdown()`**
- [ ] `std::fs::remove_file` (line 259, FS **[high]**)
- [ ] `std::fs::remove_file` (line 270, FS **[high]**)

### `crates/auths-core/src/api/runtime.rs` (FS:2)
**`start_agent_listener_with_handle()`**
- [ ] `std::fs::create_dir_all` (line 739, FS)
- [ ] `std::fs::remove_file` (line 746, FS **[high]**)

### `crates/auths-core/src/config.rs` (ENV:10) *(environment config loading — acceptable at startup boundary)*
**`from_env()`**
- [ ] `std::env::var` (line 59, ENV)
- [ ] `std::env::var` (line 62, ENV)
- [ ] `std::env::var` (line 65, ENV)
- [ ] `std::env::var` (line 66, ENV)
- [ ] `std::env::var` (line 67, ENV)
- [ ] `std::env::var` (line 116, ENV)
- [ ] `std::env::var` (line 117, ENV)
- [ ] `std::env::var` (line 118, ENV)
- [ ] `std::env::var` (line 162, ENV)
- [ ] `std::env::var` (line 167, ENV)

### `crates/auths-core/src/storage/encrypted_file.rs` (FS:1) *(platform-specific storage — keep with INVARIANT comments)*
**`read_data()`**
- [ ] `std::fs::File::open` (line 176, FS)

### `crates/auths-core/src/storage/windows_credential.rs` (FS:3) *(platform-specific storage — keep with INVARIANT comments)*
**`load_index()`**
- [ ] `std::fs::read_to_string` (line 113, FS)

**`new()`**
- [ ] `std::fs::create_dir_all` (line 91, FS)

**`save_index()`**
- [ ] `std::fs::write` (line 125, FS **[high]**)

### `crates/auths-core/src/testing/builder.rs` (PROC:2) *(test infrastructure — acceptable)*
**`build()`**
- [ ] `std::process::Command::new` (line 192, PROC **[critical]**)
- [ ] `output` (line 195, PROC **[critical]**)

### `crates/auths-core/src/trust/pinned.rs` (FS:5)
**`lock()`**
- [ ] `std::fs::create_dir_all` (line 224, FS)

**`read_all()`**
- [ ] `std::fs::read_to_string` (line 195, FS)

**`write_all()`**
- [ ] `std::fs::create_dir_all` (line 207, FS)
- [ ] `std::fs::File::create` (line 211, FS **[high]**)
- [ ] `std::fs::rename` (line 217, FS)

### `crates/auths-core/src/trust/roots_file.rs` (FS:2)
**`create_temp_roots_file()`**
- [ ] `std::fs::File::create` (line 112, FS **[high]**)

**`load()`**
- [ ] `std::fs::read_to_string` (line 79, FS)

### `crates/auths-core/src/witness/server.rs` (NET:1)
**`run_server()`**
- [ ] `tokio::net::TcpListener::bind` (line 269, NET **[high]**)

### `crates/auths-id/src/agent_identity.rs` (FS:2)
**`ensure_git_repo()`**
- [ ] `std::fs::create_dir_all` (line 217, FS)

**`write_agent_toml()`**
- [ ] `std::fs::write` (line 378, FS **[high]**)

### `crates/auths-id/src/freeze.rs` (FS:4)
**`load_active_freeze()`**
- [ ] `std::fs::read_to_string` (line 85, FS)
- [ ] `std::fs::remove_file` (line 91, FS **[high]**)

**`remove_freeze()`**
- [ ] `std::fs::remove_file` (line 110, FS **[high]**)

**`store_freeze()`**
- [ ] `std::fs::write` (line 101, FS **[high]**)

### `crates/auths-id/src/storage/registry/hooks.rs` (FS:15)
**`find_git_dir()`**
- [ ] `std::fs::read_to_string` (line 150, FS)

**`install_cache_hooks()`**
- [ ] `std::fs::create_dir_all` (line 88, FS)

**`install_hook()`**
- [ ] `std::fs::read_to_string` (line 107, FS)
- [ ] `std::fs::write` (line 129, FS **[high]**)
- [ ] `std::fs::metadata` (line 132, FS)

**`install_linearity_hook()`**
- [ ] `std::fs::create_dir_all` (line 299, FS)
- [ ] `std::fs::read_to_string` (line 305, FS)
- [ ] `std::fs::write` (line 327, FS **[high]**)
- [ ] `std::fs::metadata` (line 331, FS)

**`uninstall_cache_hooks()`**
- [ ] `std::fs::read_to_string` (line 186, FS)
- [ ] `std::fs::remove_file` (line 217, FS **[high]**)
- [ ] `std::fs::write` (line 219, FS **[high]**)

**`uninstall_linearity_hook()`**
- [ ] `std::fs::read_to_string` (line 359, FS)
- [ ] `std::fs::remove_file` (line 387, FS **[high]**)
- [ ] `std::fs::write` (line 389, FS **[high]**)

---

## Priority 3: Infrastructure Crate I/O (23 findings)

Legitimate I/O in infrastructure crates. When these crates adopt capsec
as a dependency, add `SendCap<P>` tokens to their adapter structs —
same pattern as auths-infra-git and auths-infra-http.

### auths-infra-http (NET:2)
**`crates/auths-infra-http/src/request.rs`**
- [ ] `reqwest::Client::new` in `build_get_creates_get_request()` (line 72, NET)
- [ ] `reqwest::Client::new` in `build_post_creates_post_with_body()` (line 81, NET)

### auths-sdk (FS:7)
**`crates/auths-sdk/src/workflows/transparency.rs`**
- [ ] `std::fs::read_to_string` in `try_cache_checkpoint()` (line 276, FS)
- [ ] `std::fs::create_dir_all` in `try_cache_checkpoint()` (line 331, FS)
- [ ] `std::fs::write` in `try_cache_checkpoint()` (line 333, FS **[high]**)
- [ ] `std::fs::read_to_string` in `update_checkpoint_cache()` (line 211, FS)
- [ ] `std::fs::create_dir_all` in `update_checkpoint_cache()` (line 236, FS)
- [ ] `std::fs::write` in `update_checkpoint_cache()` (line 238, FS **[high]**)
- [ ] `std::fs::read_to_string` in `update_checkpoint_cache_writes_new_file()` (line 472, FS)

### auths-storage (FS:8)
**`crates/auths-storage/src/git/adapter.rs`**
- [ ] `std::fs::File::create` in `acquire()` (line 106, FS **[high]**)
- [ ] `std::fs::create_dir_all` in `init_if_needed()` (line 234, FS)
- [ ] `std::fs::read` in `load_tenant_metadata()` (line 323, FS)

**`crates/auths-storage/src/git/vfs.rs`**
- [ ] `std::fs::remove_file` in `delete_file()` (line 107, FS **[high]**)
- [ ] `std::fs::rename` in `persist_temp_file()` (line 157, FS)
- [ ] `std::fs::copy` in `persist_temp_file()` (line 161, FS)
- [ ] `std::fs::remove_file` in `persist_temp_file()` (line 162, FS **[high]**)
- [ ] `std::fs::read` in `read_file()` (line 89, FS)

### auths-telemetry (FS:2)
**`crates/auths-telemetry/src/config.rs`**
- [ ] `std::fs::create_dir_all` in `build_file_sink()` (line 220, FS)
- [ ] `std::fs::read_to_string` in `load_audit_config()` (line 95, FS)

### auths-transparency (FS:4)
**`crates/auths-transparency/src/fs_store.rs`**
- [ ] `tokio::fs::read` in `read_checkpoint()` (line 73, FS)
- [ ] `tokio::fs::read` in `read_tile()` (line 48, FS)
- [ ] `tokio::fs::write` in `write_checkpoint()` (line 89, FS **[high]**)
- [ ] `tokio::fs::write` in `write_tile()` (line 66, FS **[high]**)
