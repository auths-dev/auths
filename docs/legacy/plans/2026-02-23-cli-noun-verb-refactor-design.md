# CLI Noun-Verb Refactor Design

## Problem

The CLI has 28 top-level commands mixing nouns and verbs (`pair`, `migrate`, `verify-commit`). Users cannot predict the grammar. The routing in `main.rs` threads 5-6 arguments through every handler, creating merge conflicts when engineers add commands.

## Design Principle

Enforce **Tool -> Noun -> Verb** grammar. Top-level commands are reserved for ergonomic workflows and break-glass operations. Everything else follows `auths <noun> <verb>`.

## Command Hierarchy

### Top-Level (Ergonomic Workflows)

| Command | Purpose |
|---|---|
| `auths init` | Workspace wizard. `--config <file>` for headless provisioning (absorbs `provision`) |
| `auths status` | Dashboard aggregating identity + device state |
| `auths sign <target>` | Smart router to `artifact sign` or `commit sign`. Zero business logic. |
| `auths verify <target>` | Smart router to `artifact verify`, `commit verify`, or `device verify`. Zero business logic. |
| `auths tutorial` | Interactive walkthrough (renamed from `learn`) |
| `auths doctor` | Health checks |
| `auths completions` | Shell completion generation |
| `auths emergency <action>` | Break-glass: `freeze`, `unfreeze`, `rotate-now`, `revoke-device`, `report` |

### Noun-Verb (Core Domain)

| Noun | Verbs |
|---|---|
| `auths id` | `create` (renamed from `init`), `show`, `rotate`, `migrate` |
| `auths device` | `list`, `pair`, `revoke`, `extend`, `verify` |
| `auths key` | `list`, `import`, `export`, `delete` |
| `auths artifact` | `sign`, `verify` |
| `auths policy` | `lint`, `compile`, `explain`, `test`, `diff` |
| `auths git` | `allowed-signers`, `hooks` |
| `auths trust` | `add`, `remove`, `list`, `show` |
| `auths org` | `list`, `switch` |
| `auths audit` | `report` |
| `auths agent` | `start`, `stop`, `status`, `env`, `lock`, `unlock` |
| `auths witness` | `serve`, `add`, `remove`, `list` |

### Hidden (Machine / Internal)

| Command | Purpose |
|---|---|
| `auths commit sign` | Called by `.gitconfig` `gpg.program` |
| `auths commit verify` | Called by `.gitconfig` `gpg.ssh.program` |
| `auths debug cache` | Identity history cache management |
| `auths debug index` | SQLite device lookup management |
| `auths debug util` | Developer plumbing (derive identity ID) |

## File Architecture

```
auths-cli/src/
├── main.rs                    # Bootstrapper: parse, resolve config, dispatch, exit code
├── cli.rs                     # AuthsCli struct + RootCommand enum (declarative only)
├── config.rs                  # CliConfig (globals only, no domain args)
├── lib.rs                     # Public re-exports
├── core/
│   ├── mod.rs
│   ├── provider.rs            # PassphraseProvider implementations
│   ├── types.rs               # Shared type enums (ExportFormat, etc.)
│   └── pubkey_cache.rs        # Public key caching
├── ux/
│   ├── mod.rs
│   ├── format.rs              # JSON vs TTY output (from output.rs)
│   └── dialogs.rs             # Spinners, prompts, progress bars
├── errors/
│   ├── mod.rs
│   ├── cli_error.rs           # CliError types (from error.rs)
│   └── renderer.rs            # Error rendering (from error_renderer.rs)
└── commands/
    ├── mod.rs                 # ExecutableCommand trait + module re-exports
    ├── init.rs                # Top-level wizard (--config for headless)
    ├── status.rs              # Dashboard aggregator
    ├── sign.rs                # Smart router (zero logic)
    ├── verify.rs              # Smart router (zero logic)
    ├── tutorial.rs            # Interactive walkthrough (renamed from learn)
    ├── doctor.rs              # Health checks
    ├── completions.rs         # Shell completion generation
    ├── agent/
    │   └── mod.rs             # AgentCmd: Start, Stop, Status, Env, Lock, Unlock
    ├── artifact/
    │   ├── mod.rs             # ArtifactCmd: Sign, Verify
    │   ├── sign.rs
    │   └── verify.rs
    ├── audit/
    │   └── mod.rs             # AuditCmd: Report
    ├── commit/                # Hidden — .gitconfig bindings
    │   ├── mod.rs             # CommitCmd: Sign, Verify
    │   ├── sign.rs
    │   └── verify.rs
    ├── debug/                 # Hidden — plumbing
    │   ├── mod.rs             # DebugCmd: Cache, Index, Util
    │   ├── cache.rs
    │   ├── index.rs
    │   └── util.rs
    ├── device/
    │   ├── mod.rs             # DeviceCmd: List, Pair, Revoke, Extend, Verify
    │   ├── pair/
    │   │   ├── mod.rs
    │   │   ├── online.rs
    │   │   ├── offline.rs
    │   │   ├── lan.rs         # (feature: lan-pairing)
    │   │   └── join.rs
    │   └── verify.rs          # Attestation verification
    ├── emergency/
    │   └── mod.rs             # EmergencyCmd: Freeze, Unfreeze, RotateNow, RevokeDevice, Report
    ├── git/
    │   └── mod.rs             # GitCmd: AllowedSigners, Hooks
    ├── id/
    │   └── mod.rs             # IdCmd: Create, Show, Rotate, Migrate
    ├── key/
    │   └── mod.rs             # KeyCmd: List, Import, Export, Delete
    ├── org/
    │   └── mod.rs             # OrgCmd: List, Switch
    ├── policy/
    │   └── mod.rs             # PolicyCmd: Lint, Compile, Explain, Test, Diff
    ├── trust/
    │   └── mod.rs             # TrustCmd: Add, Remove, List, Show
    └── witness/
        └── mod.rs             # WitnessCmd: Serve, Add, Remove, List
```

## Core Abstractions

### CliConfig (Slim Global Context)

Only cross-cutting concerns. Domain-specific args stay in command structs.

```rust
// config.rs
pub struct CliConfig {
    pub repo_path: PathBuf,
    pub output_format: OutputFormat,
    pub is_interactive: bool,  // Derived from stdout TTY + --quiet
    pub passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
}
```

### ExecutableCommand Trait

Native async (Rust 1.93, no `#[async_trait]` needed).

```rust
// commands/mod.rs
use anyhow::Result;
use crate::config::CliConfig;

pub trait ExecutableCommand {
    async fn execute(&self, ctx: &CliConfig) -> Result<()>;
}
```

### Declarative Router (cli.rs)

```rust
#[derive(Parser)]
#[command(name = "auths", version)]
pub struct AuthsCli {
    #[command(subcommand)]
    pub command: RootCommand,

    #[arg(long, global = true)]
    pub json: bool,

    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[arg(long, global = true)]
    pub repo: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum RootCommand {
    // Top-level workflows
    Init(InitCmd),
    Status(StatusCmd),
    Sign(SignCmd),
    Verify(VerifyCmd),
    Tutorial(TutorialCmd),
    Doctor(DoctorCmd),
    Completions(CompletionsCmd),
    Emergency(EmergencyCmd),

    // Noun-verb domain
    Id(IdCmd),
    Device(DeviceCmd),
    Key(KeyCmd),
    Artifact(ArtifactCmd),
    Policy(PolicyCmd),
    Git(GitCmd),
    Trust(TrustCmd),
    Org(OrgCmd),
    Audit(AuditCmd),
    Agent(AgentCmd),
    Witness(WitnessCmd),

    // Hidden (machine/internal)
    #[command(hide = true)]
    Commit(CommitCmd),
    #[command(hide = true)]
    Debug(DebugCmd),
}
```

### Bootstrapper (main.rs)

```rust
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = AuthsCli::parse();
    let ctx = CliConfig::from_cli(&cli);

    let result = match cli.command {
        RootCommand::Init(cmd) => cmd.execute(&ctx).await,
        RootCommand::Status(cmd) => cmd.execute(&ctx).await,
        RootCommand::Sign(cmd) => cmd.execute(&ctx).await,
        // ... uniform pattern for every variant
    };

    if let Err(e) = result {
        errors::renderer::render_error(&e, ctx.output_format);
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
```

### Nested Dispatch (Example: device/mod.rs)

```rust
#[derive(Parser, Debug)]
pub struct DeviceCmd {
    #[command(subcommand)]
    pub command: DeviceSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum DeviceSubcommand {
    List(ListCmd),
    Pair(PairCmd),
    Revoke(RevokeCmd),
    Extend(ExtendCmd),
    Verify(DeviceVerifyCmd),
}

impl ExecutableCommand for DeviceCmd {
    async fn execute(&self, ctx: &CliConfig) -> Result<()> {
        match &self.command {
            DeviceSubcommand::List(cmd) => cmd.execute(ctx).await,
            DeviceSubcommand::Pair(cmd) => cmd.execute(ctx).await,
            DeviceSubcommand::Revoke(cmd) => cmd.execute(ctx).await,
            DeviceSubcommand::Extend(cmd) => cmd.execute(ctx).await,
            DeviceSubcommand::Verify(cmd) => cmd.execute(ctx).await,
        }
    }
}
```

## Migration Map

| Current location | New location | Notes |
|---|---|---|
| `main.rs` (monolith) | `main.rs` + `cli.rs` + `config.rs` | Split into bootstrapper, parser, config |
| `output.rs` | `ux/format.rs` | |
| `error.rs` | `errors/cli_error.rs` | |
| `error_renderer.rs` | `errors/renderer.rs` | |
| `provider.rs` | `core/provider.rs` | |
| `types.rs` | `core/types.rs` | |
| `pubkey_cache.rs` | `core/pubkey_cache.rs` | |
| `commands/learn.rs` | `commands/tutorial.rs` | Rename |
| `commands/provision.rs` | Deleted | Absorbed into `init.rs --config` |
| `commands/pair/` | `commands/device/pair/` | Nested under device |
| `commands/migrate.rs` | `commands/id/mod.rs` (Migrate variant) | Moved under id |
| `commands/sign.rs` | `commands/sign.rs` (router) + `commands/commit/sign.rs` + `commands/artifact/sign.rs` | Split |
| `commands/unified_verify.rs` | `commands/verify.rs` (router) | Smart router |
| `commands/verify_commit.rs` | `commands/commit/verify.rs` | |
| `commands/verify.rs` | `commands/device/verify.rs` | Attestation verification |
| `commands/verify_helpers.rs` | `commands/commit/verify.rs` or shared in `core/` | Evaluate during impl |
| `commands/cache.rs` | `commands/debug/cache.rs` | |
| `commands/index.rs` | `commands/debug/index.rs` | |
| `commands/utils.rs` | `commands/debug/util.rs` | |
| `commands/id.rs` | `commands/id/mod.rs` | `init` subcommand renamed to `create` |
| `commands/status.rs` | `commands/status.rs` | Stays top-level |

## UX Rules

1. **Context-aware defaults**: `auths git hooks` resolves `.git` from `$PWD` automatically.
2. **Structured output**: Every command supports `--json`. TTY gets colors + spinners; piped output or `--json` gets strictly structured JSON with no interactive prompts.
3. **Actionable errors**: Every error includes what failed, why, and the exact command to fix it.

## Implementation Order

1. Scaffolding: Create directory structure, `cli.rs`, `config.rs`, `ExecutableCommand` trait
2. Move `ux/` and `errors/` modules (no logic changes, just file moves + re-exports)
3. Move `core/` utilities (provider, types, pubkey_cache)
4. Migrate noun-verb commands one group at a time (id, device, key, etc.)
5. Wire up top-level routers (sign, verify, status)
6. Wire up hidden commands (commit, debug)
7. Delete dead files (provision, old verify variants, old pair location)
8. Update tests to match new module paths
9. Verify all 251 tests pass
