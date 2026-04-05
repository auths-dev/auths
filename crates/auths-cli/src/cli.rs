use std::path::PathBuf;

use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Parser, Subcommand};

use crate::commands::account::AccountCommand;
use crate::commands::agent::AgentCommand;
use crate::commands::approval::ApprovalCommand;
use crate::commands::artifact::ArtifactCommand;
use crate::commands::audit::AuditCommand;
use crate::commands::auth::AuthCommand;
use crate::commands::ci::CiCommand;
use crate::commands::commit::CommitCmd;
use crate::commands::completions::CompletionsCommand;
use crate::commands::config::ConfigCommand;
use crate::commands::debug::DebugCmd;
use crate::commands::device::DeviceCommand;
use crate::commands::device::pair::PairCommand;
use crate::commands::doctor::DoctorCommand;
use crate::commands::emergency::EmergencyCommand;
use crate::commands::error_lookup::ErrorLookupCommand;
use crate::commands::git::GitCommand;
use crate::commands::id::IdCommand;
use crate::commands::init::InitCommand;
use crate::commands::key::KeyCommand;
use crate::commands::learn::LearnCommand;
use crate::commands::log::LogCommand;
use crate::commands::namespace::NamespaceCommand;
use crate::commands::org::OrgCommand;
use crate::commands::policy::PolicyCommand;
use crate::commands::reset::ResetCommand;
use crate::commands::scim::ScimCommand;
use crate::commands::sign::SignCommand;
use crate::commands::sign_commit::SignCommitCommand;
use crate::commands::signers::SignersCommand;
use crate::commands::status::StatusCommand;
use crate::commands::trust::TrustCommand;
use crate::commands::unified_verify::UnifiedVerifyCommand;
use crate::commands::whoami::WhoamiCommand;
use crate::commands::witness::WitnessCommand;

fn cli_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Blue.on_default() | Effects::BOLD)
        .usage(AnsiColor::Blue.on_default() | Effects::BOLD)
        .literal(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Cyan.on_default())
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
        .valid(AnsiColor::Green.on_default() | Effects::BOLD)
        .invalid(AnsiColor::Yellow.on_default() | Effects::BOLD)
}

#[derive(Parser, Debug)]
#[command(
    name = "auths",
    about = "\x1b[1;32mauths \u{2014} cryptographic identity for developers and agents\x1b[0m",
    version,
    styles = cli_styles(),
    after_help = "Run 'auths <command> --help' for details on any command.\nRun 'auths --help-all' for all commands including advanced ones."
)]
pub struct AuthsCli {
    #[command(subcommand)]
    pub command: Option<RootCommand>,

    #[clap(long, help = "Show all commands including advanced ones")]
    pub help_all: bool,

    #[clap(short = 'j', long, global = true, help = "Emit machine-readable JSON")]
    pub json: bool,

    #[clap(short, long, global = true, help = "Suppress non-essential output")]
    pub quiet: bool,

    #[clap(
        long,
        value_parser,
        global = true,
        help = "Override the local storage directory (default: ~/.auths)"
    )]
    pub repo: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
#[command(rename_all = "lowercase")]
pub enum RootCommand {
    // ── Primary ──
    Init(InitCommand),
    Sign(SignCommand),
    Verify(UnifiedVerifyCommand),
    Artifact(ArtifactCommand),
    Status(StatusCommand),
    Whoami(WhoamiCommand),

    // ── Setup & Troubleshooting ──
    Pair(PairCommand),
    Trust(TrustCommand),
    Doctor(DoctorCommand),
    Tutorial(LearnCommand),

    // ── Utilities ──
    Config(ConfigCommand),
    Completions(CompletionsCommand),

    // ── CI/CD ──
    Ci(CiCommand),

    // ── Advanced (visible via --help-all) ──
    #[command(hide = true)]
    Reset(ResetCommand),
    #[command(hide = true)]
    SignCommit(SignCommitCommand),
    #[command(hide = true)]
    Signers(SignersCommand),
    #[command(hide = true)]
    Error(ErrorLookupCommand),
    #[command(hide = true)]
    Id(IdCommand),
    #[command(hide = true)]
    Device(DeviceCommand),
    #[command(hide = true)]
    Key(KeyCommand),
    #[command(hide = true)]
    Approval(ApprovalCommand),
    #[command(hide = true)]
    Policy(PolicyCommand),
    #[command(hide = true)]
    Git(GitCommand),
    #[command(hide = true)]
    Namespace(NamespaceCommand),
    #[command(hide = true)]
    Org(OrgCommand),
    #[command(hide = true)]
    Audit(AuditCommand),
    #[command(hide = true)]
    Auth(AuthCommand),

    // ── Internal (visible via --help-all) ──
    #[command(hide = true)]
    Emergency(EmergencyCommand),
    #[command(hide = true)]
    Agent(AgentCommand),
    #[command(hide = true)]
    Witness(WitnessCommand),
    #[command(hide = true)]
    Scim(ScimCommand),
    #[command(hide = true)]
    Commit(CommitCmd),
    #[command(hide = true)]
    Debug(DebugCmd),
    #[command(hide = true)]
    Log(LogCommand),
    #[command(hide = true)]
    Account(AccountCommand),
}
