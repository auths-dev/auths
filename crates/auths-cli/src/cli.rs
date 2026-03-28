use std::path::PathBuf;

use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Parser, Subcommand};

use crate::commands::account::AccountCommand;
use crate::commands::agent::AgentCommand;
use crate::commands::approval::ApprovalCommand;
use crate::commands::artifact::ArtifactCommand;
use crate::commands::audit::AuditCommand;
use crate::commands::auth::AuthCommand;
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
use crate::commands::scim::ScimCommand;
use crate::commands::sign::SignCommand;
use crate::commands::sign_commit::SignCommitCommand;
use crate::commands::signers::SignersCommand;
use crate::commands::status::StatusCommand;
use crate::commands::trust::TrustCommand;
use crate::commands::unified_verify::UnifiedVerifyCommand;
use crate::commands::whoami::WhoamiCommand;
use crate::commands::witness::WitnessCommand;
use crate::config::OutputFormat;

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
    after_help = "Run 'auths <command> --help' for details on any command.\nRun 'auths --help-all' for advanced commands (id, device, key, policy, ...)."
)]
pub struct AuthsCli {
    #[command(subcommand)]
    pub command: Option<RootCommand>,

    #[clap(long, help = "Show all commands including advanced ones")]
    pub help_all: bool,

    #[clap(
        long,
        value_enum,
        default_value = "text",
        global = true,
        hide = true,
        help = "Output format (text or json)"
    )]
    pub format: OutputFormat,

    #[clap(long, global = true, help = "Emit machine-readable JSON")]
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
    Init(InitCommand),
    Sign(SignCommand),
    SignCommit(SignCommitCommand),
    Verify(UnifiedVerifyCommand),
    Status(StatusCommand),
    Whoami(WhoamiCommand),
    Tutorial(LearnCommand),
    Doctor(DoctorCommand),
    Signers(SignersCommand),
    Pair(PairCommand),
    Error(ErrorLookupCommand),
    Completions(CompletionsCommand),
    #[command(hide = true)]
    Emergency(EmergencyCommand),

    Id(IdCommand),
    Device(DeviceCommand),
    Key(KeyCommand),
    Approval(ApprovalCommand),
    Artifact(ArtifactCommand),
    Policy(PolicyCommand),
    Git(GitCommand),
    Trust(TrustCommand),
    Namespace(NamespaceCommand),
    Org(OrgCommand),
    Audit(AuditCommand),
    Config(ConfigCommand),

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
    Auth(AuthCommand),
}
