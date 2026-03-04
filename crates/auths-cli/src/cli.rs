use std::path::PathBuf;

use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Parser, Subcommand};

use crate::commands::agent::AgentCommand;
use crate::commands::artifact::ArtifactCommand;
use crate::commands::audit::AuditCommand;
use crate::commands::commit::CommitCmd;
use crate::commands::completions::CompletionsCommand;
use crate::commands::config::ConfigCommand;
use crate::commands::debug::DebugCmd;
use crate::commands::device::DeviceCommand;
use crate::commands::doctor::DoctorCommand;
use crate::commands::emergency::EmergencyCommand;
use crate::commands::git::GitCommand;
use crate::commands::id::IdCommand;
use crate::commands::init::InitCommand;
use crate::commands::key::KeyCommand;
use crate::commands::learn::LearnCommand;
use crate::commands::org::OrgCommand;
use crate::commands::policy::PolicyCommand;
use crate::commands::sign::SignCommand;
use crate::commands::status::StatusCommand;
use crate::commands::trust::TrustCommand;
use crate::commands::unified_verify::UnifiedVerifyCommand;
use crate::commands::witness::WitnessCommand;
use crate::config::OutputFormat;

fn cli_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Green.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Cyan.on_default())
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
        .valid(AnsiColor::Green.on_default() | Effects::BOLD)
        .invalid(AnsiColor::Yellow.on_default() | Effects::BOLD)
}

#[derive(Parser, Debug)]
#[command(
    name = "auths",
    about = "auths \u{2014} cryptographic identity for developers",
    long_about = "Commands:\n  init     Set up your cryptographic identity and Git signing\n  sign     Sign a Git commit or artifact\n  verify   Verify a signed commit or attestation\n  status   Show identity and signing status\n\nMore commands (run with --help for details):\n  auths device, auths id, auths key, auths policy, auths emergency, ...",
    version,
    styles = cli_styles()
)]
pub struct AuthsCli {
    #[command(subcommand)]
    pub command: RootCommand,

    #[clap(
        long,
        value_enum,
        default_value = "text",
        global = true,
        help_heading = "Display",
        help = "Output format (text or json)"
    )]
    pub output: OutputFormat,

    #[clap(
        long,
        global = true,
        help_heading = "Display",
        help = "Emit machine-readable JSON"
    )]
    pub json: bool,

    #[clap(
        short,
        long,
        global = true,
        help_heading = "Display",
        help = "Suppress non-essential output"
    )]
    pub quiet: bool,

    #[clap(
        long,
        value_parser,
        global = true,
        help_heading = "Advanced Setup",
        hide_short_help = true,
        help = "Override the local storage directory (default: ~/.auths)"
    )]
    pub repo: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
#[command(rename_all = "lowercase")]
pub enum RootCommand {
    Init(InitCommand),
    Sign(SignCommand),
    Verify(UnifiedVerifyCommand),
    Status(StatusCommand),
    Tutorial(LearnCommand),
    Doctor(DoctorCommand),
    Completions(CompletionsCommand),
    Emergency(EmergencyCommand),

    Id(IdCommand),
    Device(DeviceCommand),
    Key(KeyCommand),
    Artifact(ArtifactCommand),
    Policy(PolicyCommand),
    Git(GitCommand),
    Trust(TrustCommand),
    Org(OrgCommand),
    Audit(AuditCommand),
    Agent(AgentCommand),
    Witness(WitnessCommand),
    Config(ConfigCommand),

    #[command(hide = true)]
    Commit(CommitCmd),
    #[command(hide = true)]
    Debug(DebugCmd),
}
